#!/usr/bin/env python3
# Port Tunnel Manager: Web UI + CLI + persistence + real reverse SSH tunnels (non-blocking startup)
import argparse
import asyncio
import json
import logging
import os
import pathlib
import shlex
import sys
import time
from typing import Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
import uvicorn

# -------------------------
# Logging
# -------------------------
logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("ptm")

# -------------------------
# Tunables / timeouts
# -------------------------
SERVER_CHECK_TIMEOUT = 5.0            # seconds for server reachability checks
CONNECT_PREP_TIMEOUT = 45.0           # seconds for initial /connect preparation
SERVER_CONNECT_TIMEOUT = 40.0         # seconds for server connection timeout

# -------------------------
# Resource path (PyInstaller/Nuitka friendly)
# -------------------------
def resource_path(relative: str) -> str:
    if hasattr(sys, "_MEIPASS"):  # set by PyInstaller onefile
        base = pathlib.Path(sys._MEIPASS)
    else:
        base = pathlib.Path(__file__).resolve().parent
    return str((base / relative).resolve())

# -------------------------
# Persistence
# -------------------------
APP_NAME = "port_tunnel_manager"
CONFIG_DIR = pathlib.Path.home() / ".config" / APP_NAME
STATE_FILE = CONFIG_DIR / "state.json"

def ensure_cfg_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

def load_state() -> dict:
    ensure_cfg_dir()
    if not STATE_FILE.exists():
        return {"server": None, "tunnels": {}}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"server": None, "tunnels": {}}

def save_state(data: dict):
    ensure_cfg_dir()
    tmp = STATE_FILE.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, STATE_FILE)

# -------------------------
# Simple "current server" holder
# -------------------------
class CurrentServer:
    def __init__(self):
        self.host: Optional[str] = None
        self.user: Optional[str] = None
        self.port: Optional[int] = None
        self.key_path: Optional[str] = None

    def is_set(self) -> bool:
        return bool(self.host and self.user and self.port and self.key_path)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "user": self.user,
            "ssh_port": self.port,
            "ssh_key_path": self.key_path,
        }

    def from_dict(self, d: dict):
        self.host = d.get("host")
        self.user = d.get("user")
        self.port = d.get("ssh_port")
        self.key_path = d.get("ssh_key_path")

CURRENT = CurrentServer()

# -------------------------
# SSH setup helpers (Paramiko for first-time password step)
# -------------------------
import paramiko

def ensure_local_ssh_key(key_path: str = "~/.ssh/id_ed25519") -> Tuple[str, str]:
    key_path = os.path.expanduser(key_path)
    pub_path = key_path + ".pub"
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    if not os.path.exists(pub_path):
        log.info(f"Generating SSH key: {key_path}")
        import subprocess
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", ""], check=True)
    return key_path, pub_path

def _connect_password(host: str, user: str, port: int, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # accept-new
    client.connect(hostname=host, username=user, port=port, password=password,
                   look_for_keys=False, allow_agent=False, timeout=10)
    return client

def _connect_key(host: str, user: str, port: int, key_path: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key_path = os.path.expanduser(key_path)
    try:
        pkey = paramiko.Ed25519Key.from_private_key_file(key_path)
    except Exception:
        pkey = paramiko.RSAKey.from_private_key_file(key_path)
    client.connect(hostname=host, username=user, port=port, pkey=pkey,
                   look_for_keys=False, allow_agent=False, timeout=10)
    return client

def _ssh_exec(client: paramiko.SSHClient, cmd: str, sudo: bool = False, password: Optional[str] = None):
    # Request PTY so sudo -S works reliably
    if sudo:
        cmd = f"sudo -S bash -lc {shlex.quote(cmd)}"
    else:
        cmd = f"bash -lc {shlex.quote(cmd)}"
    stdin, stdout, stderr = client.exec_command(cmd, get_pty=True, timeout=15)
    if sudo and password:
        stdin.write(password + "\n")
        stdin.flush()
    rc = stdout.channel.recv_exit_status()
    out = stdout.read().decode(errors="ignore")
    err = stderr.read().decode(errors="ignore")
    return rc, out, err

def _install_pubkey_with_password(host: str, user: str, port: int, password: str, pubkey_text: str):
    c = _connect_password(host, user, port, password)
    try:
        cmds = [
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh",
            f"grep -qxF {shlex.quote(pubkey_text)} ~/.ssh/authorized_keys || echo {shlex.quote(pubkey_text)} >> ~/.ssh/authorized_keys",
            "chmod 600 ~/.ssh/authorized_keys",
        ]
        rc, out, err = _ssh_exec(c, " && ".join(cmds), sudo=False)
        if rc != 0:
            raise RuntimeError(f"Failed to install pubkey: {err or out}")
    finally:
        c.close()

def _configure_sshd(host: str, user: str, port: int, password: str):
    c = _connect_password(host, user, port, password)
    try:
        is_root = (user == "root")
        config_cmd = r"""
            sed -i '/^[[:space:]]*AllowTcpForwarding[[:space:]]/d' /etc/ssh/sshd_config
            sed -i '/^[[:space:]]*GatewayPorts[[:space:]]/d' /etc/ssh/sshd_config
            printf '%s\n' 'AllowTcpForwarding yes' 'GatewayPorts clientspecified' >> /etc/ssh/sshd_config
            (systemctl restart sshd || service ssh restart)
        """
        rc, out, err = _ssh_exec(c, config_cmd, sudo=not is_root, password=password)
        if rc != 0:
            raise RuntimeError(f"Failed to configure sshd: {err or out}")
    finally:
        c.close()

def prepare_server_with_password(host: str, user: str, port: int, password: str, key_path: str, pub_path: str):
    with open(pub_path, "r", encoding="utf-8") as f:
        pubkey = f.read().strip()
    _install_pubkey_with_password(host, user, port, password, pubkey)
    _configure_sshd(host, user, port, password)
    # Verify passwordless SSH works
    import subprocess
    test = subprocess.run([
        "ssh", "-i", os.path.expanduser(key_path),
        "-p", str(port),
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        f"{user}@{host}", "true"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if test.returncode != 0:
        raise RuntimeError(f"Passwordless SSH test failed: {test.stderr.decode(errors='ignore')}")

# -------------------------
# Pydantic models (v2)
# -------------------------
class ServerConnect(BaseModel):
    host: str
    user: str = "root"
    ssh_port: int = 22
    password: str
    ssh_key_path: str = "~/.ssh/id_ed25519"

    @field_validator("ssh_port")
    @classmethod
    def _port_ok(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("Invalid port")
        return v

class TunnelCreate(BaseModel):
    name: str = Field(..., pattern=r"^[a-zA-Z0-9._:-]{1,64}$")
    remote_bind_port: int
    local_port: int
    remote_bind_host: str = "0.0.0.0"
    local_host: str = "127.0.0.1"
    active: bool = True

    @field_validator("remote_bind_port", "local_port")
    @classmethod
    def _port_ok(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("Invalid port")
        return v

class TunnelInfo(BaseModel):
    name: str
    pid: Optional[int]
    running: bool
    active: bool
    created_at: float
    vps_host: str
    vps_user: str
    vps_ssh_port: int
    remote_bind: str
    local_bind: str
    returncode: Optional[int] = None

# -------------------------
# Tunnel Manager: uses ssh -R subprocesses
# -------------------------
class TunnelProcess:
    def __init__(self, name: str, cmd: List[str], proc: Optional[asyncio.subprocess.Process], meta: dict, active: bool):
        self.name = name
        self.cmd = cmd
        self.proc = proc  # None when disabled
        self.meta = meta
        self.active = active
        self.created_at = time.time()

class TunnelManager:
    def __init__(self):
        self._tunnels: Dict[str, TunnelProcess] = {}
        self._lock = asyncio.Lock()

    def _require_server(self):
        if not CURRENT.is_set():
            raise RuntimeError("No server connected. Use /connect first.")

    def _build_cmd(self, r_host: str, r_port: int, l_host: str, l_port: int) -> List[str]:
        self._require_server()
        return [
            "ssh", "-N", "-T",
            "-p", str(CURRENT.port),
            "-i", os.path.expanduser(CURRENT.key_path),
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "GatewayPorts=yes",
            "-R", f"{r_host}:{r_port}:{l_host}:{l_port}",
            f"{CURRENT.user}@{CURRENT.host}",
        ]

    async def _spawn(self, cmd: List[str]) -> asyncio.subprocess.Process:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        # Brief wait to detect immediate failure (bind denied etc.)
        try:
            await asyncio.wait_for(proc.wait(), timeout=0.6)
            stderr = (await proc.stderr.read()).decode(errors="ignore") if proc.stderr else ""
            raise RuntimeError(f"ssh exited immediately (code={proc.returncode}). stderr:\n{stderr}")
        except asyncio.TimeoutError:
            pass
        return proc

    async def create(self, spec: TunnelCreate):
        async with self._lock:
            if spec.name in self._tunnels:
                raise RuntimeError(f"Tunnel '{spec.name}' already exists.")
            cmd = self._build_cmd(spec.remote_bind_host, spec.remote_bind_port, spec.local_host, spec.local_port)
            proc = await self._spawn(cmd) if spec.active else None
            meta = {
                "vps_host": CURRENT.host,
                "vps_user": CURRENT.user,
                "vps_ssh_port": CURRENT.port,
                "remote_bind": f"{spec.remote_bind_host}:{spec.remote_bind_port}",
                "local_bind": f"{spec.local_host}:{spec.local_port}",
            }
            self._tunnels[spec.name] = TunnelProcess(spec.name, cmd, proc, meta, active=spec.active)

    async def list(self) -> List[TunnelInfo]:
        async with self._lock:
            out: List[TunnelInfo] = []
            for name, tp in self._tunnels.items():
                running = (tp.proc is not None and tp.proc.returncode is None)
                out.append(TunnelInfo(
                    name=name,
                    pid=(tp.proc.pid if (tp.proc and tp.proc.pid) else None),
                    running=running,
                    active=tp.active,
                    created_at=tp.created_at,
                    vps_host=tp.meta["vps_host"],
                    vps_user=tp.meta["vps_user"],
                    vps_ssh_port=tp.meta["vps_ssh_port"],
                    remote_bind=tp.meta["remote_bind"],
                    local_bind=tp.meta["local_bind"],
                    returncode=(tp.proc.returncode if tp.proc else None),
                ))
            return out

    async def get(self, name: str) -> Optional[TunnelInfo]:
        async with self._lock:
            tp = self._tunnels.get(name)
            if not tp:
                return None
            running = (tp.proc is not None and tp.proc.returncode is None)
            return TunnelInfo(
                name=name,
                pid=(tp.proc.pid if (tp.proc and tp.proc.pid) else None),
                running=running,
                active=tp.active,
                created_at=tp.created_at,
                vps_host=tp.meta["vps_host"],
                vps_user=tp.meta["vps_user"],
                vps_ssh_port=tp.meta["vps_ssh_port"],
                remote_bind=tp.meta["remote_bind"],
                local_bind=tp.meta["local_bind"],
                returncode=(tp.proc.returncode if tp.proc else None),
            )

    async def enable(self, name: str):
        async with self._lock:
            tp = self._tunnels.get(name)
            if not tp:
                raise RuntimeError(f"Tunnel '{name}' not found")
            if tp.proc is None or tp.proc.returncode is not None:
                tp.proc = await self._spawn(tp.cmd)
            tp.active = True

    async def disable(self, name: str):
        async with self._lock:
            tp = self._tunnels.get(name)
            if not tp:
                raise RuntimeError(f"Tunnel '{name}' not found")
            if tp.proc and tp.proc.returncode is None:
                tp.proc.terminate()
                try:
                    await asyncio.wait_for(tp.proc.wait(), timeout=2)
                except asyncio.TimeoutError:
                    tp.proc.kill()
            tp.proc = None
            tp.active = False

    async def delete(self, name: str):
        async with self._lock:
            tp = self._tunnels.get(name)
            if not tp:
                raise RuntimeError(f"Tunnel '{name}' not found")
            if tp.proc and tp.proc.returncode is None:
                tp.proc.terminate()
                try:
                    await asyncio.wait_for(tp.proc.wait(), timeout=2)
                except asyncio.TimeoutError:
                    tp.proc.kill()
            del self._tunnels[name]

    async def disable_all_and_clear(self):
        async with self._lock:
            for tp in list(self._tunnels.values()):
                if tp.proc and tp.proc.returncode is None:
                    tp.proc.terminate()
                    try:
                        await asyncio.wait_for(tp.proc.wait(), timeout=2)
                    except asyncio.TimeoutError:
                        tp.proc.kill()
            self._tunnels.clear()

MANAGER = TunnelManager()

# -------------------------
# Server info (via key auth) with timeout
# -------------------------
def get_server_info() -> dict:
    if not CURRENT.is_set():
        raise RuntimeError("No server connected.")
    
    # Try to connect with timeout
    try:
        c = _connect_key(CURRENT.host, CURRENT.user, CURRENT.port, CURRENT.key_path)
    except Exception as e:
        raise RuntimeError(f"Failed to connect to server: {e}")
    
    try:
        rc, distro, _ = _ssh_exec(c, "source /etc/os-release 2>/dev/null; echo ${PRETTY_NAME:-Unknown}")
        rc1, uname, _ = _ssh_exec(c, "uname -a")
        rc2, hostn, _ = _ssh_exec(c, "hostname -f || hostname")
        rc3, up, _ = _ssh_exec(c, "uptime -p || true")
        return {
            "host": CURRENT.host,
            "user": CURRENT.user,
            "ssh_port": CURRENT.port,
            "distro": (distro or "").strip() or "Unknown",
            "kernel": (uname or "").strip(),
            "hostname": (hostn or "").strip(),
            "uptime": (up or "").strip(),
        }
    finally:
        c.close()

# -------------------------
# Check server connection with timeout
# -------------------------
async def check_server_connection(timeout: float = SERVER_CONNECT_TIMEOUT) -> bool:
    """Check if server is reachable with timeout"""
    if not CURRENT.is_set():
        return False
    
    try:
        # Run the blocking connection check in a thread with timeout
        await asyncio.wait_for(
            asyncio.to_thread(_connect_key, CURRENT.host, CURRENT.user, CURRENT.port, CURRENT.key_path),
            timeout=timeout
        )
        return True
    except (asyncio.TimeoutError, Exception):
        return False

# -------------------------
# FastAPI app & routes
# -------------------------
app = FastAPI(title="Port Tunnel Manager", version="5.1.0")

STATIC_DIR = resource_path("static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
async def index():
    return FileResponse(str(pathlib.Path(STATIC_DIR) / "index.html"))

@app.post("/connect")
async def connect_server(cfg: ServerConnect):
    try:
        # Key creation is quick; do it inline
        key_path, pub_path = ensure_local_ssh_key(cfg.ssh_key_path)

        # Potentially slow network work -> thread + timeout
        await asyncio.wait_for(
            asyncio.to_thread(
                prepare_server_with_password,
                cfg.host, cfg.user, cfg.ssh_port, cfg.password, key_path, pub_path
            ),
            timeout=CONNECT_PREP_TIMEOUT
        )

        CURRENT.host = cfg.host
        CURRENT.user = cfg.user
        CURRENT.port = cfg.ssh_port
        CURRENT.key_path = key_path

        st = load_state()
        st["server"] = CURRENT.to_dict()
        save_state(st)

        # also get server info without blocking the loop
        info = await asyncio.wait_for(asyncio.to_thread(get_server_info), timeout=SERVER_CHECK_TIMEOUT)
        return {"ok": True, "server": info}
    except asyncio.TimeoutError:
        raise HTTPException(408, "Connect/prepare timed out")
    except Exception as e:
        raise HTTPException(400, str(e))

@app.get("/server")
async def server_info():
    try:
        # Check if server is reachable first with 40 second timeout
        is_connected = await check_server_connection(SERVER_CONNECT_TIMEOUT)
        if not is_connected:
            # Server is dead, clear the session
            await disconnect_server_internal()
            raise HTTPException(408, "Server is not reachable. Session has been cleared.")
        
        # Non-blocking + timeout so UI won't hang if VPS is gone
        info = await asyncio.wait_for(asyncio.to_thread(get_server_info), timeout=SERVER_CHECK_TIMEOUT)
        return {"ok": True, "server": info}
    except asyncio.TimeoutError:
        # Server is dead, clear the session
        await disconnect_server_internal()
        raise HTTPException(408, "Server info timed out. Session has been cleared.")
    except Exception as e:
        # If it fails, surface a clean error so UI can show Connect form
        raise HTTPException(400, str(e))

async def disconnect_server_internal():
    """Internal function to disconnect server and clear state"""
    try:
        await MANAGER.disable_all_and_clear()
        CURRENT.host = CURRENT.user = CURRENT.key_path = None
        CURRENT.port = None
        st = load_state()
        st["tunnels"] = {}
        st["server"] = None
        save_state(st)
        return True
    except Exception as e:
        log.error(f"Error during disconnect: {e}")
        return False

@app.post("/disconnect")
async def disconnect_server():
    try:
        success = await disconnect_server_internal()
        if success:
            return {"ok": True}
        else:
            raise HTTPException(500, "Failed to disconnect")
    except Exception as e:
        raise HTTPException(400, str(e))

@app.get("/tunnels", response_model=List[TunnelInfo])
async def list_tunnels():
    # Check server connection before listing tunnels
    is_connected = await check_server_connection(SERVER_CONNECT_TIMEOUT)
    if not is_connected:
        await disconnect_server_internal()
        raise HTTPException(408, "Server is not reachable. Session has been cleared.")
    
    return await MANAGER.list()

@app.get("/tunnels/{name}", response_model=TunnelInfo)
async def get_tunnel(name: str):
    # Check server connection before getting tunnel info
    is_connected = await check_server_connection(SERVER_CONNECT_TIMEOUT)
    if not is_connected:
        await disconnect_server_internal()
        raise HTTPException(408, "Server is not reachable. Session has been cleared.")
    
    t = await MANAGER.get(name)
    if not t:
        raise HTTPException(404, f"Tunnel '{name}' not found")
    return t

@app.post("/tunnels")
async def add_tunnel(spec: TunnelCreate):
    # Check server connection before adding tunnel
    is_connected = await check_server_connection(SERVER_CONNECT_TIMEOUT)
    if not is_connected:
        await disconnect_server_internal()
        raise HTTPException(408, "Server is not reachable. Session has been cleared.")
    
    try:
        await MANAGER.create(spec)
        st = load_state()
        if not st.get("tunnels"): st["tunnels"] = {}
        st["tunnels"][spec.name] = {
            "remote_bind_host": spec.remote_bind_host,
            "remote_bind_port": spec.remote_bind_port,
            "local_host": spec.local_host,
            "local_port": spec.local_port,
            "active": spec.active,
        }
        save_state(st)
        return {"ok": True, "name": spec.name}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.patch("/tunnels/{name}/enable")
async def enable_tunnel(name: str):
    # Check server connection before enabling tunnel
    is_connected = await check_server_connection(SERVER_CONNECT_TIMEOUT)
    if not is_connected:
        await disconnect_server_internal()
        raise HTTPException(408, "Server is not reachable. Session has been cleared.")
    
    try:
        await MANAGER.enable(name)
        st = load_state()
        if st.get("tunnels", {}).get(name):
            st["tunnels"][name]["active"] = True
            save_state(st)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.patch("/tunnels/{name}/disable")
async def disable_tunnel(name: str):
    try:
        await MANAGER.disable(name)
        st = load_state()
        if st.get("tunnels", {}).get(name):
            st["tunnels"][name]["active"] = False
            save_state(st)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.delete("/tunnels/{name}")
async def delete_tunnel(name: str):
    try:
        await MANAGER.delete(name)
        st = load_state()
        if st.get("tunnels", {}).get(name):
            del st["tunnels"][name]
            save_state(st)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(404, str(e))

# -------------------------
# Restore state ON THE SERVER LOOP (non-blocking + timeout)
# -------------------------
@app.on_event("startup")
async def startup_restore():
    st = load_state()
    server = st.get("server")
    tunnels = st.get("tunnels") or {}

    if server:
        try:
            CURRENT.from_dict(server)
            # Run blocking server check in a thread with timeout
            is_connected = await check_server_connection(SERVER_CONNECT_TIMEOUT)
            if not is_connected:
                log.warning(f"Could not restore server (server unreachable): {server['host']}")
                st["server"] = None
                st["tunnels"] = {}
                save_state(st)
                return
                
            log.info(f"Restored server {server['user']}@{server['host']}:{server['ssh_port']}")
        except Exception as e:
            log.warning(f"Could not restore server (clearing state): {e}")
            st["server"] = None
            st["tunnels"] = {}
            save_state(st)
            return

    # Only restore tunnels if server was reachable
    for name, t in tunnels.items():
        try:
            spec = TunnelCreate(
                name=name,
                remote_bind_host=t.get("remote_bind_host", "0.0.0.0"),
                remote_bind_port=t["remote_bind_port"],
                local_host=t.get("local_host", "127.0.0.1"),
                local_port=t["local_port"],
                active=False
            )
            await MANAGER.create(spec)
            if t.get("active", True):
                await MANAGER.enable(name)
            log.info(f"Restored tunnel {name} ({t['remote_bind_port']} -> {t['local_port']})")
        except Exception as e:
            log.warning(f"Could not restore tunnel '{name}': {e}")

# -------------------------
# CLI (local-only helpers using same persistence)
# -------------------------
def print_table(rows, headers):
    if not rows:
        print("No tunnels.")
        return
    colw = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
    def fmt_row(r): return "  ".join(str(r[i]).ljust(colw[i]) for i in range(len(headers)))
    print(fmt_row(headers))
    print("  ".join("-"*w for w in colw))
    for r in rows: print(fmt_row(r))

async def cli_connect(args):
    import getpass
    password = args.password or getpass.getpass(f"Password for {args.user}@{args.host}: ")
    key_path, pub_path = ensure_local_ssh_key(args.ssh_key_path)
    # blocking prep in a thread + timeout
    await asyncio.wait_for(
        asyncio.to_thread(prepare_server_with_password, args.host, args.user, args.ssh_port, password, key_path, pub_path),
        timeout=CONNECT_PREP_TIMEOUT
    )
    CURRENT.host, CURRENT.user, CURRENT.port, CURRENT.key_path = args.host, args.user, args.ssh_port, key_path
    st = load_state()
    st["server"] = CURRENT.to_dict()
    save_state(st)
    info = await asyncio.wait_for(asyncio.to_thread(get_server_info), timeout=SERVER_CHECK_TIMEOUT)
    print(f"Connected: {info['user']}@{info['host']}:{info['ssh_port']}  {info['distro']}")

async def cli_serverinfo(args):
    st = load_state()
    if st.get("server"):
        CURRENT.from_dict(st["server"])
    if not CURRENT.is_set():
        print("No server connected.")
        return
    
    # Check server connection with timeout
    is_connected = await check_server_connection(SERVER_CONNECT_TIMEOUT)
    if not is_connected:
        print("Server is not reachable. Clearing session.")
        await cli_disconnect(args)
        return
        
    try:
        info = await asyncio.wait_for(asyncio.to_thread(get_server_info), timeout=SERVER_CHECK_TIMEOUT)
        for k in ["host","user","ssh_port","hostname","distro","uptime","kernel"]:
            print(f"{k:10}: {info.get(k)}")
    except Exception as e:
        print(f"Error: {e}")

async def cli_list(args):
    st = load_state()
    server = st.get("server")
    rows = []
    for name, t in (st.get("tunnels") or {}).items():
        rows.append([
            name,
            f"{server['user']}@{server['host']}:{server['ssh_port']}" if server else "-",
            f"{t.get('remote_bind_host','0.0.0.0')}:{t['remote_bind_port']}",
            f"{t.get('local_host','127.0.0.1')}:{t['local_port']}",
            "on" if t.get("active", True) else "off"
        ])
    print_table(rows, ["name","vps","remote","local","active"])

async def cli_add(args):
    st = load_state()
    if st.get("server"):
        CURRENT.from_dict(st["server"])
    if not CURRENT.is_set():
        print("No server connected. Run 'connect' first.")
        return
    
    # Check server connection with timeout
    is_connected = await check_server_connection(SERVER_CONNECT_TIMEOUT)
    if not is_connected:
        print("Server is not reachable. Clearing session.")
        await cli_disconnect(args)
        return
        
    spec = TunnelCreate(
        name=args.name,
        remote_bind_port=args.remote_port,
        local_port=args.local_port,
        remote_bind_host=args.remote_host,
        local_host=args.local_host,
        active=not args.disabled
    )
    await MANAGER.create(spec)
    if spec.active:
        await MANAGER.enable(spec.name)
    st.setdefault("tunnels", {})[spec.name] = {
        "remote_bind_host": spec.remote_bind_host,
        "remote_bind_port": spec.remote_bind_port,
        "local_host": spec.local_host,
        "local_port": spec.local_port,
        "active": spec.active,
    }
    save_state(st)
    print(f"Added '{spec.name}' ({spec.remote_bind_host}:{spec.remote_bind_port} -> {spec.local_host}:{spec.local_port}) active={spec.active}")

async def cli_disable(args):
    st = load_state()
    if st.get("server"):
        CURRENT.from_dict(st["server"])
    await MANAGER.disable(args.name)
    if st.get("tunnels", {}).get(args.name):
        st["tunnels"][args.name]["active"] = False
        save_state(st)
    print(f"Disabled '{args.name}'")

async def cli_delete(args):
    st = load_state()
    if st.get("server"):
        CURRENT.from_dict(st["server"])
    await MANAGER.delete(args.name)
    if st.get("tunnels", {}).get(args.name):
        del st["tunnels"][args.name]
        save_state(st)
    print(f"Deleted '{args.name}'")

async def cli_disconnect(args):
    await MANAGER.disable_all_and_clear()
    st = load_state()
    st["tunnels"] = {}
    st["server"] = None
    save_state(st)
    CURRENT.host = CURRENT.user = CURRENT.key_path = None
    CURRENT.port = None
    print("Disconnected and cleared tunnels")

def build_argparser():
    p = argparse.ArgumentParser(description="Port Tunnel Manager (web + CLI)")
    p.add_argument("--webport", type=int, default=None, help="Start web server on this port (e.g. 8080). If omitted and no subcommand, defaults to 8000.")
    sub = p.add_subparsers(dest="cmd")

    c = sub.add_parser("connect", help="Prepare key auth & configure sshd via password")
    c.add_argument("--host", required=True)
    c.add_argument("--user", default="root")
    c.add_argument("--ssh-port", type=int, default=22)
    c.add_argument("--ssh-key-path", default="~/.ssh/id_ed25519")
    c.add_argument("--password", help="Password (prompted if omitted)")

    sub.add_parser("serverinfo", help="Show connected server info")
    sub.add_parser("list", help="List persisted tunnels (active flag)")

    a = sub.add_parser("add", help="Add a tunnel")
    a.add_argument("--name", required=True)
    a.add_argument("--remote-port", type=int, required=True, help="Remote port on VPS")
    a.add_argument("--local-port", type=int, required=True, help="Local port on this machine")
    a.add_argument("--remote-host", default="0.0.0.0")
    a.add_argument("--local-host", default="127.0.0.1")
    a.add_argument("--disabled", action="store_true", help="Create disabled")

    d = sub.add_parser("disable", help="Disable a tunnel")
    d.add_argument("--name", required=True)

    r = sub.add_parser("delete", help="Delete a tunnel")
    r.add_argument("--name", required=True)

    sub.add_parser("disconnect", help="Disconnect server and clear tunnels")
    return p

async def run_cli(args):
    if args.cmd == "connect":
        await cli_connect(args)
    elif args.cmd == "serverinfo":
        await cli_serverinfo(args)
    elif args.cmd == "list":
        await cli_list(args)
    elif args.cmd == "add":
        await cli_add(args)
    elif args.cmd == "disable":
        await cli_disable(args)
    elif args.cmd == "delete":
        await cli_delete(args)
    elif args.cmd == "disconnect":
        await cli_disconnect(args)
    else:
        print("Unknown command")

def start_web_server(port: int):
    port = port or 8000
    print(f"[+] Web UI on http://0.0.0.0:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")

if __name__ == "__main__":
    parser = build_argparser()
    args = parser.parse_args()

    if args.cmd:
        try:
            asyncio.run(run_cli(args))
        except KeyboardInterrupt:
            pass
        sys.exit(0)

    # No subcommand → start web server (restore happens in startup event on the server loop)
    start_web_server(args.webport or 8000)
