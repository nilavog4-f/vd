#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
# ##  VOID IP Intel — IP Address Intelligence Scanner
# ##  ** Multi-source geo, ASN, proxy/VPN/Tor, port check, DDG **
# ##  WSL / Kali Linux Edition  ·  @lfw.k4rma_
# ##  For authorized use only.
# ══════════════════════════════════════════════════════════════════

import subprocess, sys, os

def _ensure_deps():
    mods = {
        "requests":  "requests",
        "rich":      "rich",
        "pyfiglet":  "pyfiglet",
        "ddgs":      "ddgs",
    }
    for mod, pkg in mods.items():
        try:
            __import__(mod)
        except ImportError:
            print(f"[*] Installing {pkg}...")
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", pkg, "-q",
                     "--break-system-packages"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", pkg, "-q"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

_ensure_deps()

# ## Imports ######################################################
import json, re, time, socket, threading, concurrent.futures
from datetime import datetime
import requests
from ddgs import DDGS

from rich.console  import Console
from rich.table    import Table
from rich.text     import Text
from rich.align    import Align
from rich.rule     import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich          import box
import pyfiglet

console   = Console()
_ddg_lock = threading.Lock()

# ## Config #######################################################
CONFIG_FILE = "osint_config.json"
OPENROUTER  = "https://openrouter.ai/api/v1/chat/completions"

def _load_cfg():
    try:
        if os.path.exists(CONFIG_FILE):
            c = open(CONFIG_FILE).read().strip()
            if c: return json.loads(c)
    except Exception: pass
    return {"api_key": "", "model": "openai/gpt-4o-mini"}

cfg     = _load_cfg()
# Prefer the env var (Replit Secrets) over the plaintext config file.
API_KEY = os.environ.get("OPENROUTER_API_KEY", "").strip() or cfg.get("api_key", "")
MODEL   = cfg.get("model", "openai/gpt-4o-mini")

UA   = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36")
SESS = requests.Session()
SESS.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})

# Common ports to probe
PROBE_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017:"MongoDB",
}

# Known Tor exit list URL
TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"
_tor_exits: set = set()
_tor_loaded = False

# ## Banner #######################################################
def banner():
    console.clear()
    fig = pyfiglet.figlet_format("IP  INTEL", font="doom")
    colors = ["bright_cyan","cyan","bright_blue","blue",
              "bright_cyan","cyan","bright_blue","blue"]
    txt = Text()
    for i, line in enumerate(fig.splitlines()):
        txt.append(line + "\n", style=colors[i % len(colors)])
    console.print(Align.center(txt))

    sub = Text()
    sub.append("  ◈ ", style="bright_cyan")
    sub.append("IP ADDRESS INTELLIGENCE FRAMEWORK", style="bold bright_white")
    sub.append(" ◈  ", style="bright_cyan")
    console.print(Align.center(sub))

    tags = Text()
    for label, sep in [
        ("Geolocation", " | "), ("ASN / ISP", " | "), ("Proxy / VPN", " | "),
        ("Tor Detection", " | "), ("Port Scan", " | "), ("AI Analysis", ""),
    ]:
        tags.append(label, style="bright_cyan")
        if sep: tags.append(sep, style="dim cyan")
    console.print(Align.center(tags))
    console.print(Align.center(
        Text("by @lfw.k4rma_  ·  FOR AUTHORIZED USE ONLY\n", style="dim cyan")))
    console.print(Rule(style="bright_cyan"))

# ## Helpers ######################################################
def _get(url, **kw):
    try:
        return SESS.get(url, timeout=8, **kw)
    except Exception:
        return None

def _risk_label(score: int):
    if score == 0:  return "UNKNOWN",       "dim white"
    if score < 20:  return "CLEAN",         "bright_green"
    if score < 45:  return "SUSPICIOUS",    "yellow"
    if score < 70:  return "LIKELY THREAT", "bright_red"
    return               "CONFIRMED THREAT","bold bright_red"

def _bar(score: int, width=28) -> Text:
    filled = int(score / 100 * width)
    color  = _risk_label(score)[1].replace("bold ", "")
    t = Text()
    t.append("█" * filled,          style=color)
    t.append("░" * (width - filled), style="dim white")
    return t

def _load_tor_exits():
    global _tor_exits, _tor_loaded
    if _tor_loaded:
        return
    try:
        r = requests.get(TOR_EXIT_URL, timeout=6)
        _tor_exits = {line.strip() for line in r.text.splitlines()
                      if line.strip() and not line.startswith("#")}
    except Exception:
        _tor_exits = set()
    _tor_loaded = True

# ## Lookup sources ###############################################

def lookup_my_ip() -> str:
    """Return the caller's public IP."""
    for url in ["https://api.ipify.org", "https://icanhazip.com",
                "https://ifconfig.me/ip"]:
        r = _get(url)
        if r and r.status_code == 200:
            ip = r.text.strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                return ip
    return ""

def lookup_ip_api(ip: str) -> dict:
    """ip-api.com — free, no key, proxy/VPN/hosting flags."""
    fields = ("status,message,continent,country,countryCode,regionName,"
              "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,"
              "mobile,proxy,hosting,query")
    r = _get(f"http://ip-api.com/json/{ip}?fields={fields}")
    if r and r.status_code == 200:
        try:
            return r.json()
        except Exception:
            pass
    return {}

def lookup_ipwho(ip: str) -> dict:
    """ipwho.is — free backup geo source."""
    r = _get(f"https://ipwho.is/{ip}")
    if r and r.status_code == 200:
        try:
            return r.json()
        except Exception:
            pass
    return {}

def lookup_ipapi_co(ip: str) -> dict:
    """ipapi.co — secondary source, org/ASN cross-check."""
    r = _get(f"https://ipapi.co/{ip}/json/",
             headers={"Referer": "https://ipapi.co/"})
    if r and r.status_code == 200:
        try:
            return r.json()
        except Exception:
            pass
    return {}

def lookup_rdns(ip: str) -> str:
    """Reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def lookup_tor(ip: str) -> bool:
    """Check if IP is a known Tor exit node."""
    _load_tor_exits()
    return ip in _tor_exits

def port_scan(ip: str) -> dict:
    """Quick TCP connect scan on common ports. Returns {port: banner_or_open}."""
    open_ports = {}

    def _probe(port):
        try:
            with socket.create_connection((ip, port), timeout=1.2) as s:
                try:
                    s.settimeout(0.5)
                    banner = s.recv(256).decode("utf-8", errors="ignore").strip()[:60]
                except Exception:
                    banner = ""
                open_ports[port] = banner or "open"
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = [ex.submit(_probe, p) for p in PROBE_PORTS]
        concurrent.futures.wait(futures, timeout=5)

    return open_ports

def ddg_search(ip: str) -> dict:
    result = {"results": [], "abuse_mentions": 0, "platforms": []}
    platforms = ["shodan", "censys", "abuseipdb", "virustotal",
                 "greynoise", "threatcrowd", "spamhaus"]
    snippets  = []

    queries = [
        f'"{ip}"',
        f'"{ip}" abuse OR spam OR malware OR threat',
        f'"{ip}" site:shodan.io OR site:abuseipdb.com OR site:greynoise.io',
    ]

    for q in queries:
        try:
            with _ddg_lock:
                hits = list(DDGS().text(q, max_results=4))
            for h in hits:
                body  = h.get("body", "") or h.get("snippet", "")
                title = h.get("title", "")
                snippets.append(f"{title} {body}")
                result["results"].append({
                    "title": title[:80],
                    "url":   h.get("href", "")[:100],
                    "body":  body[:120],
                })
            time.sleep(0.3)
        except Exception:
            pass

    full = " ".join(snippets).lower()
    abuse_words = ["abuse", "spam", "malware", "botnet", "ransomware",
                   "threat", "malicious", "attack", "reported", "blacklist"]
    result["abuse_mentions"] = sum(1 for w in abuse_words if w in full)
    result["platforms"] = [p for p in platforms if p in full]
    return result

def ai_summary(ip: str, data: dict) -> str:
    if not API_KEY:
        return ""
    prompt = (
        f"You are an IP threat analyst. Summarize the following data about "
        f"IP address {ip} in 3-4 sentences. Give a clear verdict: "
        f"is this IP clean, suspicious, or a known threat?\n\n"
        f"Data:\n{json.dumps(data, indent=2, default=str)[:3000]}"
    )
    try:
        r = requests.post(
            OPENROUTER,
            headers={"Authorization": f"Bearer {API_KEY}",
                     "Content-Type": "application/json"},
            json={"model": MODEL,
                  "messages": [{"role": "user", "content": prompt}],
                  "max_tokens": 280},
            timeout=20
        )
        return r.json()["choices"][0]["message"]["content"].strip()
    except Exception:
        return ""

# ## Threat score #################################################
def calc_threat_score(ip_api: dict, ipwho: dict, is_tor: bool,
                      open_ports: dict, ddg: dict) -> int:
    score = 0

    # Proxy / VPN flag from ip-api
    if ip_api.get("proxy"):
        score += 35
    # Hosting / data-center
    if ip_api.get("hosting"):
        score += 20
    # Tor exit node
    if is_tor:
        score += 45

    # Sensitive open ports
    sensitive = {23, 3389, 5900, 445, 6379, 27017}
    for p in open_ports:
        if p in sensitive:
            score += 8

    # DDG abuse mentions
    mentions = ddg.get("abuse_mentions", 0)
    score += min(mentions * 5, 25)

    # Known threat intel platforms found it
    plat_count = len(ddg.get("platforms", []))
    score += min(plat_count * 5, 15)

    return min(score, 100)

# ## Display ######################################################
def display_results(ip: str, ip_api: dict, ipwho: dict, ipco: dict,
                    rdns: str, is_tor: bool, open_ports: dict,
                    ddg: dict, ai: str, score: int):

    risk_label, risk_color = _risk_label(score)
    score_col = risk_color.replace("bold ", "")

    console.print()
    console.print(Rule("[bold bright_cyan]  ◈  IP INTEL RESULTS  ◈  [/]",
                       style="bright_cyan"))
    console.print()

    # ## Stat summary (no box borders)
    summary = Text()
    summary.append("  IP ", style="dim")
    summary.append(ip, style="bold bright_cyan")
    summary.append("    THREAT SCORE ", style="dim")
    summary.append(str(score), style=f"bold {score_col}")
    summary.append("    VERDICT ", style="dim")
    summary.append(risk_label, style=risk_color)
    summary.append("  ")
    console.print(Align.center(summary))
    console.print()

    # Threat meter
    console.print(f"  [dim]Threat meter[/]  [{score_col}]{score:3d}/100[/]  ", end="")
    console.print(_bar(score))
    console.print()

    # ## Identity flags
    flags = []
    if ip_api.get("proxy"):  flags.append(("[bright_red]⚠  PROXY / VPN DETECTED[/bright_red]", True))
    if ip_api.get("hosting"): flags.append(("[yellow]⚠  HOSTING / DATA CENTER[/yellow]", True))
    if is_tor:               flags.append(("[bold bright_red]⚠  TOR EXIT NODE[/bold bright_red]", True))
    if ip_api.get("mobile"): flags.append(("[bright_cyan]◈  MOBILE NETWORK[/bright_cyan]", False))
    if not flags:            flags.append(("[bright_green]✓  No proxy/VPN/Tor flags[/bright_green]", False))

    for flag, _ in flags:
        console.print(f"  {flag}")
    console.print()

    # ## Geolocation details
    console.print(Rule("[dim cyan]  GEOLOCATION  [/]", style="dim cyan"))
    geo_rows = [
        ("IP Address",   ip_api.get("query", ip),              "bright_cyan"),
        ("Country",      ip_api.get("country", "—"),           "bright_white"),
        ("Region",       ip_api.get("regionName", "—"),        "white"),
        ("City",         ip_api.get("city", "—"),              "white"),
        ("Postal Code",  ip_api.get("zip", "—"),               "dim white"),
        ("Latitude",     str(ip_api.get("lat", "—")),          "dim white"),
        ("Longitude",    str(ip_api.get("lon", "—")),          "dim white"),
        ("Timezone",     ip_api.get("timezone", "—"),          "dim white"),
        ("Coordinates",
         (f"https://maps.google.com/?q={ip_api['lat']},{ip_api['lon']}"
          if ip_api.get("lat") else "—"),
         "blue underline"),
    ]
    for label, value, color in geo_rows:
        console.print(f"  [dim]{label:<18}[/]  [{color}]{value}[/]")
    console.print()

    # ## Network details
    console.print(Rule("[dim cyan]  NETWORK / ASN  [/]", style="dim cyan"))
    net_rows = [
        ("ISP",          ip_api.get("isp", "—"),               "bright_magenta"),
        ("Organisation", ip_api.get("org", "—"),               "bright_magenta"),
        ("ASN",          ip_api.get("as", "—"),                "yellow"),
        ("AS Name",      ip_api.get("asname", "—"),            "yellow"),
        ("Reverse DNS",  rdns or "—",                          "bright_white"),
        ("Type",
         ("Mobile" if ip_api.get("mobile") else
          "Hosting/DC" if ip_api.get("hosting") else
          "Residential"),
         "bright_cyan"),
    ]
    for label, value, color in net_rows:
        console.print(f"  [dim]{label:<18}[/]  [{color}]{value}[/]")
    console.print()

    # ## Source comparison table
    console.print(Rule("[dim cyan]  SOURCE CROSS-CHECK  [/]", style="dim cyan"))
    t = Table(box=box.SIMPLE_HEAVY, border_style="dim cyan",
              header_style="bold cyan", expand=True)
    t.add_column("SOURCE",    width=18)
    t.add_column("COUNTRY",   width=14)
    t.add_column("CITY",      width=16)
    t.add_column("ISP / ORG", min_width=24)
    t.add_column("FLAGS",     min_width=20)

    # ip-api.com
    api_flags = []
    if ip_api.get("proxy"):   api_flags.append("[red]PROXY[/red]")
    if ip_api.get("hosting"): api_flags.append("[yellow]HOSTING[/yellow]")
    if ip_api.get("mobile"):  api_flags.append("[cyan]MOBILE[/cyan]")
    if is_tor:                api_flags.append("[bold red]TOR[/bold red]")
    t.add_row(
        "ip-api.com",
        ip_api.get("country", "—"),
        ip_api.get("city", "—"),
        (ip_api.get("isp") or ip_api.get("org") or "—")[:30],
        " ".join(api_flags) if api_flags else "[dim green]clean[/dim green]"
    )

    # ipwho.is
    t.add_row(
        "ipwho.is",
        ipwho.get("country", "—"),
        ipwho.get("city", "—"),
        (ipwho.get("connection", {}).get("isp") or
         ipwho.get("org", "") or "—")[:30],
        "[yellow]PROXY[/yellow]" if ipwho.get("is_proxy") else "[dim green]clean[/dim green]"
    )

    # ipapi.co
    t.add_row(
        "ipapi.co",
        ipco.get("country_name", "—"),
        ipco.get("city", "—"),
        (ipco.get("org") or ipco.get("asn") or "—")[:30],
        "—"
    )

    console.print(t)

    # ## Open ports
    if open_ports:
        console.print(Rule("[dim cyan]  OPEN PORTS  [/]", style="dim cyan"))
        pt = Table(box=box.SIMPLE_HEAVY, border_style="dim cyan",
                   header_style="bold cyan", expand=False)
        pt.add_column("PORT", width=8, style="bright_cyan")
        pt.add_column("SERVICE", width=12, style="bright_white")
        pt.add_column("RISK", width=10)
        pt.add_column("BANNER", min_width=30, style="dim")

        high_risk = {23, 3389, 5900, 445, 6379, 27017, 110, 143}
        for port in sorted(open_ports):
            svc    = PROBE_PORTS.get(port, "unknown")
            banner = open_ports[port]
            if port in high_risk:
                risk = "[bright_red]HIGH[/bright_red]"
            elif port in {21, 25, 3306}:
                risk = "[yellow]MEDIUM[/yellow]"
            else:
                risk = "[dim green]LOW[/dim green]"
            pt.add_row(str(port), svc, risk, banner[:50] if banner != "open" else "")
        console.print(pt)
    else:
        console.print(Rule("[dim cyan]  OPEN PORTS  [/]", style="dim cyan"))
        console.print("  [dim green]No open ports detected on scanned range.[/dim green]")
    console.print()

    # ## DDG web intelligence
    console.print(Rule("[dim cyan]  WEB INTELLIGENCE  [/]", style="dim cyan"))
    plats = ddg.get("platforms", [])
    if plats:
        console.print(f"  [dim]Found on       :[/]  [bright_magenta]"
                      f"{', '.join(p.capitalize() for p in plats)}[/]")
    mentions = ddg.get("abuse_mentions", 0)
    m_col = "bright_red" if mentions >= 3 else ("yellow" if mentions >= 1 else "dim green")
    console.print(f"  [dim]Abuse mentions :[/]  [{m_col}]{mentions} abuse-related reference(s)[/]")

    web_results = ddg.get("results", [])
    if web_results:
        console.print(f"\n  [bold dim]Top results:[/]")
        for r in web_results[:4]:
            if r.get("url"):
                console.print(f"  [dim cyan]•[/]  [blue underline]{r['url']}[/]")
                if r.get("body"):
                    console.print(f"     [dim]{r['body'][:120]}[/]")
    console.print()

    # ## AI summary
    if ai:
        console.print(Rule("[dim cyan]  AI ANALYSIS  [/]", style="dim cyan"))
        console.print(f"  [bright_white]{ai}[/bright_white]")
        console.print()

    console.print(Rule(style="bright_cyan"))

# ## Main #########################################################
def main():
    banner()
    console.print()

    while True:
        console.print("  [dim cyan]◈[/]  ", end="")
        raw = input(
            "Enter IP address (or press Enter to look up your own IP, Q to quit): "
        ).strip()

        if raw.lower() in ("q", "quit", "exit"):
            console.print("  [dim]Session ended.[/]"); break

        if not raw:
            console.print("  [dim cyan]⟳  Detecting your public IP...[/]", end="\r")
            raw = lookup_my_ip()
            if not raw:
                console.print("  [red][!] Could not detect public IP.[/]"); continue
            console.print(f"  [dim]Your public IP:[/]  [bright_cyan]{raw}[/]")

        # Basic validation
        ip = raw.strip()
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            # Could be a hostname — try resolving
            try:
                resolved = socket.gethostbyname(ip)
                console.print(f"  [dim]Resolved:[/]  [bright_cyan]{ip}[/] → [bright_white]{resolved}[/]")
                ip = resolved
            except Exception:
                console.print(f"  [red][!] Invalid IP or hostname: {ip}[/]"); continue

        console.print()

        # ## Run all lookups in parallel
        results = {}
        tasks = {
            "ip_api": (lookup_ip_api,  [ip]),
            "ipwho":  (lookup_ipwho,   [ip]),
            "ipco":   (lookup_ipapi_co,[ip]),
            "rdns":   (lookup_rdns,    [ip]),
            "tor":    (lookup_tor,     [ip]),
            "ports":  (port_scan,      [ip]),
            "ddg":    (ddg_search,     [ip]),
        }

        with Progress(
            SpinnerColumn(spinner_name="dots", style="bright_cyan"),
            TextColumn("[bright_cyan]{task.description}[/]"),
            BarColumn(bar_width=28, style="cyan", complete_style="bright_cyan"),
            TextColumn("[dim]{task.completed}/{task.total}[/]"),
            console=console,
            transient=True,
        ) as prog:
            tid = prog.add_task("Running IP intelligence scan...", total=len(tasks))

            with concurrent.futures.ThreadPoolExecutor(max_workers=7) as ex:
                futures = {
                    ex.submit(fn, *args): key
                    for key, (fn, args) in tasks.items()
                }
                for fut in concurrent.futures.as_completed(futures):
                    key = futures[fut]
                    try:
                        results[key] = fut.result()
                    except Exception:
                        results[key] = {} if key not in ("rdns","tor","ports") else ("" if key == "rdns" else (False if key == "tor" else {}))
                    prog.advance(tid)

        ip_api = results.get("ip_api", {})
        ipwho  = results.get("ipwho",  {})
        ipco   = results.get("ipco",   {})
        rdns   = results.get("rdns",   "")
        is_tor = results.get("tor",    False)
        ports  = results.get("ports",  {})
        ddg    = results.get("ddg",    {})

        score = calc_threat_score(ip_api, ipwho, is_tor, ports, ddg)

        # AI summary
        ai = ""
        if API_KEY:
            with Progress(
                SpinnerColumn(spinner_name="dots", style="cyan"),
                TextColumn("[cyan]Running AI analysis...[/]"),
                console=console, transient=True
            ) as p:
                p.add_task("", total=None)
                ai = ai_summary(ip, {
                    "ip_api": ip_api, "tor": is_tor,
                    "open_ports": list(ports.keys()),
                    "threat_score": score,
                    "ddg_abuse_mentions": ddg.get("abuse_mentions", 0),
                })

        display_results(ip, ip_api, ipwho, ipco, rdns, is_tor, ports, ddg, ai, score)

        # Save JSON
        fname = f"ip_intel_{ip.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(fname, "w") as f:
                json.dump({
                    "ip": ip, "threat_score": score,
                    "verdict": _risk_label(score)[0],
                    "ip_api": ip_api, "ipwho": ipwho, "ipco": ipco,
                    "rdns": rdns, "tor_exit": is_tor,
                    "open_ports": {str(k): v for k, v in ports.items()},
                    "web_intel": ddg, "ai_summary": ai,
                    "scanned_at": datetime.now().isoformat(),
                }, f, indent=2)
            console.print(f"  [dim]Full report saved to:[/]  [bright_cyan]{fname}[/]")
        except Exception:
            pass

        console.print()
        console.print("  [dim cyan]◈[/]  ", end="")
        again = input("Scan another IP? (Y/N): ").strip().lower()
        if again not in ("y", "yes"):
            break

    console.print("\n  [dim]Session ended.[/]\n")

# ## Entry ########################################################
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n  [dim]Scan cancelled.[/]")
    except Exception as exc:
        console.print(f"\n  [bright_red][!] Error:[/bright_red]  [red]{exc}[/red]")
