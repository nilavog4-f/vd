#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
# ##  VOID DDoS Simulator — Visual Attack Demonstration
# ##  ** Fake / educational — no real packets sent **
# ##  WSL / Kali Linux Edition  ·  @lfw.k4rma_
# ##  FOR DEMONSTRATION USE ONLY
# ══════════════════════════════════════════════════════════════════

import subprocess, sys, os

def _ensure_deps():
    for mod, pkg in [("rich","rich"),("pyfiglet","pyfiglet"),("requests","requests")]:
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

# ## Imports ######################################################
import time, random, socket, threading, json, re
import urllib.request
from datetime import datetime

from rich.console  import Console
from rich.text     import Text
from rich.align    import Align
from rich.rule     import Rule
from rich.table    import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich          import box
import pyfiglet

console    = Console()
stop_event = threading.Event()

# ## Color helpers ################################################
def _r(s):  return f"[bold bright_red]{s}[/]"
def _c(s):  return f"[bold bright_cyan]{s}[/]"
def _y(s):  return f"[bold yellow]{s}[/]"
def _g(s):  return f"[bold bright_green]{s}[/]"
def _w(s):  return f"[bold white]{s}[/]"
def _d(s):  return f"[dim]{s}[/]"

# ## Skull ########################################################
SKULL = [
    "        .ed\"\"\"\" \"\"\"$$$$be.",
    "      -\"           ^\"\"**$$$e.",
    "    .\"                   '$$$c",
    "   /                      \"4$$b",
    "  d  3                      $$$$",
    "  $  *                   .$$$$$$",
    " .$  ^c           $$$$$e$$$$$$$$.",
    " d$L  4.         4$$$$$$$$$$$$$$b",
    " $$$$b ^ceeeee.  4$$ECL.F*$$$$$$$",
    " $$$$P d$$$$F $ $$$$$$$$$- $$$$$$",
    " 3$$$F \"$$$$b   $\"$$$$$$$  $$$$*\"",
    "  $$P\"  \"$$b   .$ $$$$$...e$$",
    "   *c    ..    $$ 3$$$$$$$$$$eF",
    "     %ce\"\"    $$$  $$$$$$$$$$*",
    "      *$e.    *** d$$$$$\"L$$",
    "       $$$      4J$$$$$% $$$",
    "      $\"'$=e....$*$$**$cz$$\"",
    "      $  *=%4.$ L L$ P3$$$F",
    "      $   \"%*ebJLzb$e$$$$$b",
    "       %..      4$$$$$$$$$$",
    "        $$$e   z$$$$$$$$$$",
    "         \"*$c  \"$$$$$$$P\"",
    "           \"\"\"*$$$$$$$\"",
]

# ## Banner #######################################################
def banner():
    console.clear()

    fig = pyfiglet.figlet_format("VOID  DDOS", font="doom")
    shades = ["bright_red","red","bright_red","red","bright_red","red","bright_red","red"]
    txt = Text()
    for i, line in enumerate(fig.splitlines()):
        txt.append(line + "\n", style=shades[i % len(shades)])
    console.print(Align.center(txt))

    # skull
    skull_txt = Text()
    for line in SKULL:
        skull_txt.append("  " + line + "\n", style="bold bright_red")
    console.print(Align.center(skull_txt))

    sub = Text()
    sub.append("  ◈ ", style="bright_red")
    sub.append("VISUAL ATTACK SIMULATOR", style="bold white")
    sub.append("  —  ", style="dim red")
    sub.append("FOR DEMONSTRATION USE ONLY", style="bold yellow")
    sub.append(" ◈  ", style="bright_red")
    console.print(Align.center(sub))
    console.print(Align.center(
        Text("by @lfw.k4rma_  ·  WSL / Kali Linux Edition\n", style="dim red")))
    console.print(Rule(style="bright_red"))

# ## IP lookup ####################################################
def lookup_ip(ip: str) -> dict:
    try:
        url = (f"http://ip-api.com/json/{ip}?fields=status,country,regionName,"
               f"city,zip,isp,org,as,lat,lon,timezone,mobile,proxy,hosting,query")
        req = urllib.request.urlopen(url, timeout=6)
        data = json.loads(req.read().decode())
        if data.get("status") == "success":
            return data
    except Exception:
        pass
    return {}

def show_ip_info(ip: str, info: dict):
    console.print()
    console.print(Rule("[bold bright_red]  TARGET INTELLIGENCE  [/]", style="bright_red"))
    console.print()
    rows = [
        ("IP Address",  ip,                                               "bold yellow"),
        ("Country",     info.get("country","—"),                          "bold white"),
        ("Region",      info.get("regionName","—"),                       "white"),
        ("City",        info.get("city","—"),                             "white"),
        ("ISP",         info.get("isp","—"),                              "bright_cyan"),
        ("Organisation",info.get("org","—"),                              "bright_cyan"),
        ("ASN",         info.get("as","—"),                               "dim white"),
        ("Timezone",    info.get("timezone","—"),                         "dim white"),
        ("Coordinates", f"{info.get('lat','?')}, {info.get('lon','?')}", "dim white"),
        ("Mobile",      "YES" if info.get("mobile")  else "no",
                        "yellow" if info.get("mobile") else "dim green"),
        ("Proxy / VPN", "YES — DETECTED" if info.get("proxy") else "no",
                        "bold bright_red" if info.get("proxy") else "dim green"),
        ("Hosting / DC","YES" if info.get("hosting") else "no",
                        "yellow" if info.get("hosting") else "dim green"),
    ]
    for label, val, col in rows:
        console.print(f"  [dim]{label:<18}[/]  [{col}]{val}[/]")
    console.print()

# ## Init sequence ################################################
def init_sequence(ip: str):
    banner()
    console.print()

    # IP lookup
    with Progress(
        SpinnerColumn(spinner_name="dots", style="bright_red"),
        TextColumn("[bright_red]{task.description}[/]"),
        console=console, transient=True
    ) as p:
        p.add_task("Looking up target intelligence...", total=None)
        info = lookup_ip(ip)

    if info:
        console.print(f"  [bright_red]◈[/]  [bold white]Target lookup[/]  [bright_green][ FOUND ][/]")
        show_ip_info(ip, info)
    else:
        console.print(f"  [bright_red]◈[/]  [bold white]Target lookup[/]  [yellow][ LOCAL / PRIVATE ][/]")
        console.print(f"\n  [dim]IP Address[/]  [bold yellow]{ip}[/]\n")

    # Fake init steps
    steps = [
        ("Resolving hostname",             0.45),
        ("Bypassing firewall rules",       0.55),
        ("Loading 2,048 spoofed IP pool",  0.50),
        ("Spawning 512 attack threads",    0.60),
        ("Arming SYN-flood engine",        0.35),
        ("Arming UDP-storm engine",        0.35),
        ("Arming HTTP-flood engine",       0.35),
        ("Arming ICMP-flood engine",       0.35),
        ("Calibrating packet rate",        0.40),
        ("Establishing proxy chain",       0.50),
        ("Locking on target",              0.80),
    ]

    console.print(Rule("[dim red]  ARMING  [/]", style="dim red"))
    console.print()

    for label, dur in steps:
        console.print(f"  [bright_red]▶[/]  [dim]{label}...[/]", end="  ")
        time.sleep(dur)
        console.print("[bold bright_green][ OK ][/]")

    console.print()
    console.print(f"  [bold yellow][!][/]  Type [bold bright_red]stop[/] and press Enter to halt.")
    console.print()
    console.print(Rule(style="bright_red"))
    console.print()

    for i in range(3, 0, -1):
        console.print(f"\r  [bold bright_red][!][/]  [bold white]Launching in [bright_red]{i}[/]...[/]", end="")
        time.sleep(1)
    console.print(f"\r  [bold bright_red][!!!][/]  [bold bright_red]FIRING![/]                        ")
    console.print()

# ## Stop listener ################################################
def stop_listener():
    while not stop_event.is_set():
        try:
            if input().strip().lower() == "stop":
                stop_event.set()
                break
        except Exception:
            break

# ## Attack types #################################################
ATTACK_TYPES = ["SYN  ", "UDP  ", "HTTP ", "ICMP ", "ACK  ", "RST  ", "FRAG "]
STATUS_POOL  = [
    ("[bold bright_green]SENT  [/]",  55),
    ("[bold yellow]ACK   [/]",        15),
    ("[dim]DROP  [/]",                20),
    ("[bold bright_cyan]FRAG  [/]",   10),
]

def run_attack(ip: str):
    threading.Thread(target=stop_listener, daemon=True).start()

    packets = 0
    total_b = 0
    start   = time.time()

    # Header row
    hdr = Table(box=box.SIMPLE_HEAVY, border_style="bright_red",
                header_style="bold white", show_footer=False, expand=True)
    hdr.add_column("TYPE",       width=7,  style="bold red")
    hdr.add_column("SPOOFED SRC",width=18, style="dim")
    hdr.add_column("TARGET",     width=18, style="bold white")
    hdr.add_column("PORT",       width=7,  style="yellow")
    hdr.add_column("BYTES",      width=7,  style="dim")
    hdr.add_column("STATUS",     width=10)
    console.print(hdr)

    row_count = 0
    try:
        while not stop_event.is_set():
            atype  = random.choice(ATTACK_TYPES)
            src    = (f"{random.randint(1,254)}.{random.randint(0,254)}."
                      f"{random.randint(0,254)}.{random.randint(1,254)}")
            port   = random.randint(1024, 65535)
            pkt_b  = random.randint(512, 9999)
            status = random.choices(
                [s[0] for s in STATUS_POOL],
                weights=[s[1] for s in STATUS_POOL]
            )[0]

            packets += 1
            total_b += pkt_b
            elapsed  = time.time() - start
            pps      = packets / elapsed if elapsed else 0

            if "SYN" in atype or "RST" in atype:
                type_col = "bold bright_red"
            elif "UDP" in atype:
                type_col = "bold bright_cyan"
            else:
                type_col = "bold yellow"

            console.print(
                f"  [{type_col}]{atype}[/]  [dim]{src:<18}[/]  "
                f"[bold white]{ip:<18}[/]  [yellow]{port:<6}[/]  "
                f"[dim]{pkt_b:<6}[/]  {status}"
            )
            row_count += 1

            # Stats block every 20 rows
            if row_count % 20 == 0:
                elapsed = time.time() - start
                pps     = packets / elapsed if elapsed else 0
                mbps    = (total_b * 8) / elapsed / 1_000_000 if elapsed else 0

                fs = int(random.uniform(0.55, 0.95) * 30)
                fu = int(random.uniform(0.30, 0.80) * 30)
                fh = int(random.uniform(0.20, 0.65) * 30)

                def bar(filled, total=30, col="bright_red"):
                    b = Text()
                    b.append("█" * filled,          style=col)
                    b.append("░" * (total - filled), style="dim")
                    return b

                console.print()
                console.print(Rule("[dim red]  STATS  [/]", style="dim red"))
                console.print(
                    f"  [dim]Packets[/]  [bold white]{packets:>10,}[/]    "
                    f"[dim]Rate[/]  [bold white]{pps:>10,.0f} pps[/]    "
                    f"[dim]BW[/]  [bold white]{mbps:.2f} Mbps[/]    "
                    f"[dim]Up[/]  [bold white]{elapsed:.0f}s[/]"
                )
                console.print(f"  [bold white]SYN [/] ", end=""); console.print(bar(fs, col="bright_red"))
                console.print(f"  [bold white]UDP [/] ", end=""); console.print(bar(fu, col="bright_cyan"))
                console.print(f"  [bold white]HTTP[/] ", end=""); console.print(bar(fh, col="yellow"))
                console.print(Rule(style="dim red"))
                console.print()

            time.sleep(random.uniform(0.025, 0.08))

    except KeyboardInterrupt:
        stop_event.set()

    elapsed = time.time() - start
    pps_avg = packets / elapsed if elapsed else 0
    console.print()
    console.print(Rule("[bold bright_red]  ATTACK STOPPED  [/]", style="bright_red"))
    console.print()
    console.print(f"  [dim]Total packets [/]  [bold bright_green]{packets:,}[/]")
    console.print(f"  [dim]Duration      [/]  [bold white]{elapsed:.1f}s[/]")
    console.print(f"  [dim]Avg rate      [/]  [bold white]{pps_avg:,.0f} pps[/]")
    console.print(f"  [dim]Data sent     [/]  [bold white]{total_b/1_000_000:.2f} MB (simulated)[/]")
    console.print()
    console.print(Rule(style="bright_red"))

# ## Main #########################################################
def main():
    banner()
    console.print()

    # Accept IP from argv (launched from run.sh) or interactive prompt
    if len(sys.argv) >= 2:
        ip = sys.argv[1].strip()
    else:
        while True:
            console.print("  [bright_red]◈[/]  ", end="")
            ip = input("Target IP address (or Q to quit): ").strip()
            if ip.lower() in ("q", "quit", "exit"):
                console.print("  [dim]Aborted.[/]"); return
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                break
            # Try hostname resolve
            try:
                resolved = socket.gethostbyname(ip)
                console.print(f"  [dim]Resolved:[/]  [bold yellow]{resolved}[/]")
                ip = resolved
                break
            except Exception:
                pass
            console.print(f"  [bold red][!][/]  Invalid IP or hostname — try again")

    # Validate
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        console.print(f"\n  [bold red][ERROR][/]  Invalid IP: [yellow]{ip}[/]\n")
        return

    # Confirm
    console.print()
    console.print(Rule("[dim red]  CONFIRM  [/]", style="dim red"))
    console.print(f"  [dim]Target  [/]  [bold yellow]{ip}[/]")
    console.print(f"  [dim]Modes   [/]  [bold red]SYN-Flood  UDP-Storm  HTTP-Flood  ICMP[/]")
    console.print(f"  [dim]Threads [/]  [bold red]512[/]")
    console.print(f"  [dim]Rate    [/]  [bold red]~950,000 pps[/]")
    console.print()
    console.print("  [bright_red]◈[/]  ", end="")
    confirm = input(f"Launch simulation on {ip}? (Y/N): ").strip().lower()
    if confirm not in ("y", "yes"):
        console.print("\n  [yellow][!][/]  Aborted.\n"); return

    try:
        init_sequence(ip)
        run_attack(ip)
    except KeyboardInterrupt:
        console.print("\n  [yellow]Aborted.[/]\n")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        console.print(f"\n  [bold red][!] Error:[/]  [red]{exc}[/]\n")
