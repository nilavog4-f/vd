#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
# ##  VOID Port Scanner — TCP/UDP + Minecraft + Vuln Flags
# ##  ** Multi-threaded · banner grabbing · risk scoring **
# ##  WSL / Kali Linux Edition  ·  @lfw.k4rma_
# ##  For authorized use on systems you own / have permission to scan.
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

import socket, threading, time, re, struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from rich.console  import Console
from rich.table    import Table
from rich.text     import Text
from rich.align    import Align
from rich.rule     import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich          import box
import pyfiglet

console = Console()

# ── Port definitions ──────────────────────────────────────────────
TCP_PORTS = {
    21:    ("FTP",              "File transfer — credentials often in cleartext"),
    22:    ("SSH",              "Secure shell — check for weak keys/passwords"),
    23:    ("Telnet",           "Unencrypted remote shell — CRITICAL RISK"),
    25:    ("SMTP",             "Mail server — check for open relay"),
    53:    ("DNS",              "DNS server — check for zone transfer"),
    80:    ("HTTP",             "Web server"),
    110:   ("POP3",             "Mail retrieval — cleartext if no TLS"),
    135:   ("MS-RPC",           "Windows RPC — common exploit vector"),
    137:   ("NetBIOS-NS",       "Windows NetBIOS name service"),
    139:   ("NetBIOS-SSN",      "Windows file sharing"),
    143:   ("IMAP",             "Mail — cleartext if no TLS"),
    443:   ("HTTPS",            "Encrypted web server"),
    445:   ("SMB",              "Windows file sharing — EternalBlue target"),
    1433:  ("MSSQL",            "Microsoft SQL Server — database exposure"),
    1521:  ("Oracle DB",        "Oracle database — database exposure"),
    3306:  ("MySQL",            "MySQL database — CRITICAL if public"),
    3389:  ("RDP",              "Remote Desktop — BlueKeep / brute force target"),
    4444:  ("Metasploit",       "Common Metasploit default listener port"),
    5432:  ("PostgreSQL",       "Postgres database — database exposure"),
    5900:  ("VNC",              "Remote desktop — often no auth"),
    6379:  ("Redis",            "Redis database — NO AUTH by default — CRITICAL"),
    8080:  ("HTTP-Alt",         "Alternative web / proxy"),
    8443:  ("HTTPS-Alt",        "Alternative HTTPS"),
    8888:  ("Jupyter/Alt HTTP", "Jupyter notebook — code execution if unprotected"),
    9200:  ("Elasticsearch",    "ElasticSearch — NO AUTH by default — CRITICAL"),
    27017: ("MongoDB",          "MongoDB — NO AUTH by default — CRITICAL"),
    # Minecraft
    25565: ("Minecraft Java",   "Minecraft Java Edition server"),
    25575: ("MC RCON",          "Minecraft remote console — full server control"),
    19565: ("MC Bedrock Alt",   "Minecraft Bedrock alternate"),
}

UDP_PORTS = {
    53:    ("DNS",              "DNS — check for amplification attack potential"),
    67:    ("DHCP",             "DHCP server"),
    69:    ("TFTP",             "Trivial FTP — no auth, file read/write"),
    123:   ("NTP",              "NTP — check for amplification"),
    137:   ("NetBIOS-NS",       "NetBIOS name service"),
    161:   ("SNMP",             "SNMP — community string leaks — MEDIUM RISK"),
    500:   ("IKE/VPN",          "VPN key exchange"),
    1194:  ("OpenVPN",          "OpenVPN"),
    1900:  ("SSDP",             "UPnP discovery — amplification risk"),
    4500:  ("IKE-NAT",          "VPN NAT traversal"),
    5353:  ("mDNS",             "Multicast DNS — local discovery"),
    19132: ("Minecraft Bedrock","Minecraft Bedrock Edition server"),
}

# ── Vulnerability risk levels ─────────────────────────────────────
VULN_MAP = {
    23:    ("CRITICAL", "Telnet sends all data including passwords in cleartext"),
    6379:  ("CRITICAL", "Redis has NO authentication by default — full database access"),
    9200:  ("CRITICAL", "Elasticsearch has NO authentication by default — all data exposed"),
    27017: ("CRITICAL", "MongoDB has NO authentication by default — full database access"),
    445:   ("HIGH",     "SMB — EternalBlue (MS17-010) if unpatched; also ransomware vector"),
    3389:  ("HIGH",     "RDP — BlueKeep, DejaBlue CVEs; brute-force target"),
    4444:  ("HIGH",     "Default Metasploit listener — likely active C2 or leftover backdoor"),
    5900:  ("HIGH",     "VNC — often configured with no or weak password"),
    21:    ("MEDIUM",   "FTP — credentials transmitted in cleartext; check for anonymous login"),
    3306:  ("MEDIUM",   "MySQL exposed publicly — should be localhost only"),
    5432:  ("MEDIUM",   "PostgreSQL exposed publicly — should be localhost only"),
    1433:  ("MEDIUM",   "MSSQL exposed publicly — brute-force / injection target"),
    8888:  ("MEDIUM",   "Jupyter Notebook — may allow unauthenticated code execution"),
    25575: ("MEDIUM",   "Minecraft RCON — full server control; ensure strong password"),
    25:    ("LOW",      "SMTP — check if open relay is configured"),
    69:    ("LOW",      "TFTP — no authentication, can read/write files"),
    161:   ("LOW",      "SNMP v1/v2 — community string 'public' leaks config data"),
    1900:  ("LOW",      "SSDP/UPnP — amplification attack source"),
}

VULN_COLORS = {
    "CRITICAL": "bold bright_red",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "yellow",
}

# ── Banner ────────────────────────────────────────────────────────
def banner():
    console.clear()
    fig = pyfiglet.figlet_format("VOID SCAN", font="doom")
    shades = ["bright_red","red","bright_red","red","bright_red","red","bright_red","red"]
    txt = Text()
    for i, line in enumerate(fig.splitlines()):
        txt.append(line + "\n", style=shades[i % len(shades)])
    console.print(Align.center(txt))

    sub = Text()
    sub.append("  ◈ ", style="bright_red")
    sub.append("PORT SCANNER  —  TCP · UDP · MINECRAFT · VULNS", style="bold bright_white")
    sub.append(" ◈  ", style="bright_red")
    console.print(Align.center(sub))

    tags = Text()
    for label, sep in [
        ("Multi-threaded", " | "), ("Banner Grabbing", " | "),
        ("UDP Probe", " | "), ("Risk Scoring", ""),
    ]:
        tags.append(label, style="bright_red")
        if sep:
            tags.append(sep, style="dim red")
    console.print(Align.center(tags))
    console.print(Align.center(
        Text("by @lfw.k4rma_  ·  Authorized use only\n", style="dim red")))
    console.print(Rule(style="bright_red"))


# ── TCP scan one port ─────────────────────────────────────────────
def tcp_scan(host: str, port: int, timeout: float = 1.5) -> dict | None:
    """Returns result dict if open, None if closed/filtered."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.perf_counter()
        rc = s.connect_ex((host, port))
        rtt = (time.perf_counter() - t0) * 1000

        if rc != 0:
            s.close()
            return None

        # Banner grab
        banner_data = ""
        try:
            s.settimeout(1.5)
            # For HTTP, send a minimal request
            if port in (80, 8080, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            elif port == 443:
                pass  # skip — needs TLS
            raw = s.recv(256)
            banner_data = raw.decode("utf-8", errors="replace").strip()[:100]
        except Exception:
            pass
        s.close()

        # Minecraft Java — try status ping
        mc_info = None
        if port == 25565:
            mc_info = mc_java_status(host, port)

        return {
            "port":    port,
            "proto":   "TCP",
            "service": TCP_PORTS.get(port, ("Unknown", ""))[0],
            "desc":    TCP_PORTS.get(port, ("", ""))[1],
            "rtt":     round(rtt, 1),
            "banner":  banner_data,
            "mc_info": mc_info,
        }
    except Exception:
        return None


# ── UDP probe ─────────────────────────────────────────────────────
def udp_probe(host: str, port: int, timeout: float = 2.0) -> dict | None:
    """
    UDP is connectionless — we can't truly confirm open without
    an application-layer response. We send a probe and check for ICMP unreachable.
    'open|filtered' = no ICMP back. 'closed' = ICMP port unreachable.
    """
    try:
        # Probe payload by port
        probes = {
            53:    b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",   # DNS
            123:   b"\x1b" + b"\x00" * 47,                                  # NTP
            161:   b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19",          # SNMP
            1900:  b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                   b"MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n",
            19132: b"\x01" + b"\x00" * 7 + b"\xff" * 8,                    # MC Bedrock unconnected ping
        }
        payload = probes.get(port, b"\x00" * 4)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(payload, (host, port))

        try:
            data, _ = s.recvfrom(512)
            s.close()
            response = data[:80].decode("utf-8", errors="replace").strip()

            # Minecraft Bedrock — check response magic
            mc_info = None
            if port == 19132 and len(data) > 20:
                try:
                    # PONG packet: 0x1c + timestamp(8) + server GUID(8) + magic(16) + server ID string
                    if data[0] == 0x1c:
                        str_start = 35
                        str_len   = struct.unpack(">H", data[33:35])[0]
                        mc_str    = data[str_start:str_start + str_len].decode("utf-8", errors="replace")
                        parts     = mc_str.split(";")
                        mc_info   = {
                            "edition":  parts[0] if len(parts) > 0 else "Bedrock",
                            "motd":     parts[1] if len(parts) > 1 else "",
                            "version":  parts[3] if len(parts) > 3 else "",
                            "players":  parts[4] if len(parts) > 4 else "?",
                            "max":      parts[5] if len(parts) > 5 else "?",
                        }
                except Exception:
                    pass

            return {
                "port":     port,
                "proto":    "UDP",
                "service":  UDP_PORTS.get(port, ("Unknown", ""))[0],
                "desc":     UDP_PORTS.get(port, ("", ""))[1],
                "state":    "open",
                "response": response[:80],
                "mc_info":  mc_info,
            }
        except socket.timeout:
            s.close()
            # No ICMP unreachable received = open|filtered
            return {
                "port":     port,
                "proto":    "UDP",
                "service":  UDP_PORTS.get(port, ("Unknown", ""))[0],
                "desc":     UDP_PORTS.get(port, ("", ""))[1],
                "state":    "open|filtered",
                "response": "",
                "mc_info":  None,
            }
    except Exception:
        return None


# ── Minecraft Java status ─────────────────────────────────────────
def mc_java_status(host: str, port: int = 25565, timeout: float = 4.0) -> dict | None:
    import json as _json, struct as _struct
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))

        def pack_vi(val):
            out = b""
            while True:
                b = val & 0x7F; val >>= 7
                if val > 0: b |= 0x80
                out += bytes([b])
                if val == 0: break
            return out

        host_b = host.encode("utf-8")
        hs = (pack_vi(0x00) + pack_vi(760) + pack_vi(len(host_b)) + host_b
              + _struct.pack(">H", port) + pack_vi(1))
        s.sendall(pack_vi(len(hs)) + hs)
        s.sendall(b"\x01\x00")

        def read_vi(sk):
            r = sh = 0
            while True:
                b = sk.recv(1)
                if not b: return 0
                byte = b[0]; r |= (byte & 0x7F) << sh
                if not (byte & 0x80): break
                sh += 7
            return r

        read_vi(s); read_vi(s); sl = read_vi(s)
        raw = b""
        while len(raw) < sl:
            c = s.recv(sl - len(raw))
            if not c: break
            raw += c
        s.close()

        d = _json.loads(raw.decode())
        desc = d.get("description", {})
        motd = (desc.get("text","") if isinstance(desc, dict) else str(desc))
        motd = re.sub(r"§.", "", motd).strip()
        pl   = d.get("players", {})
        ver  = d.get("version", {})
        return {
            "version": ver.get("name","?"),
            "motd":    motd,
            "players": pl.get("online", 0),
            "max":     pl.get("max", 0),
        }
    except Exception:
        return None


# ── Custom port range input ───────────────────────────────────────
def parse_port_range(raw: str) -> list[int]:
    """Parse '80,443,8000-8100' → list of ints."""
    ports = []
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                ports.extend(range(int(a), int(b) + 1))
            except ValueError:
                pass
        elif part.isdigit():
            ports.append(int(part))
    return [p for p in sorted(set(ports)) if 1 <= p <= 65535]


# ── Main ──────────────────────────────────────────────────────────
def main():
    banner()
    console.print()

    # ── Input ─────────────────────────────────────────────────────
    console.print("  [bright_red]◈[/]  ", end="")
    host = input("Target IP, hostname, or URL (https://site.com): ").strip()
    if not host:
        console.print("  [red][!] No target entered.[/]"); return
    # Strip protocol/path so URLs work: https://google.com/path → google.com
    import re as _re
    host = _re.sub(r'^https?://', '', host).split('/')[0].split(':')[0].strip()

    try:
        resolved = socket.gethostbyname(host)
        if resolved != host:
            console.print(f"  [dim]Resolved:[/]  [bold yellow]{resolved}[/]")
    except Exception:
        console.print(f"  [bold red][!][/]  Cannot resolve: [yellow]{host}[/]"); return

    console.print()
    console.print("  [dim]Scan mode:[/]")
    console.print("  [bright_red][1][/]  Quick — common ports only")
    console.print("  [bright_red][2][/]  Full  — all known ports + UDP")
    console.print("  [bright_red][3][/]  Custom port range  (e.g. 1-1024 or 80,443,8080)")
    console.print()
    console.print("  [bright_red]◈[/]  ", end="")
    mode = input("Mode [1/2/3]: ").strip()

    tcp_targets = list(TCP_PORTS.keys())
    udp_targets = list(UDP_PORTS.keys())
    scan_udp    = True

    if mode == "3":
        console.print("  [bright_red]◈[/]  ", end="")
        raw_range  = input("Port range / list: ").strip()
        tcp_targets = parse_port_range(raw_range)
        udp_targets = []
        scan_udp    = False
    elif mode == "1":
        tcp_targets = [21,22,23,25,53,80,110,135,139,143,443,445,
                       3306,3389,5900,6379,8080,8443,9200,27017,25565,25575,19132]
        scan_udp    = False

    THREADS = 100
    tcp_open : list[dict] = []
    udp_open : list[dict] = []

    console.print()
    console.print(Rule("[dim red]  SCANNING  [/]", style="dim red"))
    console.print()

    # ── TCP scan ──────────────────────────────────────────────────
    with Progress(
        SpinnerColumn(spinner_name="dots", style="bright_red"),
        TextColumn("[bright_red]{task.description}[/]"),
        BarColumn(bar_width=30, style="red", complete_style="bright_red"),
        TaskProgressColumn(),
        console=console,
    ) as prog:
        task = prog.add_task(f"TCP scanning {len(tcp_targets)} ports…", total=len(tcp_targets))
        with ThreadPoolExecutor(max_workers=THREADS) as ex:
            futures = {ex.submit(tcp_scan, resolved, p): p for p in tcp_targets}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    tcp_open.append(result)
                prog.advance(task)

    # ── UDP scan ──────────────────────────────────────────────────
    if scan_udp:
        with Progress(
            SpinnerColumn(spinner_name="dots", style="bright_red"),
            TextColumn("[bright_red]{task.description}[/]"),
            BarColumn(bar_width=30, style="red", complete_style="bright_red"),
            TaskProgressColumn(),
            console=console,
        ) as prog:
            task = prog.add_task(f"UDP probing {len(udp_targets)} ports…", total=len(udp_targets))
            with ThreadPoolExecutor(max_workers=30) as ex:
                futures = {ex.submit(udp_probe, resolved, p): p for p in udp_targets}
                for fut in as_completed(futures):
                    result = fut.result()
                    if result:
                        udp_open.append(result)
                    prog.advance(task)

    # ── Sort results ──────────────────────────────────────────────
    tcp_open.sort(key=lambda x: x["port"])
    udp_open.sort(key=lambda x: x["port"])

    console.print()
    console.print(Rule("[bold bright_red]  RESULTS  [/]", style="bright_red"))
    console.print()
    console.print(f"  [dim]Target  [/]  [bold white]{host}[/]  [dim]({resolved})[/]")
    console.print(f"  [dim]Scanned [/]  [white]{len(tcp_targets)} TCP[/]"
                  + (f"  [dim]+[/]  [white]{len(udp_targets)} UDP[/]" if scan_udp else ""))
    console.print(f"  [dim]Open    [/]  [bold bright_green]{len(tcp_open)} TCP[/]"
                  + (f"  [dim]+[/]  [bold yellow]{len(udp_open)} UDP[/]" if scan_udp else ""))
    console.print()

    # ── TCP results table ─────────────────────────────────────────
    if tcp_open:
        tbl = Table(box=box.SIMPLE_HEAVY, border_style="bright_red",
                    header_style="bold white", expand=True)
        tbl.add_column("PORT",    width=7,  style="bold yellow")
        tbl.add_column("SERVICE", width=18, style="bold white")
        tbl.add_column("RTT",     width=9,  style="dim white")
        tbl.add_column("BANNER / INFO", style="dim white")

        for r in tcp_open:
            rtt_s  = f"{r['rtt']:.0f} ms"
            info   = r["banner"] or r["desc"] or ""
            if r.get("mc_info"):
                mc = r["mc_info"]
                info = (f"[bold bright_green]ONLINE[/] {mc['version']}  "
                        f"{mc['players']}/{mc['max']} players  {mc['motd']}")
            tbl.add_row(str(r["port"]), r["service"], rtt_s, info)
        console.print(tbl)
    else:
        console.print("  [dim]No TCP ports found open.[/]")

    # ── UDP results table ─────────────────────────────────────────
    if udp_open:
        console.print()
        console.print(Rule("[dim red]  UDP  [/]", style="dim red"))
        console.print()
        tbl2 = Table(box=box.SIMPLE_HEAVY, border_style="red",
                     header_style="bold white", expand=True)
        tbl2.add_column("PORT",    width=7,  style="bold yellow")
        tbl2.add_column("SERVICE", width=18, style="bold white")
        tbl2.add_column("STATE",   width=16, style="dim white")
        tbl2.add_column("INFO",    style="dim white")

        for r in udp_open:
            state_col = "bright_green" if r["state"] == "open" else "yellow"
            info = r.get("response", "") or r["desc"] or ""
            if r.get("mc_info"):
                mc = r["mc_info"]
                info = (f"[bold bright_green]BEDROCK ONLINE[/]  {mc.get('version','')}  "
                        f"{mc.get('players','?')}/{mc.get('max','?')} players  "
                        f"{re.sub(chr(167)+'.','',mc.get('motd',''))}")
            tbl2.add_row(str(r["port"]), r["service"],
                         f"[{state_col}]{r['state']}[/]", info)
        console.print(tbl2)

    # ── Vulnerability report ──────────────────────────────────────
    all_open_ports = {r["port"] for r in tcp_open} | {r["port"] for r in udp_open}
    vulns = [(p, *VULN_MAP[p]) for p in all_open_ports if p in VULN_MAP]
    vulns.sort(key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x[1]))

    if vulns:
        console.print()
        console.print(Rule("[bold bright_red]  VULNERABILITY FLAGS  [/]", style="bright_red"))
        console.print()

        crit_count  = sum(1 for v in vulns if v[1] == "CRITICAL")
        high_count  = sum(1 for v in vulns if v[1] == "HIGH")
        med_count   = sum(1 for v in vulns if v[1] == "MEDIUM")
        low_count   = sum(1 for v in vulns if v[1] == "LOW")

        console.print(f"  [bold bright_red]CRITICAL: {crit_count}[/]  "
                      f"[bold red]HIGH: {high_count}[/]  "
                      f"[bold yellow]MEDIUM: {med_count}[/]  "
                      f"[yellow]LOW: {low_count}[/]")
        console.print()

        for port, level, detail in vulns:
            col   = VULN_COLORS.get(level, "white")
            svc   = TCP_PORTS.get(port, UDP_PORTS.get(port, ("?","")))[0]
            console.print(f"  [{col}][{level}][/]  [bold white]Port {port}[/]  "
                          f"[dim]({svc})[/]")
            console.print(f"           [dim]{detail}[/]")
            console.print()
    else:
        console.print()
        console.print("  [bold bright_green]◈  No known high-risk ports detected.[/]")

    console.print(Rule(style="bright_red"))
    console.print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n  [yellow]Scan stopped.[/]\n")
    except Exception as exc:
        console.print(f"\n  [bold red][!] Error:[/]  [red]{exc}[/]\n")
