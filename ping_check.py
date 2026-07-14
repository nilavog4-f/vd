#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
# ##  VOID Ping & Stability Monitor
# ##  ** TCP ping · packet loss · DDoS detection · Minecraft **
# ##  WSL / Kali Linux Edition  ·  @lfw.k4rma_
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

import socket, time, threading, struct, re, json
from datetime import datetime
from collections import deque

from rich.console  import Console
from rich.text     import Text
from rich.align    import Align
from rich.rule     import Rule
from rich.table    import Table
from rich.live     import Live
from rich.panel    import Panel
from rich          import box
import pyfiglet

console    = Console()
stop_event = threading.Event()

# ── MC Minecraft protocol constants ───────────────────────────────
MC_JAVA_PORT    = 25565
MC_BEDROCK_PORT = 19132

# ── Banner ────────────────────────────────────────────────────────
def banner():
    console.clear()
    fig = pyfiglet.figlet_format("VOID PING", font="doom")
    shades = ["bright_red","red","bright_red","red","bright_red","red","bright_red","red"]
    txt = Text()
    for i, line in enumerate(fig.splitlines()):
        txt.append(line + "\n", style=shades[i % len(shades)])
    console.print(Align.center(txt))

    sub = Text()
    sub.append("  ◈ ", style="bright_red")
    sub.append("SERVER PING & STABILITY MONITOR", style="bold bright_white")
    sub.append(" ◈  ", style="bright_red")
    console.print(Align.center(sub))

    tags = Text()
    for label, sep in [
        ("TCP Ping", " | "), ("Packet Loss", " | "),
        ("DDoS Detection", " | "), ("Minecraft", ""),
    ]:
        tags.append(label, style="bright_red")
        if sep:
            tags.append(sep, style="dim red")
    console.print(Align.center(tags))
    console.print(Align.center(
        Text("by @lfw.k4rma_  ·  WSL / Kali Linux Edition\n", style="dim red")))
    console.print(Rule(style="bright_red"))


# ── TCP connect ping ──────────────────────────────────────────────
def tcp_ping(host: str, port: int, timeout: float = 3.0) -> float | None:
    """Returns RTT in ms, or None on failure."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.perf_counter()
        s.connect((host, port))
        rtt = (time.perf_counter() - t0) * 1000
        s.close()
        return round(rtt, 2)
    except Exception:
        return None


# ── Minecraft Java Edition status ping ───────────────────────────
def mc_java_ping(host: str, port: int = MC_JAVA_PORT, timeout: float = 5.0) -> dict | None:
    """
    Sends a Minecraft Java status ping and returns parsed server info.
    Returns dict with keys: version, description, players_online, players_max, latency
    or None on failure.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.perf_counter()
        s.connect((host, port))

        # Build handshake packet
        def pack_varint(val):
            out = b""
            while True:
                b = val & 0x7F
                val >>= 7
                if val > 0:
                    b |= 0x80
                out += bytes([b])
                if val == 0:
                    break
            return out

        host_b    = host.encode("utf-8")
        host_len  = pack_varint(len(host_b))
        port_b    = struct.pack(">H", port)
        handshake = (pack_varint(0x00)          # packet id
                   + pack_varint(760)            # protocol version (1.19+)
                   + host_len + host_b           # host string
                   + port_b                      # port
                   + pack_varint(1))             # next state = status
        handshake = pack_varint(len(handshake)) + handshake
        s.sendall(handshake)

        # Status request
        s.sendall(b"\x01\x00")

        # Read response
        def read_varint(sock):
            result = shift = 0
            while True:
                b = sock.recv(1)
                if not b:
                    return 0
                byte = b[0]
                result |= (byte & 0x7F) << shift
                if not (byte & 0x80):
                    break
                shift += 7
            return result

        _pkt_len = read_varint(s)
        _pkt_id  = read_varint(s)
        str_len  = read_varint(s)

        raw = b""
        while len(raw) < str_len:
            chunk = s.recv(str_len - len(raw))
            if not chunk:
                break
            raw += chunk

        latency = (time.perf_counter() - t0) * 1000
        s.close()

        data = json.loads(raw.decode("utf-8"))
        desc = data.get("description", {})
        if isinstance(desc, dict):
            description = desc.get("text", "")
        else:
            description = str(desc)

        players = data.get("players", {})
        version = data.get("version", {})

        return {
            "version":        version.get("name", "Unknown"),
            "description":    description,
            "players_online": players.get("online", 0),
            "players_max":    players.get("max", 0),
            "latency":        round(latency, 2),
        }
    except Exception:
        return None


# ── Stability assessment ──────────────────────────────────────────
def assess(rtts: list, timeouts: int, total: int) -> tuple[str, str]:
    """
    Returns (status_label, color).
    Logic mirrors what network admins look for:
    - Sudden huge RTT spikes = flood causing queuing
    - High loss = packets being dropped (overwhelmed server/router)
    """
    if total == 0:
        return "WAITING…", "dim white"

    loss_pct = (timeouts / total) * 100
    valid    = [r for r in rtts if r is not None]

    if not valid:
        if loss_pct >= 80:
            return "⚠  SERVER DOWN / UNREACHABLE", "bold bright_red"
        return "⚠  HIGH LOSS — POSSIBLE ATTACK", "bold bright_red"

    avg = sum(valid) / len(valid)
    mn  = min(valid)
    mx  = max(valid)
    jitter = mx - mn

    # DDoS detection heuristics
    # 1. Severe loss (> 40%) = packets being dropped
    # 2. Extreme jitter (>500ms swing) = flood causing queue spikes
    # 3. RTT avg very high (>800ms) with jitter
    if loss_pct >= 60:
        return "🔴  LIKELY UNDER ATTACK — HIGH LOSS", "bold bright_red"
    if loss_pct >= 40 and jitter > 300:
        return "🔴  POSSIBLE DDOS — LOSS + SPIKE DETECTED", "bold bright_red"
    if jitter > 500 and avg > 400:
        return "🟠  UNSTABLE — SEVERE JITTER (POSSIBLE FLOOD)", "bold yellow"
    if loss_pct >= 20:
        return "🟠  UNSTABLE — NOTABLE PACKET LOSS", "bold yellow"
    if jitter > 200 or avg > 200:
        return "🟡  DEGRADED — HIGH LATENCY / JITTER", "yellow"
    if avg <= 80 and loss_pct < 5:
        return "🟢  GOOD — STABLE CONNECTION", "bold bright_green"
    return "🟢  ACCEPTABLE", "bright_green"


# ── Build live display panel ──────────────────────────────────────
def build_display(host: str, port: int, rtts: deque, timeouts: int,
                  total: int, history: list, is_mc: bool, mc_info: dict | None) -> Panel:
    valid  = [r for r in rtts if r is not None]
    loss   = (timeouts / total * 100) if total else 0.0
    avg    = sum(valid) / len(valid) if valid else 0.0
    mn     = min(valid) if valid else 0.0
    mx     = max(valid) if valid else 0.0
    jitter = mx - mn

    status_label, status_color = assess(list(rtts), timeouts, total)

    # RTT sparkline (last 40 pings, visual bar)
    spark = ""
    bars  = " ▁▂▃▄▅▆▇█"
    for r in history[-40:]:
        if r is None:
            spark += "[bold red]✗[/]"
        else:
            # map 0–500ms to bar levels
            idx = min(int(r / 60), 8)
            col = ("bright_green" if r < 80 else
                   "yellow"       if r < 200 else
                   "bright_red")
            spark += f"[{col}]{bars[idx]}[/]"

    lines = []
    lines.append(f"  [dim]Host[/]    [bold white]{host}[/]  [dim]:[/]  [bold yellow]{port}[/]")
    lines.append(f"  [dim]Time[/]    [dim]{datetime.now().strftime('%H:%M:%S')}[/]")
    lines.append("")
    lines.append(f"  [{status_color}]{status_label}[/]")
    lines.append("")
    lines.append(f"  [dim]Pings[/]   [white]{total}[/]   [dim]Loss[/]  "
                 f"[{'bright_red' if loss > 10 else 'bright_green'}]{loss:.1f}%[/]   "
                 f"[dim]Timeouts[/]  [white]{timeouts}[/]")
    lines.append(f"  [dim]Avg RTT[/] [bold white]{avg:.1f} ms[/]   "
                 f"[dim]Min[/] [bright_green]{mn:.1f}[/]   "
                 f"[dim]Max[/] [bright_red]{mx:.1f}[/]   "
                 f"[dim]Jitter[/] [yellow]{jitter:.1f} ms[/]")
    lines.append("")
    lines.append(f"  {spark}")

    if is_mc and mc_info:
        lines.append("")
        lines.append(f"  [bold bright_green]MINECRAFT[/]  [dim]{mc_info['version']}[/]  "
                     f"[white]{mc_info['players_online']}/{mc_info['players_max']} players[/]")
        if mc_info.get("description"):
            motd = re.sub(r"§.", "", mc_info["description"])[:60]
            lines.append(f"  [dim]MOTD[/]  [white]{motd}[/]")

    lines.append("")
    lines.append("  [dim]Ctrl+C to stop[/]")

    content = "\n".join(lines)
    return Panel(content, title="[bold bright_red]  VOID PING MONITOR  [/]",
                 border_style="bright_red", box=box.DOUBLE)


# ── Main ──────────────────────────────────────────────────────────
def main():
    banner()
    console.print()

    # ── Input ─────────────────────────────────────────────────────
    console.print("  [bright_red]◈[/]  ", end="")
    host = input("Target IP, hostname or URL (e.g. google.com): ").strip()
    if not host:
        console.print("  [red][!] No target entered.[/]"); return

    # Strip protocol/path from URLs so "https://site.com" works too
    host = re.sub(r"^(https?://)|(/.*)$", "", host, flags=re.IGNORECASE).strip()

    # Resolve hostname
    try:
        resolved = socket.gethostbyname(host)
        if resolved != host:
            console.print(f"  [dim]Resolved:[/]  [bold yellow]{host}[/] → [bright_white]{resolved}[/]")
    except Exception:
        console.print(f"  [bold red][!][/]  Cannot resolve: [yellow]{host}[/]")
        return

    console.print("  [bright_red]◈[/]  ", end="")
    raw_port = input("Port (default 80 for websites, 443 HTTPS, 25565 Minecraft): ").strip()
    if raw_port.lower() in ("https", "ssl"):
        port = 443
    elif raw_port.isdigit():
        port = int(raw_port)
    else:
        port = 80

    # Detect Minecraft
    is_mc = port in (MC_JAVA_PORT, MC_BEDROCK_PORT)
    if is_mc:
        console.print(f"  [bold bright_green]●[/]  Minecraft port detected — will fetch server status")

    console.print()
    console.print(Rule("[dim red]  STARTING MONITOR  [/]", style="dim red"))
    console.print()

    rtts     : deque  = deque(maxlen=60)
    history  : list   = []
    timeouts : int    = 0
    total    : int    = 0
    mc_info  : dict | None = None

    # Fetch MC info once upfront
    if is_mc and port == MC_JAVA_PORT:
        mc_info = mc_java_ping(host, port)

    try:
        with Live(console=console, refresh_per_second=4, screen=False) as live:
            while not stop_event.is_set():
                rtt = tcp_ping(resolved, port)
                total += 1
                if rtt is None:
                    timeouts += 1
                rtts.append(rtt)
                history.append(rtt)

                # Refresh MC info every 30 pings if Minecraft
                if is_mc and port == MC_JAVA_PORT and total % 30 == 0:
                    new_info = mc_java_ping(host, port)
                    if new_info:
                        mc_info = new_info

                panel = build_display(host, port, rtts, timeouts, total, history, is_mc, mc_info)
                live.update(panel)
                time.sleep(1.0)

    except KeyboardInterrupt:
        pass

    # ── Final summary ──────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold bright_red]  FINAL SUMMARY  [/]", style="bright_red"))
    console.print()

    valid  = [r for r in history if r is not None]
    loss   = (timeouts / total * 100) if total else 0.0
    avg    = sum(valid) / len(valid) if valid else 0.0
    mn     = min(valid) if valid else 0.0
    mx     = max(valid) if valid else 0.0

    status_label, status_color = assess(history, timeouts, total)

    console.print(f"  [dim]Target      [/]  [bold white]{host}:{port}[/]")
    console.print(f"  [dim]Total pings [/]  [white]{total}[/]")
    console.print(f"  [dim]Packet loss [/]  [{'bright_red' if loss > 10 else 'bright_green'}]{loss:.1f}%[/]")
    console.print(f"  [dim]Avg RTT     [/]  [white]{avg:.1f} ms[/]")
    console.print(f"  [dim]Min RTT     [/]  [bright_green]{mn:.1f} ms[/]")
    console.print(f"  [dim]Max RTT     [/]  [bright_red]{mx:.1f} ms[/]")
    console.print(f"  [dim]Jitter      [/]  [yellow]{mx - mn:.1f} ms[/]")
    console.print()
    console.print(f"  [{status_color}]{status_label}[/]")
    console.print()

    if "ATTACK" in status_label or "DDOS" in status_label or "FLOOD" in status_label:
        console.print("  [bold bright_red]⚠  RECOMMENDATION:[/]  "
                      "[white]Consider closing the server / enabling DDoS protection[/]")
        console.print("    [dim]• High loss + jitter spike = classic volumetric flood signature[/]")
        console.print("    [dim]• Close the port or enable rate limiting immediately[/]")
    console.print()
    console.print(Rule(style="bright_red"))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        console.print(f"\n  [bold red][!] Error:[/]  [red]{exc}[/]\n")
