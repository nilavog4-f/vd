import subprocess, sys, os

def _ensure_deps():
    pkgs = ["requests", "rich", "pyfiglet", "ddgs"]
    for pkg in pkgs:
        mod = pkg.replace("-","_")
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

import json, re, time, requests, concurrent.futures, threading, hashlib
from datetime import datetime
from ddgs import DDGS

_ddg_lock = threading.Lock()   # prevent parallel DDG calls from killing each other
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich.columns import Columns
from rich.live import Live
from rich import box
import pyfiglet

console = Console()

CONFIG_FILE = "osint_config.json"
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f: return json.load(f)
    cfg = {"api_key": "", "model": "openai/gpt-4o-mini"}
    with open(CONFIG_FILE, "w") as _f: _f.write(json.dumps(cfg, indent=2))
    return cfg

config  = load_config()
# Prefer the env var (Replit Secrets) over the plaintext config file.
API_KEY = os.environ.get("OPENROUTER_API_KEY", "").strip() or config.get("api_key","")
MODEL   = config.get("model","openai/gpt-4o-mini")
OPENROUTER = "https://openrouter.ai/api/v1/chat/completions"

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
SESS = requests.Session()
SESS.headers.update({"User-Agent": UA})

USERNAME_SITES = [
    # Social
    ("Twitter/X",       "https://twitter.com/{}"),
    ("Instagram",       "https://instagram.com/{}"),
    ("TikTok",          "https://tiktok.com/@{}"),
    ("Snapchat",        "https://snapchat.com/add/{}"),
    ("Pinterest",       "https://pinterest.com/{}"),
    ("Tumblr",          "https://{}.tumblr.com"),
    ("Reddit",          "https://reddit.com/user/{}"),
    ("Telegram",        "https://t.me/{}"),
    ("Facebook",        "https://facebook.com/{}"),
    ("Linktree",        "https://linktr.ee/{}"),
    ("About.me",        "https://about.me/{}"),
    ("Mastodon",        "https://mastodon.social/@{}"),
    ("Bluesky",         "https://bsky.app/profile/{}.bsky.social"),
    ("Threads",         "https://www.threads.net/@{}"),
    # Gaming
    ("Steam",           "https://steamcommunity.com/id/{}"),
    ("Roblox",          "https://roblox.com/user.aspx?username={}"),
    ("Xbox",            "https://xboxgamertag.com/search/{}"),
    ("PSN",             "https://psnprofiles.com/{}"),
    ("Twitch",          "https://twitch.tv/{}"),
    ("Kick",            "https://kick.com/{}"),
    ("Minecraft",       "https://namemc.com/profile/{}"),
    ("Epic Games",      "https://fortnitetracker.com/profile/all/{}"),
    ("Valorant",        "https://tracker.gg/valorant/profile/riot/{}/overview"),
    ("Chess.com",       "https://chess.com/member/{}"),
    ("Faceit",          "https://faceit.com/en/players/{}"),
    ("Battlenet",       "https://overwatch.blizzard.com/en-us/career/pc/{}/"),
    ("Palia",           "https://palia.com/profile/{}"),
    ("Fortnite",        "https://fortnitetracker.com/profile/all/{}"),
    # Streaming / Entertainment
    ("YouTube",         "https://youtube.com/@{}"),
    ("Spotify",         "https://open.spotify.com/user/{}"),
    ("SoundCloud",      "https://soundcloud.com/{}"),
    ("Vimeo",           "https://vimeo.com/{}"),
    ("Dailymotion",     "https://dailymotion.com/{}"),
    ("Mixcloud",        "https://mixcloud.com/{}"),
    ("Bandcamp",        "https://{}.bandcamp.com"),
    ("Last.fm",         "https://last.fm/user/{}"),
    ("Letterboxd",      "https://letterboxd.com/{}"),
    # Creative / Art
    ("DeviantArt",      "https://deviantart.com/{}"),
    ("Behance",         "https://behance.net/{}"),
    ("Dribbble",        "https://dribbble.com/{}"),
    ("ArtStation",      "https://artstation.com/{}"),
    ("Wattpad",         "https://wattpad.com/user/{}"),
    ("Redbubble",       "https://redbubble.com/people/{}"),
    # Dev / Tech
    ("GitHub",          "https://github.com/{}"),
    ("GitLab",          "https://gitlab.com/{}"),
    ("Bitbucket",       "https://bitbucket.org/{}"),
    ("Replit",          "https://replit.com/@{}"),
    ("Codepen",         "https://codepen.io/{}"),
    ("HackerRank",      "https://hackerrank.com/{}"),
    ("LeetCode",        "https://leetcode.com/{}"),
    ("Kaggle",          "https://kaggle.com/{}"),
    ("NPM",             "https://npmjs.com/~{}"),
    ("DockerHub",       "https://hub.docker.com/u/{}"),
    ("Keybase",         "https://keybase.io/{}"),
    ("HackerNews",      "https://news.ycombinator.com/user?id={}"),
    ("ProductHunt",     "https://producthunt.com/@{}"),
    # Creator Economy
    ("Patreon",         "https://patreon.com/{}"),
    ("Medium",          "https://medium.com/@{}"),
    ("Substack",        "https://substack.com/@{}"),
    ("Ko-fi",           "https://ko-fi.com/{}"),
    ("Fiverr",          "https://fiverr.com/{}"),
    ("Etsy",            "https://etsy.com/shop/{}"),
    ("Ebay",            "https://ebay.com/usr/{}"),
    ("Cashapp",         "https://cash.app/${}"),
    ("Venmo",           "https://venmo.com/{}"),
    # Q&A / Forums
    ("Quora",           "https://quora.com/profile/{}"),
    ("StackOverflow",   "https://stackoverflow.com/users/{}"),
    ("Disqus",          "https://disqus.com/by/{}"),
    ("Minds",           "https://minds.com/{}"),
    ("Gab",             "https://gab.com/{}"),
    # Other
    ("Gravatar",        "https://gravatar.com/{}"),
    ("Flickr",          "https://flickr.com/people/{}"),
    ("VK",              "https://vk.com/{}"),
    ("Weibo",           "https://weibo.com/{}"),
    ("MySpace",         "https://myspace.com/{}"),
    ("Ask.fm",          "https://ask.fm/{}"),
    ("Amino",           "https://aminoapps.com/u/{}"),
    ("VSCO",            "https://vsco.co/{}"),
    ("Goodreads",       "https://goodreads.com/{}"),
]

def username_variations(username: str) -> list:
    """Generate plausible username variants to try if the original yields nothing."""
    seen = []
    def add(v):
        v = v.strip()
        if v and v != username and v not in seen:
            seen.append(v)

    # strip trailing/leading punctuation
    stripped = username.rstrip("._-")
    add(stripped)
    add(username.lstrip("._-"))
    add(username.strip("._-"))

    # remove dots
    add(username.replace(".", ""))
    # remove underscores
    add(username.replace("_", ""))
    # dots → underscores
    add(username.replace(".", "_"))
    # underscores → dots
    add(username.replace("_", "."))
    # remove all non-alnum
    import re as _re
    add(_re.sub(r"[^a-zA-Z0-9]", "", username))
    # lowercase
    add(username.lower())
    add(stripped.lower())

    return seen

def banner():
    console.clear()
    fig = pyfiglet.figlet_format("VOID  OSINT", font="doom")
    colors = ["bright_magenta","magenta","bright_cyan","cyan","bright_blue","blue","bright_magenta","magenta","bright_cyan"]
    styled = Text()
    for i, line in enumerate(fig.splitlines()):
        styled.append(line + "\n", style=colors[i % len(colors)])
    console.print(Align.center(styled))

    subtitle = Text()
    subtitle.append("  ◈ ", style="bright_magenta")
    subtitle.append("OPEN SOURCE INTELLIGENCE FRAMEWORK", style="bold bright_white")
    subtitle.append(" v2.0 ◈  ", style="bright_magenta")
    console.print(Align.center(subtitle))

    tags = Text()
    tags.append("  [ ", style="dim magenta")
    tags.append("Multi-Engine", style="bright_cyan")
    tags.append(" | ", style="dim magenta")
    tags.append("AI-Powered", style="bright_magenta")
    tags.append(" | ", style="dim magenta")
    tags.append("50+ Platforms", style="bright_cyan")
    tags.append(" | ", style="dim magenta")
    tags.append("Breach Intel", style="bright_magenta")
    tags.append(" ]  ", style="dim magenta")
    console.print(Align.center(tags))
    console.print(Align.center(Text("by @lfw.k4rma_\n", style="dim cyan")))
    console.print(Rule(style="bright_magenta"))

def detect_input_type(value: str) -> str:
    value = value.strip()
    if re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', value): return "email"
    if re.match(r'^\+?[\d\s\-\(\)]{7,15}$', value): return "phone"
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', value): return "ip"
    if value.startswith("@"): return "username"
    if " " in value: return "full_name"
    return "username"

def parse_free_input(text: str) -> dict:
    target = {}
    tokens = [t.strip() for t in re.split(r'[\n,;|]+', text) if t.strip()]
    for token in tokens:
        kind = detect_input_type(token)
        if kind == "email" and "email" not in target:
            target["email"] = token
        elif kind == "phone" and "phone" not in target:
            target["phone"] = token
        elif kind == "ip" and "ip" not in target:
            target["ip"] = token
        elif kind == "username" and "username" not in target:
            target["username"] = token.lstrip("@")
        elif kind == "full_name" and "full_name" not in target:
            target["full_name"] = token
        elif "full_name" not in target:
            target["full_name"] = token
    return target

def ddg_search(query: str, n: int = 8) -> list:
    for attempt in range(3):
        try:
            with _ddg_lock:
                time.sleep(0.4 * attempt)
            with DDGS() as d:
                results = list(d.text(query, max_results=n))
            if results:
                return results
            time.sleep(0.6)
        except Exception:
            time.sleep(1.2 * (attempt + 1))
    return []

def bing_search(query: str, n: int = 8) -> list:
    try:
        hdrs = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        r = requests.get("https://www.bing.com/search",
                         params={"q": query, "count": n}, headers=hdrs, timeout=9)
        seen, results = set(), []
        blocks = re.findall(r'<li[^>]*class="[^"]*b_algo[^"]*"[^>]*>(.*?)</li>', r.text, re.DOTALL)
        for block in blocks[:n]:
            url_m   = re.search(r'<a[^>]+href="(https?://[^"]+)"', block)
            title_m = re.search(r'<a[^>]+>(.*?)</a>', block, re.DOTALL)
            body_m  = re.search(r'<p[^>]*>(.*?)</p>', block, re.DOTALL)
            url   = url_m.group(1)  if url_m   else ""
            title = re.sub(r'<[^>]+>', '', title_m.group(1)).strip() if title_m else ""
            body  = re.sub(r'<[^>]+>', '', body_m.group(1)).strip()  if body_m  else ""
            if url and url not in seen and "bing.com" not in url and "microsoft.com" not in url:
                results.append({"href": url, "title": title or url[:80], "body": body[:250]})
                seen.add(url)
        return results
    except Exception: return []

def google_search(query: str, n: int = 8) -> list:
    try:
        hdrs = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml",
        }
        r = requests.get("https://www.google.com/search",
                         params={"q": query, "num": n, "hl": "en"}, headers=hdrs, timeout=9)
        seen, results = set(), []
        raw_urls = re.findall(r'/url\?q=(https?://[^&"]+)', r.text)
        raw_titles = [re.sub(r'<[^>]+>', '', t).strip()
                      for t in re.findall(r'<h3[^>]*>(.*?)</h3>', r.text, re.DOTALL)]
        raw_bodies = [re.sub(r'<[^>]+>', '', s).strip()
                      for s in re.findall(r'class="[^"]*(?:VwiC3b|IsZvec|yDYNvb)[^"]*"[^>]*>(.*?)</div>',
                                          r.text, re.DOTALL)]
        for i, url in enumerate(raw_urls):
            url = requests.utils.unquote(url)
            if url not in seen and "google.com" not in url and "webcache" not in url:
                title = raw_titles[i] if i < len(raw_titles) else url[:80]
                body  = raw_bodies[i] if i < len(raw_bodies) else ""
                results.append({"href": url, "title": title, "body": body[:250]})
                seen.add(url)
                if len(results) >= n: break
        return results
    except Exception: return []

def multi_search(query: str) -> list:
    seen, combined = set(), []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futs = {ex.submit(f, query, 5): f for f in [ddg_search, bing_search, google_search]}
        for fut in concurrent.futures.as_completed(futs):
            for r in (fut.result() or []):
                url = r.get("href","")
                if url and url not in seen:
                    combined.append(r); seen.add(url)
    return combined

# Strings that mean "user not found" on each platform — if any match, skip it
PLATFORM_NOT_FOUND = {
    "GitHub":       ["not found","this is not the web page","404"],
    "Reddit":       ["nobody on reddit goes by","page not found","sorry, that community","user doesn't exist"],
    "Steam":        ["the specified profile could not be found","error","no users"],
    "Roblox":       ["user not found","page not found","404"],
    "Twitter/X":    ["this account doesn't exist","account suspended","caution: this account"],
    "Instagram":    ["sorry, this page isn't available","page not found","isn't available"],
    "TikTok":       ["couldn't find this account","user not found"],
    "Twitch":       ["sorry. unless you've been living under a rock","page not found","404"],
    "Snapchat":     ["this snapchat account doesn't exist","not found"],
    "Pinterest":    ["sorry! we couldn't find that page","page not found"],
    "YouTube":      ["this channel doesn't exist","404","this page isn't available"],
    "Kick":         ["page not found","user not found","404"],
    "Chess.com":    ["page not found","user not found","this page doesn't exist"],
    "Valorant":     ["player not found","no player found","we couldn't find"],
    "PSN":          ["profile not found","no results found"],
    "Minecraft":    ["profile not found","user not found"],
    "Faceit":       ["player not found","page not found"],
    "Medium":       ["page not found","this page doesn't exist","404"],
    "Linktree":     ["page not found","this linktree doesn't exist"],
    "Substack":     ["there is no substack","page not found"],
    "Letterboxd":   ["we can't find the page","page not found"],
    "Last.fm":      ["user not found","page not found"],
    "Goodreads":    ["page not found","we can't find the page"],
    "Replit":       ["not found","page not found"],
    "Kaggle":       ["page not found","user not found"],
    "Quora":        ["page not found","we couldn't find that"],
    "ArtStation":   ["user not found","page not found"],
    "Wattpad":      ["page not found","user not found"],
}

def _platform_found(platform: str, username: str, text: str, status: int) -> bool:
    """Return True only if we're confident the profile exists."""
    if status == 404:
        return False
    if status != 200:
        return False
    tl = text.lower()
    usl = username.lower()
    # Check NOT_FOUND phrases first
    for phrase in PLATFORM_NOT_FOUND.get(platform, []):
        if phrase.lower() in tl:
            return False
    # Must actually contain the username somewhere meaningful
    if usl not in tl:
        return False
    return True

def check_username(args):
    """Try original username then all variations. Returns (platform, url, matched_variant, is_original, found)."""
    platform, tpl, username = args
    all_attempts = [username] + username_variations(username)
    for attempt in all_attempts:
        url = tpl.format(attempt)
        try:
            r = SESS.get(url, timeout=5, allow_redirects=True)
            if _platform_found(platform, attempt, r.text, r.status_code):
                return (platform, url, attempt, attempt == username, True)
        except Exception:
            pass
    return (platform, tpl.format(username), username, True, False)

def ip_lookup(ip: str) -> dict:
    try:
        r = SESS.get(f"https://ipapi.co/{ip}/json/", timeout=6)
        return r.json()
    except Exception: return {}

def hibp_check(email: str) -> list:
    try:
        r = SESS.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(email)}",
                     headers={"hibp-api-key": "none"}, timeout=6)
        return r.json() if r.status_code == 200 else []
    except Exception: return []

def leakcheck(email: str) -> dict:
    try:
        r = SESS.get(f"https://leakcheck.io/api/public?check={email}", timeout=6)
        return r.json() if r.status_code == 200 else {}
    except Exception: return {}

def gravatar_lookup(email: str) -> dict:
    """Check Gravatar for profile image, real name, bio, location, and linked social accounts."""
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    out = {
        "exists": False, "hash": h,
        "avatar": f"https://www.gravatar.com/avatar/{h}?s=200",
        "profile_url": f"https://gravatar.com/{h}",
        "display_name": "", "real_name": "", "bio": "",
        "location": "", "urls": [], "accounts": []
    }
    try:
        r = SESS.get(f"https://www.gravatar.com/avatar/{h}?d=404", timeout=7)
        out["exists"] = (r.status_code == 200)
    except Exception: pass
    if out["exists"]:
        try:
            r2 = SESS.get(f"https://www.gravatar.com/{h}.json", timeout=7)
            if r2.status_code == 200:
                e = r2.json().get("entry", [{}])[0]
                out["display_name"] = e.get("displayName", "")
                out["real_name"]    = (e.get("name") or {}).get("formatted", "")
                out["bio"]          = e.get("aboutMe", "")
                out["location"]     = e.get("currentLocation", "")
                out["urls"]         = [u.get("value","") for u in (e.get("urls") or [])]
                out["accounts"]     = [
                    {"domain": a.get("domain",""), "display": a.get("display",""), "url": a.get("url","")}
                    for a in (e.get("accounts") or [])
                ]
        except Exception: pass
    return out

def google_account_check(email: str) -> dict:
    """Check whether a Google account exists for this email address."""
    result = {"exists": None, "detail": ""}
    try:
        # Primary method: Gmail GXLU endpoint — sets GMAIL_AT cookie if account exists
        r = requests.get(
            "https://mail.google.com/mail/gxlu",
            params={"email": email},
            headers={"User-Agent": UA},
            allow_redirects=False, timeout=8
        )
        if "GMAIL_AT" in r.cookies or r.status_code == 204:
            result["exists"] = True
            result["detail"] = "Active Gmail/Google account confirmed via GXLU check"
            return result
    except Exception: pass
    try:
        # Fallback: Google sign-in identifier step
        r2 = requests.post(
            "https://accounts.google.com/signin/v2/identifier",
            data={"Email": email, "signIn": "Sign in", "flowName": "GlifWebSignIn"},
            headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=False, timeout=8
        )
        loc = r2.headers.get("Location", "")
        if "password" in loc or "challenge" in loc or "pwdless" in loc:
            result["exists"] = True
            result["detail"] = "Google account confirmed (reached password/challenge step)"
        elif "lookup" in loc or "notenrolled" in loc:
            result["exists"] = False
            result["detail"] = "No Google account found for this email"
        else:
            result["detail"] = "Inconclusive — Google may have blocked automated check"
    except Exception as ex:
        result["detail"] = f"Check error: {ex}"
    return result

def facebook_account_check(email: str) -> dict:
    """Check whether a Facebook account is linked to this email via the recover flow."""
    result = {"exists": None, "detail": ""}
    try:
        s = requests.Session()
        s.headers.update({"User-Agent": UA,
                           "Accept": "text/html,application/xhtml+xml",
                           "Accept-Language": "en-US,en;q=0.9"})
        # Load the recover page first to get LSD token
        r = s.get("https://www.facebook.com/login/identify/",
                  params={"ctx": "recover"}, timeout=9)
        lsd_m = re.search(r'"LSD",\[\],\{"token":"([^"]+)"\}', r.text) or \
                re.search(r'name="lsd"\s+value="([^"]+)"', r.text)
        lsd = lsd_m.group(1) if lsd_m else ""
        # Submit the email to find the account
        r2 = s.post(
            "https://www.facebook.com/login/identify/",
            data={"email": email, "did_submit": 1, "lsd": lsd,
                  "action": "Search", "ctx": "recover"},
            headers={"Referer": "https://www.facebook.com/login/identify/?ctx=recover",
                     "Origin": "https://www.facebook.com"},
            timeout=9, allow_redirects=True
        )
        t = r2.text.lower()
        if any(x in t for x in ["your account", "we found", "confirm your identity",
                                  "reset your password", "reset password"]):
            result["exists"] = True
            result["detail"] = "Facebook account found linked to this email"
        elif any(x in t for x in ["no facebook account", "couldn't find", "not found",
                                    "no account", "couldn't find your account"]):
            result["exists"] = False
            result["detail"] = "No Facebook account linked to this email"
        else:
            result["detail"] = "Inconclusive — Facebook may have blocked the automated check"
    except Exception as ex:
        result["detail"] = f"Check error: {ex}"
    return result

def github_email_leak(username: str) -> dict:
    """Pull real name, email(s), company, bio, and location from GitHub public API + commit history."""
    result = {
        "found": False, "profile_url": "",
        "name": "", "company": "", "blog": "",
        "location": "", "bio": "", "twitter": "",
        "public_repos": 0, "followers": 0, "following": 0,
        "created_at": "", "emails": [], "repos": []
    }
    try:
        r = SESS.get(f"https://api.github.com/users/{username}", timeout=9,
                     headers={"Accept": "application/vnd.github.v3+json"})
        if r.status_code == 200:
            u = r.json()
            result["found"]        = True
            result["profile_url"]  = u.get("html_url", "")
            result["name"]         = u.get("name", "") or ""
            result["company"]      = u.get("company", "") or ""
            result["blog"]         = u.get("blog", "") or ""
            result["location"]     = u.get("location", "") or ""
            result["bio"]          = u.get("bio", "") or ""
            result["twitter"]      = u.get("twitter_username", "") or ""
            result["public_repos"] = u.get("public_repos", 0)
            result["followers"]    = u.get("followers", 0)
            result["following"]    = u.get("following", 0)
            result["created_at"]   = u.get("created_at", "")
            if u.get("email"):
                result["emails"].append(u["email"])
    except Exception: pass
    if not result["found"]:
        return result
    # Mine commit history for leaked email addresses
    try:
        r2 = SESS.get(f"https://api.github.com/users/{username}/events/public",
                      timeout=9, headers={"Accept": "application/vnd.github.v3+json"})
        if r2.status_code == 200:
            seen_emails = set(result["emails"])
            for event in r2.json():
                if event.get("type") == "PushEvent":
                    for commit in event.get("payload", {}).get("commits", []):
                        author = commit.get("author", {})
                        em = author.get("email", "")
                        nm = author.get("name", "")
                        if em and "noreply.github.com" not in em and em not in seen_emails:
                            seen_emails.add(em)
                            result["emails"].append(em)
                        if nm and not result["name"]:
                            result["name"] = nm
    except Exception: pass
    # Grab top repos for context
    try:
        r3 = SESS.get(f"https://api.github.com/users/{username}/repos",
                      params={"sort": "updated", "per_page": 6}, timeout=9,
                      headers={"Accept": "application/vnd.github.v3+json"})
        if r3.status_code == 200:
            result["repos"] = [
                {"name": rp.get("name",""), "description": rp.get("description","") or "",
                 "url": rp.get("html_url",""), "stars": rp.get("stargazers_count",0),
                 "language": rp.get("language","") or ""}
                for rp in r3.json()
            ]
    except Exception: pass
    return result

def build_queries(target: dict) -> list:
    name = target.get("full_name","")
    email = target.get("email","")
    username = target.get("username","")
    phone = target.get("phone","")
    city = target.get("city","")
    q = []
    if name:
        q += [
            (f'"{name}" site:linkedin.com OR site:facebook.com OR site:twitter.com', "Social Profiles"),
            (f'"{name}" password OR credentials OR leaked OR breach', "Credential Leaks"),
            (f'"{name}" site:pastebin.com OR site:ghostbin.com', "Paste Sites"),
            (f'"{name}" doxxed OR dox OR exposed', "Dox Results"),
            (f'"{name}" address OR phone OR email', "Contact Info"),
            (f'intitle:"{name}" profile OR account', "Profile Pages"),
        ]
        if city: q.append((f'"{name}" "{city}"', "Location Match"))
    if email:
        q += [
            (f'"{email}" site:pastebin.com OR site:ghostbin.com', "Email on Paste Sites"),
            (f'"{email}" leak OR dump OR breach', "Email Breach Search"),
            (f'"{email}" password', "Email + Password"),
        ]
    if username:
        q += [
            (f'"{username}" site:reddit.com OR site:twitter.com OR site:github.com', "Username Socials"),
            (f'"{username}" leaked OR doxxed', "Username Exposure"),
            (f'site:pastebin.com "{username}"', "Username on Pastebin"),
        ]
    if phone:
        q += [
            (f'"{phone}"', "Phone Number"),
            (f'"{phone}" name OR address', "Phone Owner Lookup"),
        ]
    return q

def ai_analyze(data: dict) -> str:
    if not API_KEY:
        return "AI analysis unavailable — add your OpenRouter key to osint_config.json"
    target   = data["target"]
    breaches = data.get("breach_data", [])
    lc       = data.get("email_leaks",{}).get("leakcheck",{})
    platforms= [p for p,*_ in data.get("username_platforms",[])]
    web_cats = list(data["web_results"].keys())
    total_w  = sum(len(v) for v in data["web_results"].values())

    breach_detail = []
    for b in breaches:
        breach_detail.append({
            "name": b.get("Name"),
            "date": b.get("BreachDate"),
            "records": b.get("PwnCount"),
            "data_types": b.get("DataClasses",[]),
            "passwords_leaked": b.get("IsPwnedPassword", False),
            "sensitive": b.get("IsSensitive", False),
        })

    gravatar = data.get("gravatar", {})
    gcheck   = data.get("google_check", {})
    fbcheck  = data.get("facebook_check", {})
    github   = data.get("github_intel", {})

    prompt = f"""You are VOID, an elite cybersecurity OSINT analyst with 15 years of experience.
Perform a full threat intelligence report on this target. Be sharp, specific, and professional.

TARGET:
{json.dumps(target, indent=2)}

BREACH DATA ({len(breaches)} breaches):
{json.dumps(breach_detail, indent=2)}

LEAKCHECK SOURCES: {lc.get('found', 0)} found
ACTIVE PLATFORMS: {platforms}
WEB SEARCH CATEGORIES HIT: {web_cats}
TOTAL WEB RESULTS: {total_w}

GRAVATAR: {"EXISTS — name: " + (gravatar.get("real_name") or gravatar.get("display_name","")) + ", location: " + gravatar.get("location","") + ", linked accounts: " + str(len(gravatar.get("accounts",[]))) if gravatar.get("exists") else "No profile found"}
GOOGLE ACCOUNT: {"CONFIRMED — " + gcheck.get("detail","") if gcheck.get("exists") is True else ("NOT FOUND" if gcheck.get("exists") is False else "Inconclusive")}
FACEBOOK ACCOUNT: {"CONFIRMED" if fbcheck.get("exists") is True else ("NOT FOUND" if fbcheck.get("exists") is False else "Inconclusive")}
GITHUB: {"FOUND — name: " + github.get("name","") + ", location: " + github.get("location","") + ", leaked emails: " + str(github.get("emails",[])) + ", company: " + github.get("company","") if github.get("found") else "No GitHub profile found"}

Write the report using EXACTLY this structure:

**RISK LEVEL:** [CRITICAL / HIGH / MEDIUM / LOW] — explain in one sentence why

**EXECUTIVE SUMMARY**
3-4 sentences covering the overall exposure picture.

**KEY FINDINGS**
- List every significant finding with specifics (breach names, platform names, data types, record counts)
- Be specific — name the breaches, name the platforms, reference the data types
- Flag if passwords, financial data, or physical addresses were exposed

**WHAT AN ATTACKER CAN DO**
Step-by-step realistic attack chain using the found data. Be specific to this target's exposure.

**CRITICAL VULNERABILITIES**
- List the most dangerous specific exposures found

**IMMEDIATE ACTION PLAN**
1. First thing to do right now
2-5. Other specific, actionable steps (not generic advice — reference the actual leaks found)

**LONG-TERM HARDENING**
3-4 longer-term recommendations specific to this exposure profile.

Be direct, technical, and reference actual data found. Max 500 words."""

    try:
        r = requests.post(OPENROUTER,
            headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json",
                     "HTTP-Referer": "https://osint.local", "X-Title": "VOID OSINT"},
            json={"model": MODEL, "messages": [{"role":"user","content":prompt}],
                  "temperature": 0.3}, timeout=40)
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"AI failed: {e}"

def run_search(target: dict) -> dict:
    results = {
        "target": target, "web_results": {}, "username_platforms": [],
        "breach_data": [], "email_leaks": {}, "ip_data": {}, "ai_analysis": "",
        "gravatar": {}, "google_check": {}, "facebook_check": {}, "github_intel": {}
    }

    queries = build_queries(target)
    # total steps: web queries + username + hibp + leak + ip + gravatar + google + facebook + github + ai
    extra = sum([
        1,                                     # username
        bool(target.get("email")) * 5,         # hibp + leak + gravatar + google + facebook
        bool(target.get("ip")),                # ip
        bool(target.get("username")) * 1,      # github
        1                                      # ai
    ])
    total_steps = len(queries) + extra

    with Progress(
        SpinnerColumn(spinner_name="dots12", style="bright_magenta"),
        TextColumn("[bright_cyan]{task.description:<48}"),
        BarColumn(bar_width=20, style="magenta", complete_style="bright_magenta"),
        TextColumn("[dim white]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console, transient=True
    ) as prog:
        task = prog.add_task("Initializing...", total=total_steps)

        # ── Web searches ──────────────────────────────────────────────────
        prog.update(task, description="[bright_cyan]⟳  Running web searches (3 engines)...")
        def search_one(args):
            query, label = args
            return label, multi_search(query)

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            for label, hits in ex.map(search_one, queries):
                if hits:
                    results["web_results"][label] = hits
                prog.advance(task)
                time.sleep(0.05)

        # ── Parallel intel checks ─────────────────────────────────────────
        futures = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            if target.get("username"):
                prog.update(task, description=f"[bright_cyan]⟳  Scanning {len(USERNAME_SITES)} platforms...")
                args = [(p, u, target["username"]) for p, u in USERNAME_SITES]
                futures["username"] = ex.submit(lambda a: list(ex.map(check_username, a)), args)
                futures["github"]   = ex.submit(github_email_leak, target["username"])

            if target.get("email"):
                prog.update(task, description="[bright_cyan]⟳  Running breach + account checks...")
                futures["hibp"]     = ex.submit(hibp_check,             target["email"])
                futures["leak"]     = ex.submit(leakcheck,              target["email"])
                futures["gravatar"] = ex.submit(gravatar_lookup,        target["email"])
                futures["google"]   = ex.submit(google_account_check,   target["email"])
                futures["facebook"] = ex.submit(facebook_account_check, target["email"])

            if target.get("ip"):
                futures["ip"] = ex.submit(ip_lookup, target["ip"])

            concurrent.futures.wait(futures.values())

        if "username" in futures:
            results["username_platforms"] = [
                (p, url, variant, is_orig)
                for p, url, variant, is_orig, ok in futures["username"].result() if ok
            ]
            prog.advance(task)

        if "github" in futures:
            results["github_intel"] = futures["github"].result()
            prog.advance(task)

        if "hibp" in futures:
            results["breach_data"] = futures["hibp"].result()
            prog.advance(task)

        if "leak" in futures:
            results["email_leaks"] = {"leakcheck": futures["leak"].result()}
            prog.advance(task)

        if "gravatar" in futures:
            results["gravatar"] = futures["gravatar"].result()
            prog.advance(task)

        if "google" in futures:
            results["google_check"] = futures["google"].result()
            prog.advance(task)

        if "facebook" in futures:
            results["facebook_check"] = futures["facebook"].result()
            prog.advance(task)

        if "ip" in futures:
            results["ip_data"] = futures["ip"].result()
            prog.advance(task)

        prog.update(task, description="[bright_cyan]⟳  AI threat analysis...")
        results["ai_analysis"] = ai_analyze(results)
        prog.advance(task)

    return results

def stat_panel(label: str, value: str, color: str) -> Panel:
    return Panel(
        Align.center(Text(value, style=f"bold {color}")),
        title=f"[dim]{label}[/dim]",
        border_style=color,
        padding=(0, 2),
        width=20
    )

def build_html_report(data: dict) -> str:
    target    = data["target"]
    breaches  = data.get("breach_data", [])
    lc        = data.get("email_leaks",{}).get("leakcheck",{})
    lc_srcs   = lc.get("sources", []) if lc else []
    platforms = data.get("username_platforms", [])
    ip_data   = data.get("ip_data", {})
    web       = data.get("web_results", {})
    ai_text   = data.get("ai_analysis", "")
    duration  = data.get("scan_duration", "?")
    gravatar  = data.get("gravatar", {})
    gcheck    = data.get("google_check", {})
    fbcheck   = data.get("facebook_check", {})
    github    = data.get("github_intel", {})
    ts        = datetime.now().strftime("%B %d, %Y — %H:%M:%S")
    total_hits = sum(len(v) for v in web.values())

    def esc(s):
        return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

    def badge(text, color="#a855f7"):
        return f'<span class="badge" style="background:{color}">{esc(text)}</span>'

    def card(title, content, accent="#a855f7"):
        return f'''<div class="card" style="border-left:3px solid {accent}">
  <div class="card-title" style="color:{accent}">{esc(title)}</div>
  {content}
</div>'''

    # ── Key Findings block ────────────────────────────────────────────────
    findings = []
    if platforms:
        findings.append(("✔", f"{len(platforms)} PLATFORM ACCOUNT{'S' if len(platforms)!=1 else ''} FOUND", "#22c55e"))
    if breaches:
        findings.append(("⚠", f"EMAIL IN {len(breaches)} KNOWN BREACH{'ES' if len(breaches)!=1 else ''}", "#ef4444"))
    if lc_srcs:
        findings.append(("⚠", f"LEAKCHECK: {len(lc_srcs)} SOURCE{'S' if len(lc_srcs)!=1 else ''}", "#ef4444"))
    if gravatar.get("exists"):
        grav_name = gravatar.get("real_name") or gravatar.get("display_name") or ""
        grav_loc  = gravatar.get("location","")
        grav_accs = len(gravatar.get("accounts",[]))
        detail = " | ".join(filter(None, [grav_name, grav_loc, f"{grav_accs} linked accounts" if grav_accs else ""]))
        findings.append(("✔", f"GRAVATAR PROFILE EXISTS" + (f" — {detail}" if detail else ""), "#22c55e"))
    if gcheck.get("exists") is True:
        findings.append(("✔", f"GOOGLE ACCOUNT CONFIRMED — {gcheck.get('detail','')}", "#22c55e"))
    elif gcheck.get("exists") is False:
        findings.append(("✘", f"NO GOOGLE ACCOUNT — {gcheck.get('detail','')}", "#64748b"))
    if fbcheck.get("exists") is True:
        findings.append(("✔", "FACEBOOK ACCOUNT FOUND FOR THIS EMAIL", "#22c55e"))
    elif fbcheck.get("exists") is False:
        findings.append(("✘", "NO FACEBOOK ACCOUNT LINKED TO THIS EMAIL", "#64748b"))
    if github.get("found"):
        gh_emails = github.get("emails",[])
        gh_name   = github.get("name","")
        detail = " | ".join(filter(None, [gh_name, f"{len(gh_emails)} email(s) leaked" if gh_emails else ""]))
        findings.append(("✔", f"GITHUB PROFILE FOUND" + (f" — {detail}" if detail else ""), "#22c55e"))
    if total_hits:
        findings.append(("◈", f"{total_hits} WEB RESULTS ACROSS {len(web)} CATEGORIES", "#22d3ee"))
    if ip_data and not ip_data.get("error") and ip_data.get("city"):
        findings.append(("◈", f"IP LOCATION: {ip_data.get('city','')}, {ip_data.get('country_name','')} — {ip_data.get('org','')}", "#a855f7"))
    if not findings:
        findings.append(("—", "No significant findings — try adding more target details", "#64748b"))

    findings_html = '<div class="findings-grid">'
    for icon, text, color in findings:
        findings_html += f'<div class="finding-card" style="border-left:4px solid {color}"><span class="finding-icon" style="color:{color}">{icon}</span><span class="finding-text">{esc(text)}</span></div>'
    findings_html += '</div>'
    key_findings_html = f'<section class="key-findings"><h2 class="sec-title purple">◈ KEY FINDINGS</h2>{findings_html}</section>'

    # ── Gravatar section ──────────────────────────────────────────────────
    gravatar_html = ""
    if gravatar:
        rows = ""
        if gravatar.get("exists"):
            rows += f'<tr><td class="label">STATUS</td><td><span class="found">✔ PROFILE EXISTS</span></td></tr>'
            rows += f'<tr><td class="label">AVATAR</td><td><img src="{esc(gravatar["avatar"])}" style="width:80px;height:80px;border-radius:50%;border:2px solid #a855f7;margin:4px 0"></td></tr>'
            if gravatar.get("display_name"): rows += f'<tr><td class="label">DISPLAY NAME</td><td>{esc(gravatar["display_name"])}</td></tr>'
            if gravatar.get("real_name"):    rows += f'<tr><td class="label">REAL NAME</td><td><b style="color:#22c55e">{esc(gravatar["real_name"])}</b></td></tr>'
            if gravatar.get("bio"):          rows += f'<tr><td class="label">BIO</td><td>{esc(gravatar["bio"])}</td></tr>'
            if gravatar.get("location"):     rows += f'<tr><td class="label">LOCATION</td><td>{esc(gravatar["location"])}</td></tr>'
            if gravatar.get("urls"):
                url_links = "<br>".join(
                    '<a href="' + esc(u) + '" target="_blank">' + esc(u) + '</a>'
                    for u in gravatar["urls"]
                )
                rows += f'<tr><td class="label">LINKED URLS</td><td>{url_links}</td></tr>'
            if gravatar.get("accounts"):
                acc_html = "".join(
                    f'<span style="display:inline-block;margin:2px 4px;padding:2px 8px;background:#1e1b4b;border:1px solid #a855f7;border-radius:4px;font-size:11px">'
                    f'<a href="{esc(a["url"])}" target="_blank" style="color:#c4b5fd">{esc(a["display"] or a["domain"])}</a></span>'
                    for a in gravatar["accounts"] if a.get("url")
                )
                rows += f'<tr><td class="label">LINKED ACCOUNTS</td><td>{acc_html}</td></tr>'
            rows += f'<tr><td class="label">PROFILE URL</td><td><a href="{esc(gravatar["profile_url"])}" target="_blank">{esc(gravatar["profile_url"])}</a></td></tr>'
        else:
            rows = '<tr><td colspan="2" style="color:#64748b">No Gravatar profile linked to this email address.</td></tr>'
        gravatar_html = f'<section><h2 class="sec-title purple">◈ GRAVATAR PROFILE</h2><table class="info-table">{rows}</table></section>'

    # ── Account existence section ─────────────────────────────────────────
    acct_rows = ""
    if gcheck:
        icon  = "✔ YES" if gcheck.get("exists") is True else ("✘ NO" if gcheck.get("exists") is False else "? UNKNOWN")
        color = "#22c55e" if gcheck.get("exists") is True else ("#ef4444" if gcheck.get("exists") is False else "#f59e0b")
        acct_rows += f'<tr><td class="label">GOOGLE ACCOUNT</td><td><span style="color:{color};font-weight:bold">{icon}</span> &nbsp; <span style="color:#94a3b8">{esc(gcheck.get("detail",""))}</span></td></tr>'
    if fbcheck:
        icon  = "✔ YES" if fbcheck.get("exists") is True else ("✘ NO" if fbcheck.get("exists") is False else "? UNKNOWN")
        color = "#22c55e" if fbcheck.get("exists") is True else ("#ef4444" if fbcheck.get("exists") is False else "#f59e0b")
        acct_rows += f'<tr><td class="label">FACEBOOK ACCOUNT</td><td><span style="color:{color};font-weight:bold">{icon}</span> &nbsp; <span style="color:#94a3b8">{esc(fbcheck.get("detail",""))}</span></td></tr>'
    account_check_html = ""
    if acct_rows:
        account_check_html = f'<section><h2 class="sec-title purple">◈ ACCOUNT EXISTENCE CHECKS</h2><table class="info-table">{acct_rows}</table></section>'

    # ── GitHub intel section ──────────────────────────────────────────────
    github_html = ""
    if github and github.get("found"):
        gh_rows = ""
        gh_rows += f'<tr><td class="label">PROFILE</td><td><a href="{esc(github["profile_url"])}" target="_blank">{esc(github["profile_url"])}</a></td></tr>'
        if github.get("name"):         gh_rows += f'<tr><td class="label">NAME</td><td><b style="color:#22c55e">{esc(github["name"])}</b></td></tr>'
        if github.get("company"):      gh_rows += f'<tr><td class="label">COMPANY</td><td>{esc(github["company"])}</td></tr>'
        if github.get("location"):     gh_rows += f'<tr><td class="label">LOCATION</td><td>{esc(github["location"])}</td></tr>'
        if github.get("bio"):          gh_rows += f'<tr><td class="label">BIO</td><td>{esc(github["bio"])}</td></tr>'
        if github.get("blog"):         gh_rows += f'<tr><td class="label">WEBSITE/BLOG</td><td><a href="{esc(github["blog"])}" target="_blank">{esc(github["blog"])}</a></td></tr>'
        if github.get("twitter"):      gh_rows += f'<tr><td class="label">TWITTER</td><td>{esc(github["twitter"])}</td></tr>'
        gh_rows += f'<tr><td class="label">PUBLIC REPOS</td><td>{github["public_repos"]}</td></tr>'
        gh_rows += f'<tr><td class="label">FOLLOWERS</td><td>{github["followers"]}</td></tr>'
        if github.get("created_at"):   gh_rows += f'<tr><td class="label">ACCOUNT CREATED</td><td>{esc(github["created_at"][:10])}</td></tr>'
        if github.get("emails"):
            email_tags = "".join(
                f'<span style="display:inline-block;margin:2px 4px;padding:3px 10px;background:#450a0a;border:1px solid #ef4444;border-radius:4px;font-size:12px;color:#fca5a5">{esc(e)}</span>'
                for e in github["emails"]
            )
            gh_rows += f'<tr><td class="label">⚠ LEAKED EMAILS</td><td>{email_tags}</td></tr>'
        if github.get("repos"):
            repo_rows = "".join(
                f'<tr><td><a href="{esc(r["url"])}" target="_blank" style="color:#818cf8">{esc(r["name"])}</a></td>'
                f'<td style="color:#94a3b8">{esc(r["description"][:80]) if r["description"] else "—"}</td>'
                f'<td style="color:#f59e0b">★ {r["stars"]}</td>'
                f'<td style="color:#67e8f9">{esc(r["language"])}</td></tr>'
                for r in github["repos"]
            )
            gh_rows += f'<tr><td class="label">REPOSITORIES</td><td><table style="width:100%;font-size:12px">{repo_rows}</table></td></tr>'
        github_html = f'<section><h2 class="sec-title purple">◈ GITHUB INTELLIGENCE</h2><div class="alert" style="background:rgba(239,68,68,0.07);border:1px solid #ef4444;margin-bottom:12px;padding:10px 14px;border-radius:6px;font-size:12px;color:#fca5a5">⚠ Email addresses above were extracted from public Git commit metadata — developers often forget these are publicly visible</div><table class="info-table">{gh_rows}</table></section>'

    # ── Target rows ──────────────────────────────────────────────────────
    target_rows = "".join(
        f'<tr><td class="label">{esc(k.replace("_"," ").upper())}</td><td>{esc(v)}</td></tr>'
        for k, v in target.items() if v
    )

    # ── Stat boxes ───────────────────────────────────────────────────────
    def stat_box(label, value, color):
        return f'<div class="stat-box" style="border-color:{color}"><div class="stat-val" style="color:{color}">{esc(str(value))}</div><div class="stat-label">{esc(label)}</div></div>'

    breach_color = "#ef4444" if breaches else "#22c55e"
    lc_color     = "#ef4444" if lc_srcs  else "#22c55e"
    stats = (
        stat_box("WEB HITS",     total_hits,           "#22d3ee") +
        stat_box("CATEGORIES",   len(web),             "#67e8f9") +
        stat_box("PLATFORMS",    len(platforms),        "#a855f7") +
        stat_box("BREACHES",     len(breaches),         breach_color) +
        stat_box("LEAK SOURCES", lc.get("found",0) if lc else 0, lc_color) +
        stat_box("SCAN TIME",    duration,              "#f59e0b")
    )

    # ── IP section ───────────────────────────────────────────────────────
    ip_html = ""
    if ip_data and not ip_data.get("error"):
        ip_fields = [("ip","IP"),("city","City"),("region","Region"),("country_name","Country"),
                     ("org","ISP / Org"),("asn","ASN"),("timezone","Timezone"),
                     ("latitude","Latitude"),("longitude","Longitude"),("postal","Postal")]
        rows = "".join(f'<tr><td class="label">{label}</td><td>{esc(str(ip_data[key]))}</td></tr>'
                       for key, label in ip_fields if ip_data.get(key))
        ip_html = f'<section><h2 class="sec-title purple">◈ IP INTELLIGENCE</h2><table class="info-table">{rows}</table></section>'

    # ── Web results ───────────────────────────────────────────────────────
    web_html = '<section><h2 class="sec-title purple">◈ WEB INTELLIGENCE</h2>'
    web_html += f'<p class="sub">{total_hits} results · {len(web)} categories · 3 search engines</p>'
    for label, hits in web.items():
        web_html += f'<div class="web-category"><h3 class="cat-title">## {esc(label)} <span class="cnt">({len(hits)})</span></h3><div class="hit-list">'
        for i, hit in enumerate(hits, 1):
            title = esc((hit.get("title") or hit.get("href","")).strip())
            url   = esc((hit.get("href") or "").strip())
            body  = esc((hit.get("body") or "").strip())
            web_html += f'''<div class="hit">
  <div class="hit-num">[{i}]</div>
  <div class="hit-content">
    <div class="hit-title">{title}</div>
    {f'<a class="hit-url" href="{url}" target="_blank">{url}</a>' if url else ''}
    {f'<div class="hit-body">{body}</div>' if body else ''}
  </div>
</div>'''
        web_html += '</div></div>'
    web_html += '</section>'

    # ── Platforms ─────────────────────────────────────────────────────────
    plat_html = f'<section><h2 class="sec-title purple">◈ ACTIVE PLATFORM ACCOUNTS</h2><p class="sub">{len(platforms)} confirmed · {len(USERNAME_SITES)} checked</p>'
    if platforms:
        plat_html += '<table class="info-table"><tr><th>#</th><th>Platform</th><th>Found As</th><th>URL</th><th>Status</th></tr>'
        for i, entry in enumerate(platforms, 1):
            p, url, variant, is_orig = entry
            variant_cell = esc(variant)
            if not is_orig:
                variant_cell = f'<span style="color:#f59e0b;font-weight:700">{esc(variant)}</span> <span style="color:#a78bfa;font-size:0.78em">(variation)</span>'
            plat_html += (
                f'<tr>'
                f'<td class="label">{i}</td>'
                f'<td><b>{esc(p)}</b></td>'
                f'<td>{variant_cell}</td>'
                f'<td><a href="{esc(url)}" target="_blank">{esc(url)}</a></td>'
                f'<td><span class="found">✔ FOUND</span></td>'
                f'</tr>'
            )
        plat_html += '</table>'
    else:
        plat_html += '<p class="none">No active accounts confirmed across all platforms.</p>'
    plat_html += '</section>'

    # ── Breaches ──────────────────────────────────────────────────────────
    breach_html = '<section><h2 class="sec-title red">◈ BREACH INTELLIGENCE</h2>'
    if breaches:
        breach_html += f'<div class="alert red-alert">⚠ EMAIL FOUND IN {len(breaches)} BREACH(ES)</div>'
        for i, b in enumerate(breaches, 1):
            pwned = b.get("IsPwnedPassword", False)
            sens  = b.get("IsSensitive", False)
            desc  = re.sub(r'<[^>]+>', '', b.get("Description","")).strip()
            badges = ""
            if pwned: badges += badge("PASSWORDS LEAKED","#ef4444")
            if sens:  badges += badge("SENSITIVE","#f59e0b")
            breach_html += f'''<div class="breach-card">
  <div class="breach-header">
    <span class="breach-name">{esc(b.get("Name","?"))}</span> {badges}
  </div>
  <table class="info-table">
    <tr><td class="label">Date</td><td>{esc(str(b.get("BreachDate","?")))}</td></tr>
    <tr><td class="label">Added</td><td>{esc(str(b.get("AddedDate","?"))[:10])}</td></tr>
    <tr><td class="label">Domain</td><td>{esc(b.get("Domain","?"))}</td></tr>
    <tr><td class="label">Records</td><td><b>{b.get("PwnCount",0):,}</b></td></tr>
    <tr><td class="label">Exposed Data</td><td>{esc(", ".join(b.get("DataClasses",[])))}</td></tr>
    {f'<tr><td class="label">Details</td><td>{esc(desc[:400])}</td></tr>' if desc else ''}
  </table>
</div>'''
    else:
        breach_html += '<div class="alert green-alert">✔ Email not found in any known public breach.</div>'

    if lc_srcs:
        breach_html += f'<div class="alert red-alert" style="margin-top:16px">⚠ LEAKCHECK: FOUND IN {len(lc_srcs)} SOURCE(S)</div>'
        breach_html += '<table class="info-table"><tr><th>#</th><th>Source</th><th>Date</th><th>Type</th></tr>'
        for i, src in enumerate(lc_srcs, 1):
            breach_html += f'<tr><td class="label">{i}</td><td>{esc(src.get("name","?"))}</td><td>{esc(src.get("date","?"))}</td><td>{esc(src.get("type","?"))}</td></tr>'
        breach_html += '</table>'
    elif target.get("email"):
        breach_html += '<div class="alert green-alert" style="margin-top:16px">✔ LeakCheck: No sources found.</div>'
    breach_html += '</section>'

    # ── AI Analysis ───────────────────────────────────────────────────────
    ai_lines = []
    for line in ai_text.splitlines():
        s = line.strip()
        if s.startswith("**RISK"):
            ai_lines.append(f'<p class="ai-risk">{esc(line)}</p>')
        elif s.startswith("**") or s.startswith("##"):
            ai_lines.append(f'<p class="ai-header">{esc(line)}</p>')
        elif s.startswith("-") or s.startswith("•"):
            ai_lines.append(f'<p class="ai-bullet">{esc(line)}</p>')
        elif s == "":
            ai_lines.append('<br>')
        else:
            ai_lines.append(f'<p class="ai-body">{esc(line)}</p>')
    ai_html = f'<section><h2 class="sec-title purple">◈ AI THREAT ANALYSIS</h2><div class="ai-box">{"".join(ai_lines)}</div></section>'

    # ── Full HTML ─────────────────────────────────────────────────────────
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VOID OSINT — {esc(target.get("full_name", target.get("email","Target")))}</title>
<style>
  :root {{
    --bg: #0a0a0f;
    --bg2: #111118;
    --bg3: #1a1a24;
    --border: #2a2a3a;
    --purple: #a855f7;
    --cyan: #22d3ee;
    --red: #ef4444;
    --green: #22c55e;
    --yellow: #f59e0b;
    --white: #f1f5f9;
    --dim: #64748b;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--white); font-family: 'Courier New', monospace; font-size: 14px; line-height: 1.6; }}
  a {{ color: var(--cyan); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  .header {{ background: linear-gradient(135deg, #0f0f1a 0%, #1a0a2e 50%, #0f0f1a 100%); padding: 48px 40px 32px; border-bottom: 1px solid var(--border); text-align: center; }}
  .header pre {{ font-size: 11px; line-height: 1.2; background: linear-gradient(180deg,#a855f7,#22d3ee,#a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; display: inline-block; }}
  .header-sub {{ color: var(--cyan); letter-spacing: 4px; font-size: 11px; margin-top: 12px; }}
  .header-meta {{ color: var(--dim); font-size: 12px; margin-top: 8px; }}

  .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px; }}

  .stats {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 32px; }}
  .stat-box {{ flex: 1; min-width: 120px; background: var(--bg2); border: 1px solid; border-radius: 8px; padding: 16px 12px; text-align: center; }}
  .stat-val {{ font-size: 28px; font-weight: bold; margin-bottom: 4px; }}
  .stat-label {{ font-size: 10px; letter-spacing: 2px; color: var(--dim); }}

  section {{ margin-bottom: 40px; }}
  .sec-title {{ font-size: 13px; letter-spacing: 3px; padding: 10px 0; margin-bottom: 16px; border-bottom: 1px solid var(--border); }}
  .sec-title.purple {{ color: var(--purple); border-color: var(--purple); }}
  .sec-title.red {{ color: var(--red); border-color: var(--red); }}
  .sub {{ color: var(--dim); font-size: 12px; margin-bottom: 16px; }}

  .info-table {{ width: 100%; border-collapse: collapse; background: var(--bg2); border-radius: 8px; overflow: hidden; }}
  .info-table th {{ background: var(--bg3); color: var(--purple); padding: 10px 14px; text-align: left; font-size: 11px; letter-spacing: 1px; border-bottom: 1px solid var(--border); }}
  .info-table td {{ padding: 9px 14px; border-bottom: 1px solid var(--border); }}
  .info-table tr:last-child td {{ border-bottom: none; }}
  .info-table tr:hover td {{ background: var(--bg3); }}
  td.label {{ color: var(--cyan); font-size: 11px; letter-spacing: 1px; width: 160px; white-space: nowrap; }}

  .web-category {{ margin-bottom: 24px; background: var(--bg2); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }}
  .cat-title {{ padding: 10px 16px; background: var(--bg3); color: var(--cyan); font-size: 12px; letter-spacing: 1px; border-bottom: 1px solid var(--border); }}
  .cnt {{ color: var(--dim); }}
  .hit-list {{ padding: 8px 0; }}
  .hit {{ display: flex; gap: 12px; padding: 10px 16px; border-bottom: 1px solid var(--border); }}
  .hit:last-child {{ border-bottom: none; }}
  .hit:hover {{ background: var(--bg3); }}
  .hit-num {{ color: var(--purple); min-width: 28px; font-size: 12px; }}
  .hit-content {{ flex: 1; min-width: 0; }}
  .hit-title {{ color: var(--white); margin-bottom: 2px; word-break: break-word; }}
  .hit-url {{ color: var(--cyan); font-size: 12px; word-break: break-all; display: block; margin-bottom: 2px; }}
  .hit-body {{ color: var(--dim); font-size: 12px; word-break: break-word; }}

  .found {{ color: var(--green); font-weight: bold; }}
  .none {{ color: var(--dim); padding: 12px 0; }}

  .alert {{ padding: 12px 18px; border-radius: 6px; font-weight: bold; margin-bottom: 16px; }}
  .red-alert {{ background: rgba(239,68,68,0.12); border: 1px solid var(--red); color: var(--red); }}
  .green-alert {{ background: rgba(34,197,94,0.1); border: 1px solid var(--green); color: var(--green); }}

  .breach-card {{ background: var(--bg2); border: 1px solid var(--red); border-radius: 8px; margin-bottom: 16px; overflow: hidden; }}
  .breach-header {{ background: rgba(239,68,68,0.08); padding: 12px 16px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
  .breach-name {{ color: var(--red); font-weight: bold; font-size: 15px; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: bold; letter-spacing: 1px; color: #fff; }}

  .ai-box {{ background: var(--bg2); border: 1px solid var(--purple); border-radius: 8px; padding: 24px 28px; }}
  .ai-risk {{ color: var(--red); font-weight: bold; font-size: 16px; margin-bottom: 12px; }}
  .ai-header {{ color: var(--cyan); font-weight: bold; margin-top: 16px; margin-bottom: 6px; }}
  .ai-bullet {{ color: var(--white); padding-left: 16px; margin-bottom: 4px; }}
  .ai-body {{ color: #cbd5e1; margin-bottom: 4px; }}

  .footer {{ text-align: center; padding: 32px; color: var(--dim); font-size: 11px; letter-spacing: 2px; border-top: 1px solid var(--border); }}

  /* ── Key Findings ────────────────────────── */
  .key-findings {{ margin-bottom: 40px; }}
  .findings-grid {{ display: flex; flex-direction: column; gap: 10px; }}
  .finding-card {{ display: flex; align-items: center; gap: 16px; background: var(--bg2); border-radius: 8px; padding: 14px 20px; border-left-width: 4px; border-left-style: solid; }}
  .finding-icon {{ font-size: 20px; flex-shrink: 0; width: 24px; text-align: center; }}
  .finding-text {{ font-size: 13px; font-weight: 700; letter-spacing: 1.5px; color: var(--white); }}
</style>
</head>
<body>
<div class="header">
  <pre>
 __   ___  _______   _______     ______        _______  _______  ___  ____  ____  ______ 
|  | /  / /  ___  | |_   _  |  |  ___ \      |  ___  ||  _____||  | |    \|    ||__  __|
|  |/  / | |   | |   | | | |  | |   \ \     | |   | || |___   |  | |  .  '  . |  |  |  
|     <  | |   | |   | | | |  | |   | |     | |   | ||___  |  |  | |  |\ /|  |  |  |  
|  |\  \ | |___| |  _| |_| |  | |___/ /     | |___| | ___| |  |  | |  | V |  |  |  |  
|__| \__\ \_____/  |_______|  |______/      |_______||_______|  |__||__| V |__|  |__|  
  </pre>
  <div class="header-sub">OPEN SOURCE INTELLIGENCE FRAMEWORK v2.0</div>
  <div class="header-meta">by @lfw.k4rma_ &nbsp;|&nbsp; Generated: {ts} &nbsp;|&nbsp; Scan Duration: {esc(duration)}</div>
</div>
<div class="container">
  <div class="stats">{stats}</div>
  {key_findings_html}

  <section>
    <h2 class="sec-title purple">◈ TARGET PROFILE</h2>
    <table class="info-table">{target_rows}</table>
  </section>

  {gravatar_html}
  {account_check_html}
  {github_html}
  {ip_html}
  {web_html}
  {plat_html}
  {breach_html}
  {ai_html}
</div>
<div class="footer">VOID OSINT v2.0 &nbsp;◈&nbsp; by @lfw.k4rma_ &nbsp;◈&nbsp; FOR AUTHORIZED USE ONLY</div>
</body>
</html>'''

def section_header(title: str, subtitle: str = ""):
    console.print()
    console.print(Rule(style="bright_magenta"))
    t = Text()
    t.append("  # ", style="bold bright_magenta")
    t.append(f"**{title}**", style="bold bright_white")
    if subtitle:
        t.append(f"  →  {subtitle}", style="dim cyan")
    console.print(t)
    console.print(Rule(style="dim magenta"))

def display_results(data: dict):
    target   = data["target"]
    breaches = data.get("breach_data", [])
    lc       = data.get("email_leaks",{}).get("leakcheck",{})
    lc_srcs  = lc.get("sources",[]) if lc else []
    lc_found = lc.get("found",0) if lc else 0
    platforms= data.get("username_platforms",[])
    ip_data  = data.get("ip_data",{})
    web      = data.get("web_results",{})
    ai_text  = data.get("ai_analysis","")
    gravatar = data.get("gravatar",{})
    gcheck   = data.get("google_check",{})
    fbcheck  = data.get("facebook_check",{})
    github   = data.get("github_intel",{})
    duration = data.get("scan_duration","?")
    total_hits = sum(len(v) for v in web.values())

    # ── Stat bar ──────────────────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold bright_magenta]  ◈ SCAN RESULTS ◈  [/bold bright_magenta]", style="bright_magenta"))
    console.print()
    stats = [
        stat_panel("WEB HITS",     str(total_hits),              "bright_cyan"),
        stat_panel("CATEGORIES",   str(len(web)),                 "cyan"),
        stat_panel("PLATFORMS",    str(len(platforms)),           "bright_magenta"),
        stat_panel("BREACHES",     str(len(breaches)),            "bright_red" if breaches else "green"),
        stat_panel("LEAK SOURCES", str(lc_found),                 "bright_red" if lc_found else "green"),
        stat_panel("DURATION",     duration,                      "bright_cyan"),
    ]
    console.print(Columns(stats, equal=True, expand=True))

    # ── KEY FINDINGS ──────────────────────────────────────────────────────
    section_header("KEY FINDINGS", "summary of all significant discoveries")
    kf = []
    if platforms:
        kf.append(("[bold green]✔[/]", f"[bold green]{len(platforms)} platform account(s) found[/]"))
    if breaches:
        kf.append(("[bold red]⚠[/]", f"[bold red]Email in {len(breaches)} known breach(es)[/]"))
    if lc_found:
        kf.append(("[bold red]⚠[/]", f"[bold red]LeakCheck: {lc_found} source(s)[/]"))
    if gravatar.get("exists"):
        nm = gravatar.get("real_name") or gravatar.get("display_name","")
        kf.append(("[bold green]✔[/]", f"[green]Gravatar profile exists{' — ' + nm if nm else ''}[/]"))
    if gcheck.get("exists") is True:
        kf.append(("[bold green]✔[/]", f"[green]Google account confirmed — {gcheck.get('detail','')}[/]"))
    elif gcheck.get("exists") is False:
        kf.append(("[dim]✘[/]", f"[dim]No Google account found[/]"))
    if fbcheck.get("exists") is True:
        kf.append(("[bold green]✔[/]", "[green]Facebook account confirmed for this email[/]"))
    elif fbcheck.get("exists") is False:
        kf.append(("[dim]✘[/]", "[dim]No Facebook account linked[/]"))
    if github.get("found"):
        em_count = len(github.get("emails",[]))
        kf.append(("[bold green]✔[/]", f"[green]GitHub: {github.get('name','') or 'profile found'}{' — ' + str(em_count) + ' email(s) leaked from commits' if em_count else ''}[/]"))
    if total_hits:
        kf.append(("[cyan]◈[/]", f"[cyan]{total_hits} web results across {len(web)} categories[/]"))
    if ip_data and not ip_data.get("error") and ip_data.get("city"):
        kf.append(("[magenta]◈[/]", f"[magenta]IP: {ip_data.get('city','')}, {ip_data.get('country_name','')} — {ip_data.get('org','')}[/]"))
    if not kf:
        kf.append(("[dim]—[/]", "[dim]No significant findings — try adding more target details[/]"))
    for icon, text in kf:
        console.print(f"  {icon}  {text}")

    # ── GRAVATAR ──────────────────────────────────────────────────────────
    if gravatar:
        section_header("GRAVATAR PROFILE", "email-linked profile image & social accounts")
        if gravatar.get("exists"):
            tbl = Table(show_header=False, box=box.SIMPLE, padding=(0,1))
            tbl.add_column("f", style="dim cyan", width=18)
            tbl.add_column("v", style="white")
            if gravatar.get("display_name"): tbl.add_row("DISPLAY NAME", gravatar["display_name"])
            if gravatar.get("real_name"):    tbl.add_row("REAL NAME",    f"[bold green]{gravatar['real_name']}[/]")
            if gravatar.get("bio"):          tbl.add_row("BIO",          gravatar["bio"][:120])
            if gravatar.get("location"):     tbl.add_row("LOCATION",     gravatar["location"])
            tbl.add_row("AVATAR",   gravatar["avatar"])
            tbl.add_row("PROFILE",  gravatar["profile_url"])
            console.print(tbl)
            if gravatar.get("accounts"):
                console.print("  [dim cyan]LINKED ACCOUNTS[/]")
                for a in gravatar["accounts"]:
                    console.print(f"    [bright_magenta]◈[/]  [white]{a.get('display') or a.get('domain','')}[/]  [dim]{a.get('url','')}[/]")
            if gravatar.get("urls"):
                console.print("  [dim cyan]LINKED URLS[/]")
                for u in gravatar["urls"]:
                    console.print(f"    [dim blue]{u}[/]")
        else:
            console.print("  [dim]No Gravatar profile linked to this email.[/dim]")

    # ── ACCOUNT EXISTENCE CHECKS ──────────────────────────────────────────
    if gcheck or fbcheck:
        section_header("ACCOUNT EXISTENCE CHECKS", "Google · Facebook")
        if gcheck:
            if gcheck.get("exists") is True:   icon = "[bold green]✔ YES[/]"
            elif gcheck.get("exists") is False: icon = "[bold red]✘ NO[/]"
            else:                               icon = "[yellow]? UNKNOWN[/]"
            console.print(f"  [dim cyan]GOOGLE   [/]  {icon}  [dim]{gcheck.get('detail','')}[/]")
        if fbcheck:
            if fbcheck.get("exists") is True:   icon = "[bold green]✔ YES[/]"
            elif fbcheck.get("exists") is False: icon = "[bold red]✘ NO[/]"
            else:                               icon = "[yellow]? UNKNOWN[/]"
            console.print(f"  [dim cyan]FACEBOOK [/]  {icon}  [dim]{fbcheck.get('detail','')}[/]")

    # ── GITHUB INTELLIGENCE ───────────────────────────────────────────────
    if github and github.get("found"):
        section_header("GITHUB INTELLIGENCE", "public profile + commit email extraction")
        tbl = Table(show_header=False, box=box.SIMPLE, padding=(0,1))
        tbl.add_column("f", style="dim cyan", width=18)
        tbl.add_column("v", style="white")
        if github.get("name"):       tbl.add_row("NAME",     f"[bold green]{github['name']}[/]")
        if github.get("company"):    tbl.add_row("COMPANY",  github["company"])
        if github.get("location"):   tbl.add_row("LOCATION", github["location"])
        if github.get("bio"):        tbl.add_row("BIO",      github["bio"][:100])
        if github.get("blog"):       tbl.add_row("BLOG",     github["blog"])
        if github.get("twitter"):    tbl.add_row("TWITTER",  f"@{github['twitter']}")
        tbl.add_row("REPOS",    str(github.get("public_repos", 0)))
        tbl.add_row("FOLLOWERS", str(github.get("followers", 0)))
        if github.get("created_at"): tbl.add_row("CREATED", github["created_at"][:10])
        tbl.add_row("PROFILE",  github.get("profile_url",""))
        console.print(tbl)
        if github.get("emails"):
            console.print("[bold red]  ⚠  EMAILS LEAKED FROM PUBLIC COMMIT HISTORY:[/bold red]")
            for em in github["emails"]:
                console.print(f"    [bright_red]◈[/]  [bold white]{em}[/]")
        if github.get("repos"):
            console.print("\n  [dim cyan]TOP REPOSITORIES[/]")
            for r in github["repos"][:5]:
                desc = (r.get("description") or "")[:70]
                console.print(f"    [bright_magenta]◈[/]  [white]{r['name']}[/]  [dim]{desc}[/]  [yellow]★{r['stars']}[/]  [cyan]{r.get('language','')}[/]")

    # ── PLATFORM ACCOUNTS ─────────────────────────────────────────────────
    if platforms:
        section_header("ACTIVE PLATFORM ACCOUNTS", f"{len(platforms)} confirmed / {len(USERNAME_SITES)} checked")
        tbl = Table(show_header=True, box=box.SIMPLE, padding=(0,1), header_style="bold bright_magenta")
        tbl.add_column("#",        width=4,  style="dim")
        tbl.add_column("Platform", width=16, style="bold white")
        tbl.add_column("Found As", width=22, style="bright_cyan")
        tbl.add_column("URL",                style="dim blue")
        for i, (p, url, variant, is_orig) in enumerate(platforms, 1):
            label = variant if is_orig else f"{variant} [dim](variation)[/]"
            tbl.add_row(str(i), p, label, url)
        console.print(tbl)
    else:
        section_header("PLATFORM ACCOUNTS", "")
        console.print("  [dim]No accounts confirmed across all platforms.[/dim]")

    # ── BREACH DATA ───────────────────────────────────────────────────────
    if breaches:
        section_header("BREACH INTELLIGENCE", f"{len(breaches)} breach(es) — HIBP")
        for b in breaches:
            name    = b.get("Name","Unknown")
            date    = b.get("BreachDate","?")
            records = f"{b.get('PwnCount',0):,}"
            types   = ", ".join(b.get("DataClasses",[]))[:140]
            pwned   = b.get("IsPwnedPassword",False)
            console.print(f"  [bold red]⚠[/]  [bold white]{name}[/]  [dim]({date}) · {records} records[/]")
            console.print(f"       [dim cyan]Data:[/dim cyan] [white]{types}[/]")
            if pwned:
                console.print("       [bold red]⚠ PASSWORDS WERE IN THIS BREACH[/bold red]")
            console.print()
    if lc_srcs:
        section_header("LEAKCHECK SOURCES", f"{lc_found} found")
        console.print(f"  [white]{', '.join(str(s) for s in lc_srcs[:20])}[/]")

    # ── IP DATA ───────────────────────────────────────────────────────────
    if ip_data and not ip_data.get("error") and ip_data.get("ip"):
        section_header("IP INTELLIGENCE", ip_data.get("ip",""))
        tbl = Table(show_header=False, box=box.SIMPLE, padding=(0,1))
        tbl.add_column("f", style="dim cyan", width=14)
        tbl.add_column("v", style="white")
        for k, label in [("ip","IP"),("city","City"),("region","Region"),("country_name","Country"),
                          ("org","ISP / Org"),("asn","ASN"),("timezone","Timezone")]:
            if ip_data.get(k):
                tbl.add_row(label, str(ip_data[k]))
        console.print(tbl)

    # ── WEB RESULTS ───────────────────────────────────────────────────────
    if web:
        section_header("WEB INTELLIGENCE", f"{total_hits} results · {len(web)} categories · 3 engines")
        for cat, hits in web.items():
            console.print(f"\n  [bold bright_cyan]## {cat}[/]  [dim]({len(hits)} results)[/]")
            for i, h in enumerate(hits[:5], 1):
                title = (h.get("title") or h.get("href",""))[:100]
                url   = h.get("href","")
                body  = (h.get("body") or "")[:120]
                console.print(f"    [dim]{i}.[/]  [white]{title}[/]")
                if url and url != title:
                    console.print(f"         [dim blue]{url}[/]")
                if body:
                    console.print(f"         [dim]{body}[/]")

    # ── AI ANALYSIS ───────────────────────────────────────────────────────
    if ai_text and "unavailable" not in ai_text.lower() and "failed" not in ai_text.lower()[:20]:
        section_header("AI THREAT ANALYSIS", "powered by OpenRouter")
        for line in ai_text.split("\n"):
            stripped = line.strip()
            if not stripped:
                console.print()
            elif stripped.startswith("## "):
                heading = stripped[3:].strip()
                console.print(f"\n  [bold bright_magenta]{'━' * 52}[/]")
                console.print(f"  [bold bright_magenta]{heading.upper()}[/]")
                console.print(f"  [bold bright_magenta]{'━' * 52}[/]")
            elif stripped.startswith("**") and stripped.endswith("**") and stripped.count("**") == 2:
                console.print(f"\n  [bold bright_magenta]{stripped.strip('*').strip()}[/]")
            elif stripped.startswith("**"):
                m = re.match(r'\*\*(.+?)\*\*[:\s]*(.*)', stripped)
                if m:
                    label, rest = m.group(1).strip(), m.group(2).strip()
                    if rest:
                        console.print(f"  [bold cyan]{label}:[/]  [white]{rest}[/]")
                    else:
                        console.print(f"\n  [bold cyan]{label}[/]")
                else:
                    console.print(f"  [bold cyan]{stripped.replace('**', '')}[/]")
            elif stripped.startswith(("- ","• ")):
                console.print(f"  [dim magenta]◈[/]  [white]{stripped[2:]}[/]")
            elif stripped and stripped[0].isdigit() and len(stripped) > 2 and stripped[1:3] in (". ",".) "):
                console.print(f"  [bright_magenta]{stripped[0]}[/][dim magenta].[/]  [white]{stripped[2:].strip()}[/]")
            else:
                console.print(f"  [dim white]{stripped}[/]")
    elif ai_text:
        section_header("AI ANALYSIS", "")
        console.print(f"  [dim]{ai_text}[/]")

    # ── Save HTML bonus ───────────────────────────────────────────────────
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = (list(target.values())[0] if target else "scan").replace(" ","_")
    fname = f"report_{slug}_{ts}.html"
    try:
        with open(fname, "w", encoding="utf-8") as f:
            f.write(build_html_report(data))
        console.print()
        console.print(Rule(style="dim magenta"))
        console.print(f"  [dim]HTML report saved →[/]  [bright_cyan]{fname}[/]")
    except Exception as e:
        console.print(f"  [dim yellow]HTML save failed: {e}[/]")

    console.print()
    console.print(Rule("[bold bright_magenta]  ◈ DONE ◈  [/bold bright_magenta]", style="bright_magenta"))
    console.print()

def prompt_field(label: str, hint: str = "", required: bool = False) -> str:
    while True:
        hint_text = f" [dim]({hint})[/dim]" if hint else " [dim](enter to skip)[/dim]"
        console.print(f"  [bright_magenta]›[/bright_magenta] [bold white]{label:<18}[/bold white]{hint_text} ", end="")
        val = input().strip()
        if val:
            return val
        if not required:
            return ""
        console.print("  [red]  ✘ This field is required.[/red]")

def main():
    banner()

    if not API_KEY:
        console.print(Panel(
            "[yellow]No API key configured.[/yellow]\n"
            "Edit [bright_cyan]osint_config.json[/bright_cyan] and add your OpenRouter key\n"
            "to enable AI threat analysis.",
            title="[bold yellow]⚠  AI Analysis Disabled[/bold yellow]",
            border_style="yellow"
        ))
        console.print()

    # ── Structured Input Form ────────────────────────────────────────────
    console.print(Panel(
        "[bright_white]Fill in what you know. Every field helps.\n"
        "[dim]Press Enter to skip any field.[/dim][/bright_white]",
        title="[bold bright_magenta]  ◈ TARGET INFORMATION ◈  [/bold bright_magenta]",
        border_style="bright_magenta"
    ))
    console.print()

    fields = [
        ("Full Name",    "e.g. Karma Doe",            "full_name",  True),
        ("Email",        "e.g. karma@gmail.com",       "email",      False),
        ("Username",     "e.g. karma or @karma",       "username",   False),
        ("Phone",        "e.g. +1-555-123-4567",       "phone",      False),
        ("Pet Name",     "e.g. Tony",                  "pet_name",   False),
        ("Date of Birth","e.g. 1995-08-21",            "dob",        False),
        ("City",         "e.g. London",                "city",       False),
        ("IP Address",   "e.g. 192.168.1.1",           "ip",         False),
    ]

    target = {}
    for label, hint, key, required in fields:
        val = prompt_field(label, hint, required)
        if val:
            if key == "username":
                val = val.lstrip("@")
            target[key] = val

    # ── "Wanna add more?" prompt ─────────────────────────────────────────
    console.print()
    console.print(f"  [bright_magenta]›[/bright_magenta] [bold white]Wanna add more?[/bold white] [dim](Y/N)[/dim] ", end="")
    more = input().strip().lower()

    if more == "y":
        console.print()
        console.print(Panel(
            "[bright_white]Type anything extra — nicknames, old emails, company name,\n"
            "school, city, job title, social links, etc.\n"
            "[dim]Type [bold]done[/bold] on a new line when finished.[/dim][/bright_white]",
            title="[bold bright_cyan]  ◈ ADDITIONAL DETAILS ◈  [/bold bright_cyan]",
            border_style="bright_cyan"
        ))
        console.print()
        extras = []
        while True:
            console.print("  [bright_cyan]›[/bright_cyan] ", end="")
            line = input().strip()
            if line.lower() == "done":
                break
            if line:
                extras.append(line)

        if extras:
            # Parse extras for any detectable fields, rest goes into "extra_info"
            extra_target = parse_free_input("\n".join(extras))
            for k, v in extra_target.items():
                if k not in target:
                    target[k] = v
            # Store remaining raw extras
            target["extra_info"] = " | ".join(extras)

    if not target:
        console.print("\n  [red]No valid input. Exiting.[/red]\n")
        return

    # ── Confirm target ───────────────────────────────────────────────────
    console.print()
    rows = "\n".join(
        f"  [bright_cyan]{k.replace('_',' ').title():<18}[/bright_cyan] [white]{v}[/white]"
        for k, v in target.items() if v
    )
    console.print(Panel(rows, title="[bold cyan]  ◈ CONFIRMED TARGET ◈  [/bold cyan]", border_style="cyan"))
    console.print()
    console.print(f"  [bright_magenta]›[/bright_magenta] [bold white]Start scan?[/bold white] [dim](Y/N)[/dim] ", end="")
    confirm = input().strip().lower()
    if confirm != "y":
        console.print("\n  [dim]Scan cancelled.[/dim]\n")
        return

    # ── Estimated Time ───────────────────────────────────────────────────
    filled   = sum(1 for v in target.values() if v)
    queries  = len(build_queries(target))
    has_user = 1 if target.get("username") else 0
    has_mail = 1 if target.get("email") else 0
    has_ip   = 1 if target.get("ip") else 0
    est_secs = (queries * 2) + (has_user * 12) + (has_mail * 5) + (has_ip * 3) + 15
    est_min  = est_secs // 60
    est_sec  = est_secs % 60
    est_str  = f"{est_min}m {est_sec}s" if est_min else f"~{est_sec}s"

    console.print()
    console.print(Panel(
        f"  [bright_cyan]Fields filled:[/bright_cyan]   [white]{filled}[/white]\n"
        f"  [bright_cyan]Search queries:[/bright_cyan]  [white]{queries}[/white]\n"
        f"  [bright_cyan]Platforms:[/bright_cyan]       [white]{len(USERNAME_SITES) if has_user else 0}[/white]\n"
        f"  [bright_cyan]Est. time:[/bright_cyan]       [bold bright_magenta]{est_str}[/bold bright_magenta]",
        title="[bold bright_cyan]  ◈ SCAN PREVIEW ◈  [/bold bright_cyan]",
        border_style="bright_cyan"
    ))

    console.print()
    console.print(Rule("[bold bright_magenta]  ◈ SCANNING — 3 ENGINES · 40 PLATFORMS · AI ANALYSIS ◈  [/bold bright_magenta]", style="bright_magenta"))
    console.print()

    start_time = time.time()
    results = run_search(target)
    elapsed = time.time() - start_time
    results["scan_duration"] = f"{elapsed:.1f}s"
    display_results(results)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[bright_magenta]  ◈ Scan aborted.[/bright_magenta]\n")
