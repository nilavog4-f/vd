import subprocess, sys, os

# ── Auto-install deps ──────────────────────────────────────────────
def _ensure_deps():
    mods = {
        "requests":     "requests",
        "rich":         "rich",
        "pyfiglet":     "pyfiglet",
        "ddgs":         "ddgs",
        "phonenumbers": "phonenumbers",
        "bs4":          "beautifulsoup4",
    }
    for mod, pkg in mods.items():
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

# ── Imports ───────────────────────────────────────────────────────
import json, re, time, requests, threading, concurrent.futures
from datetime import datetime
from bs4 import BeautifulSoup
from ddgs import DDGS

import phonenumbers
from phonenumbers import (
    geocoder, carrier, timezone as ph_tz,
    PhoneNumberType, NumberParseException
)

from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich.align   import Align
from rich.rule    import Rule
from rich.columns import Columns
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich         import box
import pyfiglet

console = Console()
_ddg_lock = threading.Lock()

# ── Config (shared with osint / phone tools) ──────────────────────
CONFIG_FILE = "osint_config.json"
def _load_cfg():
    try:
        if os.path.exists(CONFIG_FILE):
            c = open(CONFIG_FILE).read().strip()
            if c: return json.loads(c)
    except Exception: pass
    return {"api_key": "", "model": "openai/gpt-4o-mini"}

cfg        = _load_cfg()
# Prefer the env var (Replit Secrets) over the plaintext config file.
API_KEY    = os.environ.get("OPENROUTER_API_KEY", "").strip() or cfg.get("api_key", "")
MODEL      = cfg.get("model", "openai/gpt-4o-mini")
OPENROUTER = "https://openrouter.ai/api/v1/chat/completions"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/124.0 Safari/537.36")
SESS = requests.Session()
SESS.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})

# ## ═══════════════════════════════════════════════════════════════
# ## BANNER
# ══════════════════════════════════════════════════════════════════
def banner():
    console.clear()
    fig = pyfiglet.figlet_format("DEEP  SCAN", font="doom")
    colors = ["bright_yellow","yellow","bright_red","red",
              "bright_yellow","yellow","bright_red","red"]
    txt = Text()
    for i, line in enumerate(fig.splitlines()):
        txt.append(line + "\n", style=colors[i % len(colors)])
    console.print(Align.center(txt))

    sub = Text()
    sub.append("  ◈ ", style="bright_yellow")
    sub.append("PHONE NUMBER DEEP INTELLIGENCE", style="bold bright_white")
    sub.append(" ◈  ", style="bright_yellow")
    console.print(Align.center(sub))

    tags = Text()
    for label, sep in [
        ("Spam Reports", " | "), ("Carrier", " | "), ("Line Type", " | "),
        ("Reputation", " | "), ("Caller ID", " | "), ("AI Summary", ""),
    ]:
        tags.append(label, style="bright_yellow")
        if sep: tags.append(sep, style="dim yellow")
    console.print(Align.center(tags))
    console.print(Align.center(Text("by @lfw.k4rma_  ·  FOR AUTHORIZED USE ONLY\n", style="dim yellow")))
    console.print(Rule(style="bright_yellow"))

# ══════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════
LINE_TYPE_MAP = {
    PhoneNumberType.MOBILE:           ("MOBILE",           "bright_cyan"),
    PhoneNumberType.FIXED_LINE:       ("FIXED LINE",        "bright_blue"),
    PhoneNumberType.FIXED_LINE_OR_MOBILE: ("FIXED/MOBILE", "cyan"),
    PhoneNumberType.TOLL_FREE:        ("TOLL-FREE",         "bright_green"),
    PhoneNumberType.PREMIUM_RATE:     ("PREMIUM RATE",      "bright_red"),
    PhoneNumberType.SHARED_COST:      ("SHARED COST",       "yellow"),
    PhoneNumberType.VOIP:             ("VoIP",              "magenta"),
    PhoneNumberType.PERSONAL_NUMBER:  ("PERSONAL",          "bright_magenta"),
    PhoneNumberType.UAN:              ("UAN",               "dim white"),
    PhoneNumberType.UNKNOWN:          ("UNKNOWN",           "dim white"),
}

def _clean(raw: str) -> str:
    return re.sub(r'[\s\-\(\)\.]+', '', raw.strip())

def _risk_label(score: int):
    """score 0-100 → (label, colour)"""
    if score == 0:   return "UNKNOWN",     "dim white"
    if score < 20:   return "CLEAN",       "bright_green"
    if score < 45:   return "SUSPICIOUS",  "yellow"
    if score < 70:   return "LIKELY SPAM", "bright_red"
    return               "CONFIRMED SPAM","bold bright_red"

def _bar(score: int, width=30) -> Text:
    filled = int(score / 100 * width)
    color  = _risk_label(score)[1]
    t = Text()
    t.append("█" * filled, style=color)
    t.append("░" * (width - filled), style="dim white")
    return t

def _get(url, **kw) -> requests.Response | None:
    try:
        return SESS.get(url, timeout=10, **kw)
    except Exception:
        return None

def _soup(url, **kw) -> BeautifulSoup | None:
    r = _get(url, **kw)
    if r and r.status_code == 200:
        return BeautifulSoup(r.text, "html.parser")
    return None

# ══════════════════════════════════════════════════════════════════
#  SECTION 1 — phonenumbers library (local, no network)
# ══════════════════════════════════════════════════════════════════
def lookup_phonenumbers(number: str, default_region="US") -> dict:
    result = {
        "valid": False, "e164": number, "national": number,
        "international": number, "country": "", "region": "",
        "carrier": "", "line_type": "", "line_color": "dim white",
        "timezones": [], "country_code": "",
    }
    try:
        parsed = phonenumbers.parse(number, default_region)
        result["valid"]         = phonenumbers.is_valid_number(parsed)
        result["e164"]          = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.E164)
        result["national"]      = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        result["international"] = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        result["country_code"]  = str(parsed.country_code)
        result["country"]       = geocoder.description_for_number(parsed, "en")
        result["region"]        = geocoder.description_for_number(parsed, "en")
        result["carrier"]       = carrier.name_for_number(parsed, "en") or ""
        result["timezones"]     = list(ph_tz.time_zones_for_number(parsed))
        ntype                   = phonenumbers.number_type(parsed)
        lt = LINE_TYPE_MAP.get(ntype, ("UNKNOWN","dim white"))
        result["line_type"]  = lt[0]
        result["line_color"] = lt[1]
    except NumberParseException:
        pass
    return result

# ══════════════════════════════════════════════════════════════════
#  SECTION 2 — 800notes.com
# ══════════════════════════════════════════════════════════════════
def scrape_800notes(number: str) -> dict:
    """800notes carries US/CA spam complaints since ~2006."""
    result = {"reports": 0, "rating": "", "comments": [], "url": ""}
    digits = re.sub(r'\D', '', number)
    if len(digits) == 11 and digits[0] == '1':
        digits = digits[1:]
    if len(digits) != 10:
        return result

    fmt = f"{digits[:3]}-{digits[3:6]}-{digits[6:]}"
    url = f"https://800notes.com/Phone.aspx/1-{fmt}"
    result["url"] = url

    headers = {
        "User-Agent": UA,
        "Referer": "https://800notes.com/",
        "Accept": "text/html,application/xhtml+xml",
    }
    soup = _soup(url, headers=headers)
    if not soup:
        return result

    # report count
    for tag in soup.find_all(string=re.compile(r'\d+\s+report', re.I)):
        m = re.search(r'(\d+)', str(tag))
        if m:
            result["reports"] = int(m.group(1))
            break

    # overall rating text
    rating_el = soup.find(class_=re.compile(r'ratingBox|rating', re.I))
    if rating_el:
        result["rating"] = rating_el.get_text(strip=True)[:60]

    # grab latest comments (up to 5)
    comments = []
    for el in soup.find_all(class_=re.compile(r'comment|review|message|note', re.I)):
        txt = el.get_text(" ", strip=True)
        if len(txt) > 15:
            comments.append(txt[:200])
        if len(comments) >= 5:
            break
    result["comments"] = comments
    return result

# ══════════════════════════════════════════════════════════════════
#  SECTION 3 — tellows.com
# ══════════════════════════════════════════════════════════════════
def scrape_tellows(number: str) -> dict:
    """tellows score: 1 (trustworthy) → 9 (dangerous). Community-sourced."""
    result = {"score": 0, "calls": 0, "type": "", "url": ""}
    try:
        parsed = phonenumbers.parse(number, "US")
        intl   = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except Exception:
        intl = number

    url = f"https://www.tellows.com/num/{intl}"
    result["url"] = url

    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml",
        "Referer": "https://www.tellows.com/",
    }
    soup = _soup(url, headers=headers)
    if not soup:
        return result

    # score
    score_el = soup.find(class_=re.compile(r'score|pontuacao', re.I))
    if score_el:
        m = re.search(r'(\d+)', score_el.get_text())
        if m:
            result["score"] = int(m.group(1))

    # also try data attributes / json-ld
    if not result["score"]:
        m = re.search(r'"score"\s*:\s*(\d+)', soup.get_text())
        if m:
            result["score"] = int(m.group(1))
        m2 = re.search(r'score["\s]+(\d)', soup.decode_contents())
        if m2 and not result["score"]:
            result["score"] = int(m2.group(1))

    # call count
    m = re.search(r'(\d[\d,]+)\s*(search|call|look)', soup.get_text(), re.I)
    if m:
        result["calls"] = int(re.sub(r'\D','', m.group(1)))

    # call type label
    type_el = soup.find(class_=re.compile(r'callType|call-type|callertype', re.I))
    if type_el:
        result["type"] = type_el.get_text(strip=True)[:50]

    return result

# ══════════════════════════════════════════════════════════════════
#  SECTION 4 — shouldianswer.com
# ══════════════════════════════════════════════════════════════════
def scrape_shouldianswer(number: str) -> dict:
    result = {"rating": 0, "votes": 0, "verdict": "", "url": ""}
    digits = re.sub(r'\D', '', number)
    if digits.startswith('1') and len(digits) == 11:
        digits = digits[1:]
    url = f"https://www.shouldianswer.com/phone-number/{digits}"
    result["url"] = url

    headers = {"User-Agent": UA, "Referer": "https://www.shouldianswer.com/"}
    soup = _soup(url, headers=headers)
    if not soup:
        return result

    # rating percentage / score
    m = re.search(r'(\d{1,3})\s*%', soup.get_text())
    if m:
        result["rating"] = int(m.group(1))

    # vote count
    m2 = re.search(r'(\d+)\s*vote', soup.get_text(), re.I)
    if m2:
        result["votes"] = int(m2.group(1))

    # verdict (Safe / Dangerous / Unknown)
    for word in ("safe","dangerous","unsafe","spam","scam","unknown","neutral"):
        if word in soup.get_text().lower():
            result["verdict"] = word.capitalize()
            break

    return result

# ══════════════════════════════════════════════════════════════════
#  SECTION 5 — whocallsme.com
# ══════════════════════════════════════════════════════════════════
def scrape_whocallsme(number: str) -> dict:
    result = {"reports": 0, "type": "", "comments": [], "url": ""}
    digits = re.sub(r'\D', '', number)
    url = f"https://whocallsme.com/Phone-Number.aspx/{digits}"
    result["url"] = url

    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml",
        "Referer": "https://whocallsme.com/",
    }
    soup = _soup(url, headers=headers)
    if not soup:
        return result

    # report count
    m = re.search(r'(\d+)\s*(report|comment|review)', soup.get_text(), re.I)
    if m:
        result["reports"] = int(m.group(1))

    # type of caller
    type_el = soup.find(class_=re.compile(r'type|callerType|category', re.I))
    if type_el:
        result["type"] = type_el.get_text(strip=True)[:60]

    # comments
    comments = []
    for el in soup.find_all(class_=re.compile(r'comment|review|text|body', re.I)):
        t = el.get_text(" ", strip=True)
        if len(t) > 20:
            comments.append(t[:200])
        if len(comments) >= 4:
            break
    result["comments"] = comments
    return result

# ══════════════════════════════════════════════════════════════════
#  SECTION 6 — spamcalls.net
# ══════════════════════════════════════════════════════════════════
def scrape_spamcalls(number: str) -> dict:
    result = {"spam": False, "category": "", "reports": 0, "url": ""}
    try:
        parsed = phonenumbers.parse(number, "US")
        intl   = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except Exception:
        intl = number

    url = f"https://spamcalls.net/en/search/{intl}"
    result["url"] = url

    headers = {"User-Agent": UA, "Referer": "https://spamcalls.net/"}
    soup = _soup(url, headers=headers)
    if not soup:
        return result

    text = soup.get_text().lower()
    result["spam"] = any(w in text for w in ("spam","scam","fraud","robocall","telemarketer"))

    for cat in ("telemarketer","robocall","scam","fraud","debt collector",
                "survey","charity","political","unknown"):
        if cat in text:
            result["category"] = cat.title()
            break

    m = re.search(r'(\d+)\s*(report|complaint)', text, re.I)
    if m:
        result["reports"] = int(m.group(1))

    return result

# ══════════════════════════════════════════════════════════════════
#  SECTION 7 — DDG search (name, leaks, social)
# ══════════════════════════════════════════════════════════════════
def ddg_search(number: str) -> dict:
    result = {"results": [], "names": [], "leaks": False, "platforms": []}
    queries = [
        f'"{number}"',
        f'"{number}" spam OR scam OR reported',
        f'"{number}" site:truecaller.com OR site:whitepages.com OR site:spokeo.com',
    ]
    platforms = ["facebook","instagram","twitter","linkedin","whatsapp",
                 "telegram","tiktok","snapchat"]
    snippets = []

    for q in queries:
        try:
            with _ddg_lock:
                hits = list(DDGS().text(q, max_results=5))
            for h in hits:
                body = (h.get("body","") or h.get("snippet",""))
                title = h.get("title","")
                snippets.append(f"{title} {body}")
                result["results"].append({
                    "title": title[:80],
                    "url":   h.get("href","")[:100],
                    "body":  body[:120],
                })
            time.sleep(0.3)
        except Exception:
            pass

    full_text = " ".join(snippets).lower()

    # extract possible names (Title Case words appearing near the number)
    raw_names = re.findall(r'\b([A-Z][a-z]{2,}\s+[A-Z][a-z]{2,})\b', " ".join(snippets))
    seen = set()
    for n in raw_names:
        if n not in seen and len(n) < 40:
            result["names"].append(n)
            seen.add(n)
        if len(result["names"]) >= 5:
            break

    result["leaks"]     = any(w in full_text for w in
                              ("breach","leaked","database","pastebin","haveibeenpwned"))
    result["platforms"] = [p for p in platforms if p in full_text]

    return result

# ══════════════════════════════════════════════════════════════════
#  SECTION 8 — AI summary
# ══════════════════════════════════════════════════════════════════
def ai_summary(number: str, data: dict) -> str:
    if not API_KEY:
        return ""
    prompt = (
        f"You are a phone number intelligence analyst. "
        f"Summarize the following data about {number} in 3-4 sentences. "
        f"Give a clear verdict: is this number safe, suspicious, or spam?\n\n"
        f"Data:\n{json.dumps(data, indent=2, default=str)[:3000]}"
    )
    try:
        r = requests.post(
            OPENROUTER,
            headers={"Authorization": f"Bearer {API_KEY}",
                     "Content-Type": "application/json"},
            json={"model": MODEL,
                  "messages": [{"role":"user","content": prompt}],
                  "max_tokens": 300},
            timeout=20
        )
        return r.json()["choices"][0]["message"]["content"].strip()
    except Exception:
        return ""

# ══════════════════════════════════════════════════════════════════
#  SCORE ENGINE
# ══════════════════════════════════════════════════════════════════
def calc_spam_score(pn: dict, notes: dict, tellows: dict,
                    sia: dict, wcm: dict, spam: dict) -> int:
    score = 0
    # 800notes reports
    r = notes.get("reports", 0)
    score += min(r * 2, 25)                          # up to 25 pts

    # tellows score (1=safe, 9=spam → map to 0-35)
    ts = tellows.get("score", 0)
    if ts:
        score += int((ts - 1) / 8 * 35)             # up to 35 pts

    # shouldianswer  (0% safe = bad → dangerous = high score)
    sia_r = sia.get("rating", 0)
    # rating is "safe" percentage, so flip it
    if sia_r:
        score += int((100 - sia_r) / 100 * 20)      # up to 20 pts

    # whocallsme
    score += min(wcm.get("reports", 0), 10)          # up to 10 pts

    # spamcalls
    if spam.get("spam"):
        score += 10                                  # flat 10 pts

    return min(score, 100)

# ══════════════════════════════════════════════════════════════════
#  DISPLAY
# ══════════════════════════════════════════════════════════════════
def display_results(number: str, pn: dict, notes: dict, tellows: dict,
                    sia: dict, wcm: dict, spam: dict,
                    ddg: dict, ai: str, score: int):

    risk_label, risk_color = _risk_label(score)

    # ── Header card ──────────────────────────────────────────────
    console.print()
    console.print(Rule(f"[bold bright_yellow]  ◈  DEEP SCAN RESULTS  ◈  [/]", style="bright_yellow"))
    console.print()

    # ## Stat summary: validity | score | risk  (no box borders)
    valid_txt  = "VALID" if pn["valid"] else "INVALID"
    valid_col  = "bright_green" if pn["valid"] else "bright_red"
    score_col  = risk_color.replace("bold ","")

    summary = Text()
    summary.append("  NUMBER  ", style="dim")
    summary.append(valid_txt, style=f"bold {valid_col}")
    summary.append("    SPAM SCORE  ", style="dim")
    summary.append(str(score), style=f"bold {score_col}")
    summary.append("    VERDICT  ", style="dim")
    summary.append(risk_label, style=f"{risk_color}")
    summary.append("  ")
    console.print(Align.center(summary))
    console.print()

    # ── Spam meter ────────────────────────────────────────────────
    console.print(f"  [dim]Spam meter[/]  [{score_col}]{score:3d}/100[/]  ", end="")
    console.print(_bar(score))
    console.print()

    # ── Number details ────────────────────────────────────────────
    console.print(Rule("[dim yellow]  NUMBER DETAILS  [/]", style="dim yellow"))
    details = [
        ("Format (E.164)",    pn["e164"],          "bright_white"),
        ("International",     pn["international"],  "bright_white"),
        ("National",          pn["national"],        "white"),
        ("Country",           pn["country"] or "—",  "bright_cyan"),
        ("Carrier",           pn["carrier"]  or "Unknown", "bright_magenta"),
        ("Line Type",         pn["line_type"] or "Unknown", pn["line_color"]),
        ("Time Zones",        ", ".join(pn["timezones"][:3]) or "—", "dim white"),
    ]
    for label, value, color in details:
        console.print(f"  [dim]{label:<22}[/]  [{color}]{value}[/]")
    console.print()

    # ── Spam reports table ────────────────────────────────────────
    console.print(Rule("[dim yellow]  SPAM REPORT SOURCES  [/]", style="dim yellow"))
    t = Table(box=box.SIMPLE_HEAVY, border_style="dim yellow",
              header_style="bold yellow", expand=True)
    t.add_column("SOURCE",   width=20)
    t.add_column("REPORTS",  width=10, justify="right")
    t.add_column("SCORE",    width=10, justify="center")
    t.add_column("VERDICT",  min_width=20)

    # 800notes
    n_rep = notes.get("reports", 0)
    n_col = "bright_red" if n_rep > 5 else ("yellow" if n_rep > 0 else "dim green")
    t.add_row("800notes.com",
              str(n_rep) if n_rep else "—",
              notes.get("rating","—")[:12] or "—",
              f"[{n_col}]{n_rep} report(s)[/]" if n_rep else "[dim green]No reports[/]")

    # tellows
    ts = tellows.get("score", 0)
    ts_col = "bright_red" if ts >= 7 else ("yellow" if ts >= 4 else "dim green")
    t.add_row("tellows.com",
              str(tellows.get("calls","—")),
              f"{ts}/9" if ts else "—",
              f"[{ts_col}]{tellows.get('type','') or ('Dangerous' if ts>=7 else 'Neutral')}[/]" if ts else "[dim]No data[/]")

    # shouldianswer
    sia_r = sia.get("rating", 0)
    sia_col = "bright_red" if sia_r < 30 else ("yellow" if sia_r < 60 else "dim green")
    t.add_row("shouldianswer.com",
              str(sia.get("votes","—")),
              f"{sia_r}%" if sia_r else "—",
              f"[{sia_col}]{sia.get('verdict','') or '—'}[/]")

    # whocallsme
    wc = wcm.get("reports", 0)
    wc_col = "bright_red" if wc > 3 else ("yellow" if wc > 0 else "dim green")
    t.add_row("whocallsme.com",
              str(wc) if wc else "—",
              "—",
              f"[{wc_col}]{wcm.get('type','') or (str(wc)+' report(s)' if wc else 'No reports')}[/]")

    # spamcalls
    sp = spam.get("spam", False)
    sp_col = "bright_red" if sp else "dim green"
    t.add_row("spamcalls.net",
              str(spam.get("reports","—")),
              "—",
              f"[{sp_col}]{spam.get('category','') or ('SPAM DETECTED' if sp else 'Clean')}[/]")

    console.print(t)

    # ── Recent comments ───────────────────────────────────────────
    all_comments = notes.get("comments", []) + wcm.get("comments", [])
    if all_comments:
        console.print(Rule("[dim yellow]  CALLER REPORTS (COMMUNITY)[/]", style="dim yellow"))
        for i, c in enumerate(all_comments[:6], 1):
            console.print(f"  [dim yellow]{i}.[/]  [white]{c.strip()[:180]}[/]")
        console.print()

    # ── DDG findings ──────────────────────────────────────────────
    console.print(Rule("[dim yellow]  WEB INTELLIGENCE  [/]", style="dim yellow"))

    names = ddg.get("names", [])
    if names:
        console.print(f"  [dim]Possible name(s)  :[/]  [bright_white]{', '.join(names[:3])}[/]")

    plats = ddg.get("platforms", [])
    if plats:
        console.print(f"  [dim]Platform mentions :[/]  [bright_magenta]{', '.join(p.capitalize() for p in plats)}[/]")

    if ddg.get("leaks"):
        console.print(f"  [dim]Data leaks        :[/]  [bright_red]⚠  Number found near breach/leak references[/]")

    web_results = ddg.get("results", [])
    if web_results:
        console.print(f"\n  [bold dim]Top web results:[/]")
        for r in web_results[:4]:
            if r.get("url"):
                console.print(f"  [dim yellow]•[/]  [blue underline]{r['url']}[/]")
                if r.get("body"):
                    console.print(f"     [dim]{r['body'][:120]}[/]")
    console.print()

    # ── AI summary ────────────────────────────────────────────────
    if ai:
        console.print(Rule("[dim yellow]  AI ANALYSIS[/]", style="dim yellow"))
        console.print(f"  [yellow]{ai}[/yellow]")
        console.print()

    # ── Source URLs ───────────────────────────────────────────────
    console.print(Rule("[dim]  SOURCES  [/]", style="dim"))
    for src, url in [
        ("800notes    ", notes.get("url","")),
        ("tellows     ", tellows.get("url","")),
        ("shouldianswer", sia.get("url","")),
        ("whocallsme  ", wcm.get("url","")),
        ("spamcalls   ", spam.get("url","")),
    ]:
        if url:
            console.print(f"  [dim]{src}:[/]  [dim blue underline]{url}[/]")
    console.print()
    console.print(Rule(style="bright_yellow"))

# ## ═══════════════════════════════════════════════════════════════
# ## MAIN  ** Entry point for WSL / Kali Linux **
# ══════════════════════════════════════════════════════════════════
def main():
    banner()
    console.print()
    console.print("  [dim yellow]◈[/]  ", end="")
    raw = input("Enter phone number (e.g. +1 202-555-0147 or 2025550147): ").strip()
    if not raw:
        console.print("  [red]No number entered.[/]"); return

    number = raw
    # if no +, assume US
    if not number.startswith("+"):
        digits = re.sub(r'\D', '', number)
        number = f"+1{digits}" if len(digits) == 10 else f"+{digits}"

    console.print()

    # ── Run all lookups in parallel ───────────────────────────────
    results = {}
    tasks = {
        "pn":      (lookup_phonenumbers, [number]),
        "notes":   (scrape_800notes,     [number]),
        "tellows": (scrape_tellows,       [number]),
        "sia":     (scrape_shouldianswer, [number]),
        "wcm":     (scrape_whocallsme,    [number]),
        "spam":    (scrape_spamcalls,     [number]),
        "ddg":     (ddg_search,           [number]),
    }

    with Progress(
        SpinnerColumn(spinner_name="dots", style="bright_yellow"),
        TextColumn("[bright_yellow]{task.description}[/]"),
        BarColumn(bar_width=30, style="yellow", complete_style="bright_yellow"),
        TextColumn("[dim]{task.completed}/{task.total}[/]"),
        console=console,
        transient=True,
    ) as prog:
        task_id = prog.add_task("Running deep scan...", total=len(tasks))

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
                    results[key] = {}
                prog.advance(task_id)

    # phonenumbers is fast/local — ensure it ran
    pn      = results.get("pn",      lookup_phonenumbers(number))
    notes   = results.get("notes",   {})
    tell    = results.get("tellows", {})
    sia     = results.get("sia",     {})
    wcm     = results.get("wcm",     {})
    spam    = results.get("spam",    {})
    ddg     = results.get("ddg",     {})

    # score + optional AI (needs score data first)
    score = calc_spam_score(pn, notes, tell, sia, wcm, spam)

    ai = ""
    if API_KEY:
        with Progress(SpinnerColumn(spinner_name="dots", style="yellow"),
                      TextColumn("[yellow]Running AI analysis...[/]"),
                      console=console, transient=True) as p:
            p.add_task("", total=None)
            ai = ai_summary(number, {
                "phonenumbers": pn, "800notes": notes,
                "tellows": tell, "shouldianswer": sia,
                "spam_score": score,
            })

    display_results(number, pn, notes, tell, sia, wcm, spam, ddg, ai, score)

    # ── Save JSON ─────────────────────────────────────────────────
    fname = f"phonescan_{re.sub(r'\W','_',number)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(fname, "w") as f:
            json.dump({
                "number": number, "spam_score": score, "risk": _risk_label(score)[0],
                "phonenumbers": pn, "800notes": notes, "tellows": tell,
                "shouldianswer": sia, "whocallsme": wcm, "spamcalls": spam,
                "web": ddg, "ai_summary": ai,
                "scanned_at": datetime.now().isoformat(),
            }, f, indent=2)
        console.print(f"  [dim]Full report saved to:[/]  [bright_cyan]{fname}[/]")
    except Exception:
        pass

    console.print()

# ## Entry point ######################################################
# ** Run:  python3 osint2.py  (WSL / Kali Linux)
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n  [dim]Scan cancelled.[/]")
    except Exception as exc:
        console.print(f"\n  [bright_red][!] Unexpected error:[/bright_red]  [red]{exc}[/red]")
        console.print("  [dim]Try again or check your network connection.[/dim]")