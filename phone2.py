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

import json, re, time, requests, concurrent.futures, threading
from datetime import datetime
from ddgs import DDGS

_ddg_lock = threading.Lock()
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich.columns import Columns
from rich import box
import pyfiglet

console = Console()

CONFIG_FILE = "osint_config.json"
def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE) as f:
                content = f.read().strip()
                if content:
                    return json.loads(content)
    except Exception:
        pass
    return {"api_key": "", "model": "openai/gpt-4o-mini"}

config  = load_config()
# Prefer the env var (Replit Secrets) over the plaintext config file.
API_KEY = os.environ.get("OPENROUTER_API_KEY", "").strip() or config.get("api_key", "")
MODEL   = config.get("model", "openai/gpt-4o-mini")
OPENROUTER = "https://openrouter.ai/api/v1/chat/completions"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
SESS = requests.Session()
SESS.headers.update({"User-Agent": UA})

def banner():
    console.clear()
    fig = pyfiglet.figlet_format("PHONE  INT", font="doom")
    colors = ["bright_cyan","cyan","bright_magenta","magenta","bright_blue","blue","bright_cyan","cyan"]
    styled = Text()
    for i, line in enumerate(fig.splitlines()):
        styled.append(line + "\n", style=colors[i % len(colors)])
    console.print(Align.center(styled))
    sub = Text()
    sub.append("  ◈ ", style="bright_cyan")
    sub.append("PHONE NUMBER INTELLIGENCE FRAMEWORK", style="bold bright_white")
    sub.append(" ◈  ", style="bright_cyan")
    console.print(Align.center(sub))
    tags = Text()
    tags.append("  [ ", style="dim cyan")
    tags.append("Carrier Lookup", style="bright_cyan")
    tags.append(" | ", style="dim cyan")
    tags.append("Reverse Lookup", style="bright_magenta")
    tags.append(" | ", style="dim cyan")
    tags.append("Breach Search", style="bright_cyan")
    tags.append(" | ", style="dim cyan")
    tags.append("Social Check", style="bright_magenta")
    tags.append(" | ", style="dim cyan")
    tags.append("AI Analysis", style="bright_cyan")
    tags.append(" ]  ", style="dim cyan")
    console.print(Align.center(tags))
    console.print(Align.center(Text("by @lfw.k4rma_\n", style="dim cyan")))
    console.print(Rule(style="bright_cyan"))

def stat_box(label, value, color):
    return Panel(
        Align.center(Text(str(value), style=f"bold {color}")),
        title=f"[dim]{label}[/dim]",
        border_style=color,
        padding=(0, 2),
        width=20
    )

def clean_number(raw: str) -> str:
    return re.sub(r'[\s\-\(\)]', '', raw.strip())

# ── Lookup Functions ──────────────────────────────────────────────────────────

def veriphone_lookup(number: str) -> dict:
    try:
        r = SESS.get(f"https://api.veriphone.io/v2/verify?phone={requests.utils.quote(number)}&key=demo", timeout=8)
        return r.json() if r.status_code == 200 else {}
    except: return {}

def numverify_lookup(number: str) -> dict:
    try:
        r = SESS.get(f"http://apilayer.net/api/validate?access_key=demo&number={requests.utils.quote(number)}&format=1", timeout=8)
        return r.json() if r.status_code == 200 else {}
    except: return {}

def abstract_lookup(number: str) -> dict:
    try:
        r = SESS.get(f"https://phonevalidation.abstractapi.com/v1/?api_key=demo&phone={requests.utils.quote(number)}", timeout=8)
        return r.json() if r.status_code == 200 else {}
    except: return {}

US_AREA_CODES = {
    "201":"Jersey City, NJ","202":"Washington, DC","203":"Bridgeport, CT","205":"Birmingham, AL",
    "206":"Seattle, WA","207":"Portland, ME","208":"Boise, ID","209":"Stockton, CA",
    "210":"San Antonio, TX","212":"New York City, NY","213":"Los Angeles, CA","214":"Dallas, TX",
    "215":"Philadelphia, PA","216":"Cleveland, OH","217":"Springfield, IL","218":"Duluth, MN",
    "219":"Gary, IN","220":"Newark, OH","223":"Lancaster, PA","224":"Evanston, IL",
    "225":"Baton Rouge, LA","228":"Biloxi, MS","229":"Albany, GA","231":"Traverse City, MI",
    "234":"Akron, OH","239":"Naples, FL","240":"Bethesda, MD","248":"Troy, MI",
    "251":"Mobile, AL","252":"Rocky Mount, NC","253":"Tacoma, WA","254":"Waco, TX",
    "256":"Huntsville, AL","260":"Fort Wayne, IN","262":"Racine, WI","267":"Philadelphia, PA",
    "269":"Kalamazoo, MI","270":"Bowling Green, KY","272":"Scranton, PA","276":"Bristol, VA",
    "281":"Houston, TX","301":"Rockville, MD","302":"Wilmington, DE","303":"Denver, CO",
    "304":"Charleston, WV","305":"Miami, FL","307":"Cheyenne, WY","308":"Grand Island, NE",
    "309":"Peoria, IL","310":"Los Angeles, CA","312":"Chicago, IL","313":"Detroit, MI",
    "314":"St. Louis, MO","315":"Syracuse, NY","316":"Wichita, KS","317":"Indianapolis, IN",
    "318":"Shreveport, LA","319":"Cedar Rapids, IA","320":"St. Cloud, MN","321":"Orlando, FL",
    "323":"Los Angeles, CA","325":"Abilene, TX","330":"Akron, OH","331":"Aurora, IL",
    "332":"New York City, NY","334":"Montgomery, AL","336":"Greensboro, NC","337":"Lafayette, LA",
    "339":"Boston, MA","341":"Oakland, CA","346":"Houston, TX","347":"New York City, NY",
    "351":"Lowell, MA","352":"Gainesville, FL","360":"Bellingham, WA","361":"Corpus Christi, TX",
    "364":"Bowling Green, KY","380":"Columbus, OH","385":"Salt Lake City, UT","386":"Daytona Beach, FL",
    "401":"Providence, RI","402":"Omaha, NE","404":"Atlanta, GA","405":"Oklahoma City, OK",
    "406":"Billings, MT","407":"Orlando, FL","408":"San Jose, CA","409":"Beaumont, TX",
    "410":"Baltimore, MD","412":"Pittsburgh, PA","413":"Springfield, MA","414":"Milwaukee, WI",
    "415":"San Francisco, CA","417":"Springfield, MO","419":"Toledo, OH","423":"Chattanooga, TN",
    "424":"Los Angeles, CA","425":"Bellevue, WA","430":"Tyler, TX","432":"Midland, TX",
    "434":"Charlottesville, VA","435":"St. George, UT","440":"Cleveland, OH","442":"Escondido, CA",
    "443":"Baltimore, MD","447":"Champaign, IL","458":"Eugene, OR","463":"Indianapolis, IN",
    "464":"Chicago, IL","469":"Dallas, TX","470":"Atlanta, GA","475":"Bridgeport, CT",
    "478":"Macon, GA","479":"Fayetteville, AR","480":"Scottsdale, AZ","484":"Allentown, PA",
    "501":"Little Rock, AR","502":"Louisville, KY","503":"Portland, OR","504":"New Orleans, LA",
    "505":"Albuquerque, NM","507":"Rochester, MN","508":"Worcester, MA","509":"Spokane, WA",
    "510":"Oakland, CA","512":"Austin, TX","513":"Cincinnati, OH","515":"Des Moines, IA",
    "516":"Hempstead, NY","517":"Lansing, MI","518":"Albany, NY","520":"Tucson, AZ",
    "530":"Sacramento, CA","531":"Omaha, NE","539":"Tulsa, OK","540":"Roanoke, VA",
    "541":"Eugene, OR","551":"Jersey City, NJ","559":"Fresno, CA","561":"West Palm Beach, FL",
    "562":"Long Beach, CA","563":"Davenport, IA","564":"Seattle, WA","567":"Toledo, OH",
    "570":"Scranton, PA","571":"Arlington, VA","573":"Columbia, MO","574":"South Bend, IN",
    "575":"Las Cruces, NM","580":"Lawton, OK","585":"Rochester, NY","586":"Warren, MI",
    "601":"Jackson, MS","602":"Phoenix, AZ","603":"Manchester, NH","605":"Sioux Falls, SD",
    "606":"Ashland, KY","607":"Binghamton, NY","608":"Madison, WI","609":"Trenton, NJ",
    "610":"Allentown, PA","612":"Minneapolis, MN","614":"Columbus, OH","615":"Nashville, TN",
    "616":"Grand Rapids, MI","617":"Boston, MA","618":"East St. Louis, IL","619":"San Diego, CA",
    "620":"Dodge City, KS","623":"Phoenix, AZ","626":"Pasadena, CA","628":"San Francisco, CA",
    "629":"Nashville, TN","630":"Naperville, IL","631":"Brentwood, NY","636":"St. Louis, MO",
    "641":"Mason City, IA","646":"New York City, NY","650":"San Mateo, CA","651":"St. Paul, MN",
    "657":"Anaheim, CA","659":"Birmingham, AL","660":"Sedalia, MO","661":"Bakersfield, CA",
    "662":"Tupelo, MS","667":"Baltimore, MD","669":"San Jose, CA","671":"Guam","678":"Atlanta, GA",
    "680":"Syracuse, NY","681":"Charleston, WV","682":"Fort Worth, TX","689":"Orlando, FL",
    "701":"Fargo, ND","702":"Las Vegas, NV","703":"Arlington, VA","704":"Charlotte, NC",
    "706":"Augusta, GA","707":"Santa Rosa, CA","708":"Chicago, IL","712":"Sioux City, IA",
    "713":"Houston, TX","714":"Anaheim, CA","715":"Eau Claire, WI","716":"Buffalo, NY",
    "717":"Harrisburg, PA","718":"New York City, NY","719":"Colorado Springs, CO",
    "720":"Denver, CO","724":"Pittsburgh, PA","725":"Las Vegas, NV","726":"San Antonio, TX",
    "727":"St. Petersburg, FL","731":"Jackson, TN","732":"New Brunswick, NJ","734":"Ann Arbor, MI",
    "737":"Austin, TX","740":"Columbus, OH","743":"Greensboro, NC","747":"Los Angeles, CA",
    "754":"Fort Lauderdale, FL","757":"Virginia Beach, VA","760":"Riverside, CA",
    "762":"Augusta, GA","763":"Minneapolis, MN","764":"San Jose, CA","765":"Lafayette, IN",
    "769":"Jackson, MS","770":"Atlanta, GA","771":"Rockville, MD","772":"Port St. Lucie, FL",
    "773":"Chicago, IL","775":"Reno, NV","779":"Rockford, IL","781":"Boston, MA",
    "785":"Topeka, KS","786":"Miami, FL","801":"Salt Lake City, UT","802":"Burlington, VT",
    "803":"Columbia, SC","804":"Richmond, VA","805":"Santa Barbara, CA","806":"Lubbock, TX",
    "808":"Honolulu, HI","810":"Flint, MI","812":"Evansville, IN","813":"Tampa, FL",
    "814":"Erie, PA","815":"Rockford, IL","816":"Kansas City, MO","817":"Fort Worth, TX",
    "818":"Los Angeles, CA","820":"San Luis Obispo, CA","828":"Asheville, NC","830":"San Antonio, TX",
    "831":"Salinas, CA","832":"Houston, TX","838":"Albany, NY","839":"Columbia, SC",
    "840":"San Bernardino, CA","843":"Charleston, SC","845":"Poughkeepsie, NY","847":"Chicago, IL",
    "848":"Trenton, NJ","850":"Tallahassee, FL","854":"Charleston, SC","856":"Camden, NJ",
    "857":"Boston, MA","858":"San Diego, CA","859":"Lexington, KY","860":"Hartford, CT",
    "861":"Sacramento, CA","862":"Newark, NJ","863":"Lakeland, FL","864":"Greenville, SC",
    "865":"Knoxville, TN","878":"Pittsburgh, PA","901":"Memphis, TN","903":"Tyler, TX",
    "904":"Jacksonville, FL","906":"Marquette, MI","907":"Anchorage, AK","908":"Elizabeth, NJ",
    "909":"San Bernardino, CA","910":"Fayetteville, NC","912":"Savannah, GA","913":"Kansas City, KS",
    "914":"White Plains, NY","915":"El Paso, TX","916":"Sacramento, CA","917":"New York City, NY",
    "918":"Tulsa, OK","919":"Raleigh, NC","920":"Green Bay, WI","925":"Concord, CA",
    "928":"Yuma, AZ","929":"New York City, NY","930":"Bloomington, IN","931":"Clarksville, TN",
    "934":"Brentwood, NY","936":"Huntsville, TX","937":"Dayton, OH","938":"Huntsville, AL",
    "940":"Denton, TX","941":"Sarasota, FL","947":"Troy, MI","949":"Irvine, CA",
    "951":"Riverside, CA","952":"Minneapolis, MN","954":"Fort Lauderdale, FL","956":"Laredo, TX",
    "959":"Hartford, CT","970":"Fort Collins, CO","971":"Portland, OR","972":"Dallas, TX",
    "973":"Newark, NJ","975":"Kansas City, MO","978":"Lowell, MA","979":"Bryan, TX",
    "980":"Charlotte, NC","984":"Raleigh, NC","985":"Houma, LA","986":"Boise, ID",
}

def location_intel(number: str) -> dict:
    """Detailed location from number: area code city lookup + prefix map."""
    result = {}
    digits = re.sub(r'\D', '', number)

    # US number (+1 AAAPPPXXXX)
    if number.startswith("+1") and len(digits) == 11:
        area = digits[1:4]
        exchange = digits[4:7]
        city = US_AREA_CODES.get(area)
        result["country"]       = "United States"
        result["area_code"]     = area
        result["exchange"]      = exchange
        result["number_format"] = f"+1 ({area}) {exchange}-{digits[7:]}"
        if city:
            result["area_code_city"] = city
            result["state"] = city.split(", ")[-1] if ", " in city else ""
        # NANP special number types
        if exchange in ("555",):
            result["type_hint"] = "Fictional/reserved (555)"
        elif area in ("800","833","844","855","866","877","888"):
            result["type_hint"] = "Toll-free"
        elif area == "900":
            result["type_hint"] = "Premium-rate"

    # UK (+44)
    elif number.startswith("+44"):
        uk_prefix = digits[2:4]
        uk_map = {
            "20":"London","121":"Birmingham","131":"Edinburgh","141":"Glasgow",
            "161":"Manchester","113":"Leeds","114":"Sheffield","115":"Nottingham",
            "116":"Leicester","117":"Bristol","118":"Reading","191":"Newcastle",
        }
        result["country"] = "United Kingdom"
        for pfx, city in uk_map.items():
            if digits[2:2+len(pfx)] == pfx:
                result["area_city"] = city
                break

    # Canada (+1, same NANP — distinguish by area code)
    elif number.startswith("+1"):
        ca_areas = {"204","226","236","249","250","289","306","343","365","387","403","416",
                    "418","431","437","438","450","506","514","519","548","579","581","587",
                    "604","613","639","647","672","705","709","742","778","780","782","807",
                    "819","825","867","873","902","905"}
        digits3 = digits[1:4]
        if digits3 in ca_areas:
            result["country"] = "Canada"
            result["area_code"] = digits3

    return result

def truecaller_scrape(number: str) -> dict:
    """Scrape Truecaller web search for caller ID info."""
    info = {"name": None, "spam_score": None, "tags": [], "raw_hits": []}
    clean = re.sub(r'\D', '', number)

    # 1. DDG site search for truecaller result
    q = f'site:truecaller.com "{number}" OR site:truecaller.com "{clean}"'
    hits = ddg_phone_search(q, 5)
    info["raw_hits"].extend(hits)

    # 2. Try to extract name from truecaller search page
    for url_tpl in [
        f"https://www.truecaller.com/search/us/{requests.utils.quote(number)}",
        f"https://www.truecaller.com/search/gb/{requests.utils.quote(number)}",
        f"https://www.truecaller.com/search/in/{requests.utils.quote(number)}",
    ]:
        try:
            r = SESS.get(url_tpl, timeout=7,
                         headers={"Accept": "text/html,application/xhtml+xml",
                                  "Accept-Language": "en-US,en;q=0.9"})
            if r.status_code == 200:
                # Try to extract name from OG tags or JSON-LD
                og_title = re.search(r'<meta property="og:title" content="([^"]+)"', r.text)
                if og_title:
                    title = og_title.group(1).strip()
                    if number.replace("+","") not in title.replace(" ","") and len(title) > 3:
                        info["name"] = title
                # Spam tags
                if "spam" in r.text.lower():
                    info["tags"].append("Spam flagged")
                if "telemarketer" in r.text.lower():
                    info["tags"].append("Telemarketer")
                if "scam" in r.text.lower():
                    info["tags"].append("Scam risk")
                break
        except:
            pass

    # 3. Also check sync.me and WhoCallsMe
    for site_q in [
        f'site:sync.me "{number}"',
        f'site:whocalledme.com "{clean}"',
        f'site:whycall.me "{clean}"',
        f'site:800notes.com "{clean}"',
        f'site:calleridtest.com "{clean}"',
    ]:
        hits = ddg_phone_search(site_q, 3)
        info["raw_hits"].extend(hits)

    return info

def google_dorks_search(number: str) -> dict:
    """Run targeted Google-dork style searches across platforms."""
    clean  = re.sub(r'\D', '', number)
    no_cc  = clean[1:] if len(clean) > 10 else clean  # strip country code digit
    local  = clean[-10:] if len(clean) >= 10 else clean

    dork_queries = {
        "Facebook":   f'site:facebook.com "{number}" OR site:facebook.com "{local}"',
        "LinkedIn":   f'site:linkedin.com "{number}" OR site:linkedin.com "{local}"',
        "Twitter/X":  f'site:twitter.com "{number}" OR site:x.com "{number}"',
        "Instagram":  f'site:instagram.com "{number}"',
        "TikTok":     f'site:tiktok.com "{number}"',
        "Reddit":     f'site:reddit.com "{number}"',
        "Craigslist": f'site:craigslist.org "{number}" OR site:craigslist.org "{local}"',
        "Yelp":       f'site:yelp.com "{number}" OR site:yelp.com "{local}"',
        "Google Maps":f'site:maps.google.com "{number}" OR "google.com/maps" "{local}"',
        "Pastebin":   f'site:pastebin.com "{number}" OR site:pastebin.com "{clean}"',
        "Ghostbin":   f'site:ghostbin.com "{number}" OR site:rentry.co "{number}"',
        "GitHub":     f'site:github.com "{number}" OR site:gist.github.com "{number}"',
        "Spokeo":     f'site:spokeo.com "{local}"',
        "Whitepages": f'site:whitepages.com "{local}"',
        "BeenVerified":f'site:beenverified.com "{local}"',
        "Intelius":   f'site:intelius.com "{local}"',
        "Zabasearch": f'site:zabasearch.com "{local}"',
    }

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        def do_dork(args):
            label, q = args
            hits = ddg_phone_search(q, 4)
            return label, hits
        for label, hits in ex.map(do_dork, dork_queries.items()):
            if hits:
                results[label] = hits
    return results

def paste_search(number: str) -> list:
    """Deep paste-site and leak-site search."""
    clean = re.sub(r'\D', '', number)
    queries = [
        f'"{number}" site:pastebin.com',
        f'"{clean}" site:pastebin.com',
        f'"{number}" site:ghostbin.com OR site:rentry.co OR site:paste.ee',
        f'"{number}" database leak OR dump filetype:txt OR filetype:csv',
        f'"{number}" dox OR doxxed',
        f'"{clean}" breached.to OR site:breachedforums.com',
        f'"{number}" personal info OR full info OR "fullz"',
    ]
    all_hits = []
    seen = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        for hits in ex.map(ddg_phone_search, queries):
            for h in (hits or []):
                url = h.get("href","")
                if url and url not in seen:
                    all_hits.append(h)
                    seen.add(url)
    return all_hits

def voip_check(number: str, carrier_data: dict) -> dict:
    """Detect VoIP and find associated provider/IP range."""
    info = {"is_voip": False, "provider": None, "ip_ranges": [], "notes": []}

    # Check carrier data for VoIP indicators
    carrier_str = json.dumps(carrier_data).lower()
    voip_keywords = ["voip","google","twilio","bandwidth","vonage","magicjack",
                     "lingo","skype","ringcentral","ooma","grasshopper","TextNow",
                     "textnow","peerless","level 3","lumen","telnyx","signalwire"]
    for kw in voip_keywords:
        if kw in carrier_str:
            info["is_voip"] = True
            info["provider"] = kw.title()
            break

    # Check line type
    lt = carrier_data.get("phone_type","") or carrier_data.get("line_type","")
    if lt and "voip" in lt.lower():
        info["is_voip"] = True

    # Known VoIP providers + their IP ranges / ASN info
    voip_providers = {
        "Google Voice": {"asn": "AS15169", "ip_ranges": ["74.125.0.0/16","64.233.160.0/19"], "note": "Google Voice numbers are virtual, caller may be anywhere"},
        "Twilio":       {"asn": "AS54208", "ip_ranges": ["54.172.60.0/23","34.203.0.0/16"],  "note": "Twilio is a programmable telecom API platform"},
        "Bandwidth":    {"asn": "AS29838", "ip_ranges": ["216.82.224.0/20"],                  "note": "Major US VoIP carrier"},
        "TextNow":      {"asn": "AS54958", "ip_ranges": [],                                   "note": "Free US/CA VoIP app — anonymous"},
        "Vonage":       {"asn": "AS29838", "ip_ranges": ["174.136.0.0/21"],                   "note": "Vonage/Ericsson VoIP"},
        "Magicjack":    {"asn": "AS10835", "ip_ranges": ["67.0.0.0/11"],                      "note": "Consumer VoIP device"},
        "Ooma":         {"asn": "AS46375", "ip_ranges": ["67.231.240.0/20"],                  "note": "Consumer/business VoIP"},
        "Telnyx":       {"asn": "AS396171","ip_ranges": ["192.168.0.0/16"],                   "note": "Developer-focused VoIP API"},
    }

    if info["is_voip"] and info["provider"]:
        for name, pdata in voip_providers.items():
            if info["provider"].lower() in name.lower() or name.lower() in carrier_str:
                info["provider"]  = name
                info["ip_ranges"] = pdata["ip_ranges"]
                info["asn"]       = pdata["asn"]
                info["notes"].append(pdata["note"])
                break

    if info["is_voip"]:
        info["notes"].append("VoIP numbers do NOT have a fixed IP — the user's real IP is on their internet connection, not tied to the number")
        info["notes"].append("If the number was used to send messages/calls via app, the platform may have IP logs (requires legal process to obtain)")

    return info

def ipapi_country_from_phone(number: str) -> dict:
    prefix_map = {
        "+1": ("US/CA", "North America"), "+44": ("UK", "Europe"),
        "+61": ("Australia", "Oceania"), "+49": ("Germany", "Europe"),
        "+33": ("France", "Europe"), "+39": ("Italy", "Europe"),
        "+34": ("Spain", "Europe"), "+7": ("Russia/KZ", "Europe/Asia"),
        "+81": ("Japan", "Asia"), "+82": ("South Korea", "Asia"),
        "+86": ("China", "Asia"), "+91": ("India", "Asia"),
        "+55": ("Brazil", "South America"), "+52": ("Mexico", "North America"),
        "+27": ("South Africa", "Africa"), "+234": ("Nigeria", "Africa"),
        "+20": ("Egypt", "Africa"), "+971": ("UAE", "Middle East"),
        "+966": ("Saudi Arabia", "Middle East"), "+90": ("Turkey", "Europe/Asia"),
        "+31": ("Netherlands", "Europe"), "+46": ("Sweden", "Europe"),
        "+47": ("Norway", "Europe"), "+45": ("Denmark", "Europe"),
        "+41": ("Switzerland", "Europe"), "+43": ("Austria", "Europe"),
        "+32": ("Belgium", "Europe"), "+48": ("Poland", "Europe"),
        "+30": ("Greece", "Europe"), "+351": ("Portugal", "Europe"),
        "+92": ("Pakistan", "Asia"), "+880": ("Bangladesh", "Asia"),
        "+94": ("Sri Lanka", "Asia"), "+62": ("Indonesia", "Asia"),
        "+60": ("Malaysia", "Asia"), "+63": ("Philippines", "Asia"),
        "+66": ("Thailand", "Asia"), "+84": ("Vietnam", "Asia"),
    }
    for prefix, (country, region) in sorted(prefix_map.items(), key=lambda x: -len(x[0])):
        if number.startswith(prefix):
            return {"country": country, "region": region, "prefix": prefix}
    return {}

def ddg_phone_search(query: str, n: int = 8) -> list:
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

def bing_phone_search(query: str, n: int = 8) -> list:
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
    except: return []

def google_phone_search(query: str, n: int = 8) -> list:
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
    except: return []

def multi_phone_search(query: str) -> list:
    seen, combined = set(), []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futs = [ex.submit(f, query, 5) for f in [ddg_phone_search, bing_phone_search, google_phone_search]]
        for fut in concurrent.futures.as_completed(futs):
            for r in (fut.result() or []):
                url = r.get("href","")
                if url and url not in seen:
                    combined.append(r); seen.add(url)
    return combined

def check_truecaller_web(number: str) -> list:
    queries = [
        f'site:truecaller.com "{number}"',
        f'site:sync.me "{number}"',
        f'site:spokeo.com "{number}"',
        f'site:whitepages.com "{number}"',
    ]
    results = []
    for q in queries:
        hits = ddg_phone_search(q, 3)
        results.extend(hits)
    return results

def check_social_platforms(number: str) -> dict:
    found = {}
    clean = re.sub(r'\D', '', number)
    queries = {
        "WhatsApp":  f'wa.me/{clean} OR "whatsapp.com/send?phone={clean}"',
        "Telegram":  f'site:t.me phone {number} OR t.me/+{clean}',
        "Facebook":  f'site:facebook.com "{number}"',
        "Snapchat":  f'site:snapchat.com "{number}"',
        "LinkedIn":  f'site:linkedin.com "{number}"',
        "Instagram": f'site:instagram.com "{number}"',
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        def search_social(args):
            platform, q = args
            hits = ddg_phone_search(q, 3)
            return platform, hits
        for platform, hits in ex.map(search_social, queries.items()):
            if hits:
                found[platform] = hits
    return found

def search_breach_by_phone(number: str) -> list:
    queries = [
        f'"{number}" site:pastebin.com OR site:ghostbin.com',
        f'"{number}" leak OR breach OR dump OR database',
        f'"{number}" name OR email OR address',
    ]
    all_hits = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for hits in ex.map(multi_phone_search, queries):
            all_hits.extend(hits)
    return all_hits

def ai_analyze_phone(number: str, data: dict) -> str:
    if not API_KEY:
        return "AI analysis unavailable — add your OpenRouter key to osint_config.json"

    loc      = data.get("location_intel", {})
    tc       = data.get("truecaller", {})
    voip     = data.get("voip_info", {})
    dorks    = data.get("dork_results", {})
    pastes   = data.get("paste_hits", [])

    prompt = f"""You are VOID, an elite OSINT analyst. Analyze this phone number intelligence data and produce a professional threat report.

PHONE NUMBER: {number}

CARRIER DATA: {json.dumps(data.get("carrier_data", {}), indent=2)}
PREFIX INTEL: {json.dumps(data.get("prefix_intel", {}), indent=2)}
LOCATION INTEL: {json.dumps(loc, indent=2)}
TRUECALLER: name={tc.get("name")}, tags={tc.get("tags")}, hits={len(tc.get("raw_hits",[]))}
VOIP: is_voip={voip.get("is_voip")}, provider={voip.get("provider")}, notes={voip.get("notes",[])}
SOCIAL HITS: {list(data.get("social_hits", {}).keys())}
DORK HITS (platforms with results): {list(dorks.keys())}
WEB RESULTS COUNT: {sum(len(v) for v in data.get("web_results", {}).values())}
REVERSE LOOKUP HITS: {len(data.get("reverse_lookup", []))}
BREACH HITS: {len(data.get("breach_hits", []))}
PASTE/LEAK HITS: {len(pastes)}

Write using EXACTLY this structure:

**RISK LEVEL:** [CRITICAL / HIGH / MEDIUM / LOW] — one sentence why

**NUMBER INTEL**
- Line type, carrier, country, city (from location intel), VoIP status

**TRUECALLER / CALLER ID**
- Name found (if any), spam flags, community tags

**WHAT WAS FOUND**
- Bullet every significant hit: social platforms, dork results, paste sites, reverse lookup, breach references

**VOIP & IP NOTE**
- If VoIP: explain you cannot get IP from a phone number, but note the provider and what that means

**WHAT AN ATTACKER CAN DO**
Realistic step-by-step attack chain using only this phone number as starting point.

**IDENTITY RECONSTRUCTION POTENTIAL**
How much of a full identity can be built from this number alone?

**IMMEDIATE ACTIONS**
1-5 specific steps to protect this number's exposure.

Be direct, specific, max 450 words."""

    try:
        r = requests.post(OPENROUTER,
            headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json",
                     "HTTP-Referer": "https://phone-osint.local", "X-Title": "VOID Phone Intel"},
            json={"model": MODEL, "messages": [{"role":"user","content":prompt}], "temperature": 0.3},
            timeout=40)
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"AI failed: {e}"

def run_phone_scan(number: str) -> dict:
    results = {
        "number":        number,
        "carrier_data":  {},
        "prefix_intel":  {},
        "location_intel":{},
        "truecaller":    {},
        "voip_info":     {},
        "social_hits":   {},
        "web_results":   {},
        "dork_results":  {},
        "reverse_lookup":[],
        "breach_hits":   [],
        "paste_hits":    [],
        "ai_analysis":   "",
        "scan_duration": ""
    }

    web_queries = [
        (f'"{number}"',                               "Direct Number Search"),
        (f'"{number}" name OR owner OR person',       "Owner Search"),
        (f'"{number}" address OR location OR city',   "Location Search"),
        (f'"{number}" email OR contact',              "Contact Search"),
        (f'"{number}" scam OR spam OR fraud',         "Scam Reports"),
        (f'"{number}" whois OR registered OR carrier',"Registration Info"),
    ]

    total = len(web_queries) + 3   # phase1 + web_queries + phase3 + phase4
    with Progress(
        SpinnerColumn(spinner_name="dots12", style="bright_cyan"),
        TextColumn("[bright_cyan]{task.description:<55}"),
        BarColumn(bar_width=20, style="cyan", complete_style="bright_cyan"),
        TextColumn("[dim white]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console, transient=True
    ) as prog:
        task = prog.add_task("Initializing...", total=total)

        # Phase 1 — carrier + location (parallel)
        prog.update(task, description="[bright_cyan]⟳  Carrier lookup + location intel...")
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
                f1 = ex.submit(veriphone_lookup, number)
                f2 = ex.submit(numverify_lookup, number)
                f3 = ex.submit(ipapi_country_from_phone, number)
                f4 = ex.submit(location_intel, number)
                r1 = f1.result() or {}
                r2 = f2.result() or {}
                results["carrier_data"]   = r1 or r2
                results["prefix_intel"]   = f3.result() or {}
                results["location_intel"] = f4.result() or {}
            results["voip_info"] = voip_check(number, results["carrier_data"])
        except Exception as e:
            results["carrier_data"]   = {"error": str(e)}
        prog.advance(task)

        # Phase 2 — web searches (parallel)
        prog.update(task, description="[bright_cyan]⟳  Multi-engine web search (6 queries × 3 engines)...")
        def search_one(args):
            try:
                query, label = args
                return label, multi_phone_search(query)
            except Exception:
                return args[1], []
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
                for label, hits in ex.map(search_one, web_queries):
                    if hits:
                        results["web_results"][label] = hits
                    prog.advance(task)
                    time.sleep(0.05)
        except Exception:
            for _ in web_queries:
                prog.advance(task)

        # Phase 3 — reverse lookup + social + Truecaller + dorks + paste (all parallel)
        prog.update(task, description="[bright_cyan]⟳  Truecaller + reverse lookup + social + dorks + paste...")
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
                f_rev    = ex.submit(check_truecaller_web, number)
                f_tc     = ex.submit(truecaller_scrape, number)
                f_social = ex.submit(check_social_platforms, number)
                f_breach = ex.submit(search_breach_by_phone, number)
                f_dork   = ex.submit(google_dorks_search, number)
                f_paste  = ex.submit(paste_search, number)
                concurrent.futures.wait([f_rev, f_tc, f_social, f_breach, f_dork, f_paste])

            def safe_result(fut, default):
                try: return fut.result() or default
                except Exception: return default

            results["reverse_lookup"] = safe_result(f_rev,    [])
            results["truecaller"]     = safe_result(f_tc,     {"name":None,"tags":[],"raw_hits":[]})
            results["social_hits"]    = safe_result(f_social, {})
            results["breach_hits"]    = safe_result(f_breach, [])
            results["dork_results"]   = safe_result(f_dork,   {})
            results["paste_hits"]     = safe_result(f_paste,  [])
        except Exception as e:
            console.print(f"  [dim yellow]Phase 3 partial failure: {e}[/dim yellow]")
        prog.advance(task)

        # Phase 4 — AI
        prog.update(task, description="[bright_cyan]⟳  AI threat analysis...")
        try:
            results["ai_analysis"] = ai_analyze_phone(number, results)
        except Exception as e:
            results["ai_analysis"] = f"AI analysis failed: {e}"
        prog.advance(task)

    return results

# ── HTML Report ───────────────────────────────────────────────────────────────

def build_html_report(number: str, data: dict) -> str:
    ts       = datetime.now().strftime("%B %d, %Y — %H:%M:%S")
    duration = data.get("scan_duration","?")
    carrier  = data.get("carrier_data",{})
    prefix   = data.get("prefix_intel",{})
    loc      = data.get("location_intel",{})
    tc       = data.get("truecaller",{})
    voip     = data.get("voip_info",{})
    social   = data.get("social_hits",{})
    web      = data.get("web_results",{})
    dorks    = data.get("dork_results",{})
    rev      = data.get("reverse_lookup",[])
    breach   = data.get("breach_hits",[])
    pastes   = data.get("paste_hits",[])
    ai_text  = data.get("ai_analysis","")
    total_hits   = sum(len(v) for v in web.values())
    total_dorks  = sum(len(v) for v in dorks.values())

    def esc(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    def stat_box(label, value, color):
        return f'<div class="stat-box" style="border-color:{color}"><div class="stat-val" style="color:{color}">{esc(str(value))}</div><div class="stat-label">{esc(label)}</div></div>'

    stats = (
        stat_box("NUMBER",       number,                                         "#22d3ee") +
        stat_box("WEB HITS",     total_hits,                                     "#a855f7") +
        stat_box("DORK HITS",    total_dorks,                                    "#818cf8") +
        stat_box("SOCIAL HITS",  len(social),                                    "#22c55e") +
        stat_box("REVERSE HITS", len(rev),                                       "#f59e0b") +
        stat_box("PASTE HITS",   len(pastes),     "#ef4444" if pastes  else "#22c55e") +
        stat_box("BREACH HITS",  len(breach),     "#ef4444" if breach  else "#22c55e") +
        stat_box("VoIP",         "YES" if voip.get("is_voip") else "NO",        "#f59e0b" if voip.get("is_voip") else "#22c55e") +
        stat_box("SCAN TIME",    duration,                                       "#67e8f9")
    )

    # Carrier table
    carrier_rows = ""
    fields_map = [
        ("phone","Number"),("phone_valid","Valid"),("phone_type","Line Type"),
        ("phone_region","Region"),("country","Country"),("country_code","Country Code"),
        ("carrier","Carrier"),("carrier_type","Carrier Type"),
        ("line_type","Line Type Detail"),("national_number","National Format"),
        ("international_number","International Format"),
    ]
    for key, label in fields_map:
        val = carrier.get(key) or carrier.get(key.replace("phone_",""))
        if val and str(val).lower() not in ("none","null","false",""):
            carrier_rows += f'<tr><td class="label">{esc(label)}</td><td>{esc(str(val))}</td></tr>'
    for key, label in [("country","Country"),("region","Region"),("prefix","Dialing Prefix")]:
        val = prefix.get(key)
        if val and not carrier.get("country"):
            carrier_rows += f'<tr><td class="label">{esc(label)} (prefix)</td><td>{esc(str(val))}</td></tr>'

    carrier_html = f'<section><h2 class="sec-title cyan">◈ CARRIER INTELLIGENCE</h2><table class="info-table">{carrier_rows if carrier_rows else "<tr><td>No carrier data retrieved (demo API limits apply)</td></tr>"}</table></section>'

    # ── Key Findings ───────────────────────────────────────────────────────────
    kf_items = []
    if tc.get("name"):
        kf_items.append(("✔", f"CALLER ID NAME: {tc['name']}", "#22c55e"))
    if tc.get("tags"):
        kf_items.append(("⚠", f"SPAM FLAGS: {', '.join(tc['tags'])}", "#ef4444"))
    if voip.get("is_voip"):
        kf_items.append(("⚠", f"VoIP NUMBER — Provider: {voip.get('provider','Unknown')}", "#f59e0b"))
    if loc.get("area_code_city"):
        kf_items.append(("◈", f"AREA CODE ORIGIN: {loc['area_code_city']}", "#22d3ee"))
    if loc.get("country"):
        kf_items.append(("◈", f"COUNTRY: {loc['country']}", "#22d3ee"))
    if pastes:
        kf_items.append(("⚠", f"FOUND ON {len(pastes)} PASTE/LEAK SITE(S)", "#ef4444"))
    if breach:
        kf_items.append(("⚠", f"FOUND IN {len(breach)} BREACH/LEAK RESULT(S)", "#ef4444"))
    if social:
        kf_items.append(("✔", f"LINKED TO {len(social)} SOCIAL PLATFORM(S): {', '.join(social.keys())}", "#22c55e"))
    if total_hits:
        kf_items.append(("◈", f"{total_hits} WEB RESULTS · {total_dorks} DORK HITS", "#a855f7"))
    if not kf_items:
        kf_items.append(("—", "No significant findings — number may be private or inactive", "#64748b"))

    kf_html = '<div class="findings-grid">'
    for icon, text, color in kf_items:
        kf_html += f'<div class="finding-card" style="border-left:4px solid {color}"><span class="finding-icon" style="color:{color}">{icon}</span><span class="finding-text">{esc(text)}</span></div>'
    kf_html += '</div>'
    key_findings_html = f'<section class="key-findings"><h2 class="sec-title cyan">◈ KEY FINDINGS</h2>{kf_html}</section>'

    # ── Location Intel ─────────────────────────────────────────────────────────
    loc_rows = ""
    loc_fields = [
        ("number_format","Formatted Number"),("country","Country"),("state","State"),
        ("area_code","Area Code"),("area_code_city","Area Code City"),
        ("exchange","Exchange (NXX)"),("type_hint","Number Type"),("area_city","City"),
    ]
    for key, label in loc_fields:
        val = loc.get(key)
        if val:
            loc_rows += f'<tr><td class="label">{esc(label)}</td><td>{esc(str(val))}</td></tr>'
    if prefix:
        for key, label in [("country","Country (prefix)"),("region","Region (prefix)"),("prefix","Dialing Prefix")]:
            val = prefix.get(key)
            if val and not loc.get("country"):
                loc_rows += f'<tr><td class="label">{esc(label)}</td><td>{esc(str(val))}</td></tr>'
    location_html = f'<section><h2 class="sec-title cyan">◈ LOCATION INTELLIGENCE</h2><table class="info-table">{loc_rows if loc_rows else "<tr><td>No granular location data available for this number.</td></tr>"}</table></section>'

    # ── Truecaller / Caller ID ─────────────────────────────────────────────────
    tc_name  = tc.get("name")
    tc_tags  = tc.get("tags", [])
    tc_hits  = tc.get("raw_hits", [])
    tc_inner = ""
    if tc_name:
        tc_inner += f'<div class="alert" style="background:rgba(34,197,94,.1);border:1px solid #22c55e;color:#22c55e;margin-bottom:12px">✔ Caller ID name found: <b>{esc(tc_name)}</b></div>'
    if tc_tags:
        badges_html = " ".join(f'<span style="background:#ef4444;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;margin-right:4px">{esc(t)}</span>' for t in tc_tags)
        tc_inner += f'<div style="margin-bottom:12px">Community flags: {badges_html}</div>'
    if tc_hits:
        tc_inner += f'<p class="sub">{len(tc_hits)} reference(s) found across lookup sites</p><div class="hit-list">'
        for i, h in enumerate(tc_hits[:8], 1):
            title = esc((h.get("title") or h.get("href","")).strip())
            url   = esc((h.get("href") or "").strip())
            tc_inner += f'<div class="hit"><div class="hit-num">[{i}]</div><div class="hit-content"><div class="hit-title">{title}</div>{"<a class=hit-url href=" + chr(39) + url + chr(39) + " target=_blank>" + url + "</a>" if url else ""}</div></div>'
        tc_inner += '</div>'
    if not tc_name and not tc_tags and not tc_hits:
        tc_inner = '<p class="none">No caller ID or community data found.</p>'
    truecaller_html = f'<section><h2 class="sec-title yellow">◈ TRUECALLER / CALLER ID</h2>{tc_inner}</section>'

    # ── VoIP Detection ─────────────────────────────────────────────────────────
    voip_inner = ""
    if voip.get("is_voip"):
        voip_inner += f'<div class="alert red-alert">⚠ VoIP NUMBER DETECTED — Provider: {esc(voip.get("provider","Unknown"))}</div>'
        if voip.get("ip_ranges"):
            voip_inner += f'<p class="sub" style="margin:8px 0">Provider IP ranges (infrastructure only — not caller IP):</p>'
            voip_inner += '<table class="info-table"><tr><th>IP Range</th><th>Notes</th></tr>'
            for rng in voip.get("ip_ranges",[]):
                voip_inner += f'<tr><td class="label">{esc(rng)}</td><td>Provider infrastructure</td></tr>'
            voip_inner += '</table>'
        if voip.get("asn"):
            voip_inner += f'<p style="margin-top:8px;color:#94a3b8">ASN: {esc(voip.get("asn",""))}</p>'
        for note in voip.get("notes",[]):
            voip_inner += f'<p style="margin-top:8px;color:#f59e0b">⚠ {esc(note)}</p>'
    else:
        voip_inner = '<div class="alert green-alert">✔ Not detected as VoIP — appears to be a standard mobile/landline number.</div>'
        voip_inner += '<p style="margin-top:8px;color:#94a3b8;font-size:12px">Note: Phone numbers do not have IP addresses. Only VoIP services have associated IP ranges (the provider infrastructure, not the caller).</p>'
    voip_html = f'<section><h2 class="sec-title red">◈ VoIP DETECTION & IP NOTE</h2>{voip_inner}</section>'

    def hit_row(i, hit):
        title = esc((hit.get("title") or hit.get("href","")).strip())
        url   = esc((hit.get("href") or "").strip())
        body  = esc((hit.get("body") or "").strip())
        url_tag  = f'<a class="hit-url" href="{url}" target="_blank">{url}</a>' if url else ""
        body_tag = f'<div class="hit-body">{body}</div>' if body else ""
        return f'<div class="hit"><div class="hit-num">[{i}]</div><div class="hit-content"><div class="hit-title">{title}</div>{url_tag}{body_tag}</div></div>'

    # ── Google Dorks ───────────────────────────────────────────────────────────
    dork_html = f'<section><h2 class="sec-title purple">◈ PLATFORM DORK SEARCH</h2><p class="sub">{total_dorks} results across {len(dorks)} platforms with hits</p>'
    if dorks:
        for plat, hits in dorks.items():
            dork_html += f'<div class="web-category"><h3 class="cat-title">## {esc(plat)} <span class="cnt">({len(hits)})</span></h3><div class="hit-list">'
            for i, hit in enumerate(hits, 1):
                dork_html += hit_row(i, hit)
            dork_html += '</div></div>'
    else:
        dork_html += '<p class="none">No platform-specific results found via dork searches.</p>'
    dork_html += '</section>'

    # ── Paste / Leak Sites ──────────────────────────────────────────────────────
    paste_html = '<section><h2 class="sec-title red">◈ PASTE & LEAK SITES</h2>'
    if pastes:
        paste_html += f'<div class="alert red-alert">⚠ {len(pastes)} RESULT(S) FOUND ON PASTE/LEAK SITES</div><div class="hit-list">'
        for i, hit in enumerate(pastes, 1):
            paste_html += hit_row(i, hit)
        paste_html += '</div>'
    else:
        paste_html += '<div class="alert green-alert">✔ Number not found on paste or leak sites.</div>'
    paste_html += '</section>'

    # Web results
    web_html = f'<section><h2 class="sec-title purple">◈ WEB INTELLIGENCE</h2><p class="sub">{total_hits} results · 3 search engines</p>'
    for label, hits in web.items():
        web_html += f'<div class="web-category"><h3 class="cat-title">## {esc(label)} <span class="cnt">({len(hits)})</span></h3><div class="hit-list">'
        for i, hit in enumerate(hits, 1):
            web_html += hit_row(i, hit)
        web_html += '</div></div>'
    web_html += '</section>'

    # Reverse lookup
    rev_html = '<section><h2 class="sec-title yellow">◈ REVERSE LOOKUP</h2>'
    if rev:
        rev_html += '<div class="hit-list">'
        for i, hit in enumerate(rev, 1):
            rev_html += hit_row(i, hit)
        rev_html += '</div>'
    else:
        rev_html += '<p class="none">No reverse lookup results found.</p>'
    rev_html += '</section>'

    # Social
    social_html = f'<section><h2 class="sec-title green">◈ SOCIAL PLATFORM HITS</h2>'
    if social:
        for platform, hits in social.items():
            social_html += f'<div class="web-category"><h3 class="cat-title">## {esc(platform)} <span class="cnt found">({len(hits)} hits)</span></h3><div class="hit-list">'
            for i, hit in enumerate(hits, 1):
                social_html += hit_row(i, hit)
            social_html += '</div></div>'
    else:
        social_html += '<p class="none">No social platform hits found.</p>'
    social_html += '</section>'

    # Breach
    breach_html = '<section><h2 class="sec-title red">◈ BREACH & PASTE RESULTS</h2>'
    if breach:
        breach_html += f'<div class="alert red-alert">⚠ {len(breach)} RESULT(S) FOUND IN BREACH/PASTE SEARCHES</div><div class="hit-list">'
        for i, hit in enumerate(breach, 1):
            breach_html += hit_row(i, hit)
        breach_html += '</div>'
    else:
        breach_html += '<div class="alert green-alert">✔ No breach or paste results found.</div>'
    breach_html += '</section>'

    # AI
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

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VOID Phone Intel — {esc(number)}</title>
<style>
  :root{{--bg:#0a0a0f;--bg2:#111118;--bg3:#1a1a24;--border:#2a2a3a;--purple:#a855f7;--cyan:#22d3ee;--red:#ef4444;--green:#22c55e;--yellow:#f59e0b;--white:#f1f5f9;--dim:#64748b;}}
  *{{box-sizing:border-box;margin:0;padding:0;}}
  body{{background:var(--bg);color:var(--white);font-family:'Courier New',monospace;font-size:14px;line-height:1.6;}}
  a{{color:var(--cyan);text-decoration:none;}} a:hover{{text-decoration:underline;}}
  .header{{background:linear-gradient(135deg,#0a0f1a,#0a1a2e,#0a0f1a);padding:48px 40px 32px;border-bottom:1px solid var(--border);text-align:center;}}
  .header pre{{font-size:10px;line-height:1.2;background:linear-gradient(180deg,#22d3ee,#a855f7,#22d3ee);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;display:inline-block;}}
  .header-num{{font-size:32px;font-weight:bold;color:var(--cyan);letter-spacing:8px;margin-top:12px;}}
  .header-sub{{color:var(--purple);letter-spacing:4px;font-size:11px;margin-top:8px;}}
  .header-meta{{color:var(--dim);font-size:12px;margin-top:8px;}}
  .container{{max-width:1100px;margin:0 auto;padding:32px 24px;}}
  .stats{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:32px;}}
  .stat-box{{flex:1;min-width:120px;background:var(--bg2);border:1px solid;border-radius:8px;padding:16px 12px;text-align:center;}}
  .stat-val{{font-size:22px;font-weight:bold;margin-bottom:4px;word-break:break-all;}}
  .stat-label{{font-size:10px;letter-spacing:2px;color:var(--dim);}}
  section{{margin-bottom:40px;}}
  .sec-title{{font-size:13px;letter-spacing:3px;padding:10px 0;margin-bottom:16px;border-bottom:1px solid var(--border);}}
  .sec-title.purple{{color:var(--purple);border-color:var(--purple);}}
  .sec-title.cyan{{color:var(--cyan);border-color:var(--cyan);}}
  .sec-title.green{{color:var(--green);border-color:var(--green);}}
  .sec-title.yellow{{color:var(--yellow);border-color:var(--yellow);}}
  .sec-title.red{{color:var(--red);border-color:var(--red);}}
  .sub{{color:var(--dim);font-size:12px;margin-bottom:16px;}}
  .info-table{{width:100%;border-collapse:collapse;background:var(--bg2);border-radius:8px;overflow:hidden;}}
  .info-table th{{background:var(--bg3);color:var(--cyan);padding:10px 14px;text-align:left;font-size:11px;letter-spacing:1px;border-bottom:1px solid var(--border);}}
  .info-table td{{padding:9px 14px;border-bottom:1px solid var(--border);}}
  .info-table tr:last-child td{{border-bottom:none;}}
  .info-table tr:hover td{{background:var(--bg3);}}
  td.label{{color:var(--cyan);font-size:11px;letter-spacing:1px;width:160px;white-space:nowrap;}}
  .web-category{{margin-bottom:20px;background:var(--bg2);border-radius:8px;overflow:hidden;border:1px solid var(--border);}}
  .cat-title{{padding:10px 16px;background:var(--bg3);color:var(--cyan);font-size:12px;letter-spacing:1px;border-bottom:1px solid var(--border);}}
  .cnt{{color:var(--dim);}} .found{{color:var(--green);}}
  .hit-list{{padding:8px 0;}}
  .hit{{display:flex;gap:12px;padding:10px 16px;border-bottom:1px solid var(--border);}}
  .hit:last-child{{border-bottom:none;}} .hit:hover{{background:var(--bg3);}}
  .hit-num{{color:var(--purple);min-width:28px;font-size:12px;}}
  .hit-content{{flex:1;min-width:0;}}
  .hit-title{{color:var(--white);margin-bottom:2px;word-break:break-word;}}
  .hit-url{{color:var(--cyan);font-size:12px;word-break:break-all;display:block;margin-bottom:2px;}}
  .hit-body{{color:var(--dim);font-size:12px;word-break:break-word;}}
  .alert{{padding:12px 18px;border-radius:6px;font-weight:bold;margin-bottom:16px;}}
  .red-alert{{background:rgba(239,68,68,.12);border:1px solid var(--red);color:var(--red);}}
  .green-alert{{background:rgba(34,197,94,.1);border:1px solid var(--green);color:var(--green);}}
  .ai-box{{background:var(--bg2);border:1px solid var(--purple);border-radius:8px;padding:24px 28px;}}
  .ai-risk{{color:var(--red);font-weight:bold;font-size:16px;margin-bottom:12px;}}
  .ai-header{{color:var(--cyan);font-weight:bold;margin-top:16px;margin-bottom:6px;}}
  .ai-bullet{{color:var(--white);padding-left:16px;margin-bottom:4px;}}
  .ai-body{{color:#cbd5e1;margin-bottom:4px;}}
  .footer{{text-align:center;padding:32px;color:var(--dim);font-size:11px;letter-spacing:2px;border-top:1px solid var(--border);}}
  .key-findings{{margin-bottom:40px;}}
  .findings-grid{{display:flex;flex-direction:column;gap:10px;}}
  .finding-card{{display:flex;align-items:center;gap:16px;background:var(--bg2);border-radius:8px;padding:14px 20px;border-left-width:4px;border-left-style:solid;}}
  .finding-icon{{font-size:20px;flex-shrink:0;width:24px;text-align:center;}}
  .finding-text{{font-size:13px;font-weight:700;letter-spacing:1.5px;color:var(--white);}}
</style>
</head>
<body>
<div class="header">
  <pre>
 ____  _   _  ___  _   _  _____   ___  _   _  _____  _____  _     
|  _ \| | | |/ _ \| \ | ||  ___| |_ _|| \ | ||_   _|| ____|| |    
| |_) | |_| | | | |  \| || |__    | | |  \| |  | |  |  _|  | |    
|  __/|  _  | |_| | |\  ||  __|   | | | |\  |  | |  | |___ | |___ 
|_|   |_| |_|\___/|_| \_||_|     |___||_| \_|  |_|  |_____||_____|
  </pre>
  <div class="header-num">{esc(number)}</div>
  <div class="header-sub">PHONE NUMBER INTELLIGENCE REPORT</div>
  <div class="header-meta">by @lfw.k4rma_ &nbsp;|&nbsp; {ts} &nbsp;|&nbsp; Duration: {esc(duration)}</div>
</div>
<div class="container">
  <div class="stats">{stats}</div>
  {key_findings_html}
  {carrier_html}
  {location_html}
  {truecaller_html}
  {voip_html}
  {web_html}
  {dork_html}
  {rev_html}
  {social_html}
  {paste_html}
  {breach_html}
  {ai_html}
</div>
<div class="footer">VOID Phone Intel &nbsp;◈&nbsp; by @lfw.k4rma_ &nbsp;◈&nbsp; FOR AUTHORIZED USE ONLY</div>
</body>
</html>'''

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    banner()

    if not API_KEY:
        console.print(Panel(
            "[yellow]No API key configured.[/yellow]\n"
            "Edit [bright_cyan]osint_config.json[/bright_cyan] and add your OpenRouter key.",
            title="[bold yellow]⚠  AI Disabled[/bold yellow]", border_style="yellow"
        ))
        console.print()

    console.print(Panel(
        "[bright_white]Enter a phone number to investigate.\n"
        "[dim]Include country code for best results.\n"
        "Examples:  +447911123456   +12125551234   +971501234567[/dim][/bright_white]",
        title="[bold bright_cyan]  ◈ PHONE NUMBER INPUT ◈  [/bold bright_cyan]",
        border_style="bright_cyan"
    ))
    console.print()
    console.print("  [bright_cyan]›[/bright_cyan] [bold white]Phone Number[/bold white] [dim](with country code, e.g. +447911123456)[/dim]: ", end="")
    raw = input().strip()

    if not raw:
        console.print("\n  [red]No number entered. Exiting.[/red]\n")
        return

    number = clean_number(raw)
    if not number.startswith("+"):
        number = "+" + number

    console.print()
    console.print(Panel(
        f"  [bright_cyan]Number:[/bright_cyan]  [bold white]{number}[/bold white]",
        title="[bold cyan]  ◈ TARGET ◈  [/bold cyan]", border_style="cyan"
    ))
    console.print()
    console.print(f"  [bright_cyan]›[/bright_cyan] [bold white]Start scan?[/bold white] [dim](Y/N)[/dim] ", end="")
    if input().strip().lower() != "y":
        console.print("\n  [dim]Cancelled.[/dim]\n")
        return

    # Estimate time
    est = "~1m 30s"
    console.print()
    console.print(Panel(
        f"  [bright_cyan]Queries:[/bright_cyan]    [white]6 web searches × 3 engines[/white]\n"
        f"  [bright_cyan]Checks:[/bright_cyan]     [white]Carrier · Reverse · Social × 6 · Breach[/white]\n"
        f"  [bright_cyan]Est. time:[/bright_cyan]  [bold bright_cyan]{est}[/bold bright_cyan]",
        title="[bold bright_cyan]  ◈ SCAN PREVIEW ◈  [/bold bright_cyan]", border_style="bright_cyan"
    ))

    console.print()
    console.print(Rule("[bold bright_cyan]  ◈ SCANNING — CARRIER · REVERSE LOOKUP · SOCIAL · BREACH · AI ◈  [/bold bright_cyan]", style="bright_cyan"))
    console.print()

    start = time.time()
    results = run_phone_scan(number)
    elapsed = time.time() - start
    results["scan_duration"] = f"{elapsed:.1f}s"

    # ── Full terminal display ─────────────────────────────────────────────
    try:
        total_hits  = sum(len(v) for v in results.get("web_results",{}).values())
        total_dorks = sum(len(v) for v in results.get("dork_results",{}).values())
        voip  = results.get("voip_info",{})
        tc    = results.get("truecaller",{})
        loc   = results.get("location_intel",{})
        carrier = results.get("carrier_data",{})
        web   = results.get("web_results",{})
        dorks = results.get("dork_results",{})
        rev   = results.get("reverse_lookup",[])
        social= results.get("social_hits",{})
        pastes= results.get("paste_hits",[])
        breach= results.get("breach_hits",[])
        ai_text = results.get("ai_analysis","")

        console.print()
        console.print(Rule("[bold bright_cyan]  ◈ SCAN RESULTS ◈  [/bold bright_cyan]", style="bright_cyan"))
        console.print()

        # Stat boxes
        boxes = [
            stat_box("WEB HITS",    str(total_hits),               "bright_cyan"),
            stat_box("DORK HITS",   str(total_dorks),              "bright_magenta"),
            stat_box("SOCIAL HITS", str(len(social)),              "bright_magenta"),
            stat_box("REV. HITS",   str(len(rev)),                 "yellow"),
            stat_box("PASTE HITS",  str(len(pastes)),  "bright_red" if pastes  else "green"),
            stat_box("BREACHES",    str(len(breach)),  "bright_red" if breach  else "green"),
            stat_box("VoIP",        "YES" if voip.get("is_voip") else "NO", "yellow" if voip.get("is_voip") else "green"),
            stat_box("DURATION",    results.get("scan_duration","?"),        "bright_cyan"),
        ]
        console.print(Columns(boxes, equal=True, expand=True))

        # ── KEY FINDINGS ─────────────────────────────────────────────────
        console.print()
        console.print(Rule("[bold bright_cyan]  KEY FINDINGS  [/bold bright_cyan]", style="cyan"))
        kf = []
        if tc.get("name"):      kf.append(("[bold green]✔[/]", f"[bold green]CALLER ID NAME: {tc['name']}[/]"))
        if tc.get("tags"):      kf.append(("[bold red]⚠[/]",   f"[bold red]SPAM FLAGS: {', '.join(tc['tags'])}[/]"))
        if voip.get("is_voip"): kf.append(("[bold yellow]⚠[/]",f"[bold yellow]VoIP NUMBER — {voip.get('provider','Unknown')} (no fixed IP)[/]"))
        if loc.get("area_code_city"): kf.append(("[cyan]◈[/]", f"[cyan]AREA CODE ORIGIN: {loc['area_code_city']}[/]"))
        if loc.get("country"):  kf.append(("[cyan]◈[/]",       f"[cyan]COUNTRY: {loc['country']}[/]"))
        if pastes:              kf.append(("[bold red]⚠[/]",   f"[bold red]FOUND ON {len(pastes)} PASTE/LEAK SITE(S)[/]"))
        if breach:              kf.append(("[bold red]⚠[/]",   f"[bold red]FOUND IN {len(breach)} BREACH/LEAK RESULT(S)[/]"))
        if social:              kf.append(("[bold green]✔[/]", f"[green]LINKED TO {len(social)} SOCIAL PLATFORM(S): {', '.join(social.keys())}[/]"))
        if total_hits:          kf.append(("[magenta]◈[/]",    f"[magenta]{total_hits} WEB RESULTS · {total_dorks} DORK HITS[/]"))
        if not kf:              kf.append(("[dim]—[/]",        "[dim]Number appears private or inactive[/]"))
        for icon, text in kf:
            console.print(f"  {icon}  {text}")

        # ── CARRIER ──────────────────────────────────────────────────────
        console.print()
        console.print(Rule("[bold bright_cyan]  CARRIER INTELLIGENCE  [/bold bright_cyan]", style="cyan"))
        if carrier:
            tbl = Table(show_header=False, box=box.SIMPLE, padding=(0,1))
            tbl.add_column("f", style="dim cyan", width=22)
            tbl.add_column("v", style="white")
            for k, label in [("phone","Number"),("phone_type","Line Type"),("carrier","Carrier"),
                              ("country","Country"),("phone_region","Region"),("national_number","National Format")]:
                v = carrier.get(k)
                if v and str(v).lower() not in ("none","null","false",""):
                    tbl.add_row(label, str(v))
            prefix = results.get("prefix_intel",{})
            for k, label in [("country","Country (prefix)"),("region","Region (prefix)"),("prefix","Dialing Code")]:
                v = prefix.get(k)
                if v and not carrier.get("country"):
                    tbl.add_row(label, str(v))
            console.print(tbl)
        else:
            console.print("  [dim]No carrier data — number may be VoIP or outside coverage.[/dim]")

        # ── LOCATION ─────────────────────────────────────────────────────
        if loc:
            console.print()
            console.print(Rule("[bold bright_cyan]  LOCATION INTELLIGENCE  [/bold bright_cyan]", style="cyan"))
            tbl = Table(show_header=False, box=box.SIMPLE, padding=(0,1))
            tbl.add_column("f", style="dim cyan", width=22)
            tbl.add_column("v", style="white")
            for k, label in [("number_format","Formatted"),("country","Country"),("state","State"),
                              ("area_code","Area Code"),("area_code_city","Area Code City"),
                              ("timezone","Timezone"),("carrier_guess","Carrier Guess"),("line_type","Line Type")]:
                if loc.get(k): tbl.add_row(label, str(loc[k]))
            console.print(tbl)

        # ── CALLER ID / TRUECALLER ────────────────────────────────────────
        if tc and (tc.get("name") or tc.get("spam_score") is not None):
            console.print()
            console.print(Rule("[bold bright_cyan]  CALLER ID INTELLIGENCE  [/bold bright_cyan]", style="cyan"))
            tbl = Table(show_header=False, box=box.SIMPLE, padding=(0,1))
            tbl.add_column("f", style="dim cyan", width=22)
            tbl.add_column("v", style="white")
            if tc.get("name"):       tbl.add_row("NAME",        f"[bold green]{tc['name']}[/]")
            if tc.get("number"):     tbl.add_row("NUMBER",      tc["number"])
            if tc.get("carrier"):    tbl.add_row("CARRIER",     tc["carrier"])
            if tc.get("spam_score") is not None:
                score_col = "bright_red" if (tc.get("spam_score") or 0) > 50 else "green"
                tbl.add_row("SPAM SCORE", f"[{score_col}]{tc['spam_score']}[/]")
            if tc.get("tags"):       tbl.add_row("SPAM TAGS",   f"[bold red]{', '.join(tc['tags'])}[/]")
            if tc.get("source"):     tbl.add_row("DATA SOURCE", tc["source"])
            console.print(tbl)

        # ── VoIP ─────────────────────────────────────────────────────────
        if voip.get("is_voip"):
            console.print()
            console.print(Rule("[bold yellow]  VoIP DETECTION  [/bold yellow]", style="yellow"))
            tbl = Table(show_header=False, box=box.SIMPLE, padding=(0,1))
            tbl.add_column("f", style="dim yellow", width=22)
            tbl.add_column("v", style="white")
            tbl.add_row("VoIP", "[bold yellow]YES[/]")
            if voip.get("provider"): tbl.add_row("PROVIDER", voip["provider"])
            if voip.get("asn"):      tbl.add_row("ASN", voip["asn"])
            for n in voip.get("notes",[]):
                console.print(f"  [dim yellow]◈[/]  [dim]{n}[/]")
            console.print(tbl)

        # ── SOCIAL HITS ───────────────────────────────────────────────────
        if social:
            console.print()
            console.print(Rule("[bold bright_cyan]  SOCIAL PLATFORM HITS  [/bold bright_cyan]", style="cyan"))
            for platform, urls in social.items():
                console.print(f"  [bold green]✔[/]  [bold white]{platform}[/]")
                for u in urls[:3]:
                    console.print(f"       [dim blue]{u}[/]")

        # ── REVERSE LOOKUP ────────────────────────────────────────────────
        if rev:
            console.print()
            console.print(Rule("[bold bright_cyan]  REVERSE LOOKUP RESULTS  [/bold bright_cyan]", style="cyan"))
            for i, r in enumerate(rev[:8], 1):
                title = (r.get("title") or r.get("href",""))[:100]
                url   = r.get("href","")
                body  = (r.get("body") or "")[:100]
                console.print(f"  [dim]{i}.[/]  [white]{title}[/]")
                if url and url != title: console.print(f"       [dim blue]{url}[/]")
                if body: console.print(f"       [dim]{body}[/]")

        # ── PASTE/BREACH HITS ─────────────────────────────────────────────
        if pastes:
            console.print()
            console.print(Rule("[bold red]  PASTE SITE HITS  [/bold red]", style="red"))
            for i, p in enumerate(pastes[:8], 1):
                t = (p.get("title") or p.get("href",""))[:100]
                console.print(f"  [bold red]⚠[/]  [white]{t}[/]  [dim blue]{p.get('href','')}[/]")
        if breach:
            console.print()
            console.print(Rule("[bold red]  BREACH HITS  [/bold red]", style="red"))
            for b in breach[:8]:
                t = (b.get("title") or b.get("href",""))[:100]
                console.print(f"  [bold red]⚠[/]  [white]{t}[/]")

        # ── WEB RESULTS ───────────────────────────────────────────────────
        if web:
            console.print()
            console.print(Rule("[bold bright_cyan]  WEB INTELLIGENCE  [/bold bright_cyan]", style="cyan"))
            for cat, hits in web.items():
                console.print(f"\n  [bold bright_cyan]## {cat}[/]  [dim]({len(hits)} results)[/]")
                for i, h in enumerate(hits[:4], 1):
                    title = (h.get("title") or h.get("href",""))[:100]
                    url   = h.get("href","")
                    body  = (h.get("body") or "")[:100]
                    console.print(f"    [dim]{i}.[/]  [white]{title}[/]")
                    if url and url != title: console.print(f"         [dim blue]{url}[/]")
                    if body: console.print(f"         [dim]{body}[/]")

        # ── DORK HITS ─────────────────────────────────────────────────────
        if dorks:
            console.print()
            console.print(Rule("[bold bright_cyan]  DORK RESULTS  [/bold bright_cyan]", style="cyan"))
            for cat, hits in dorks.items():
                if not hits: continue
                console.print(f"\n  [bold cyan]## {cat}[/]  [dim]({len(hits)})[/]")
                for i, h in enumerate(hits[:3], 1):
                    t = (h.get("title") or h.get("href",""))[:100]
                    console.print(f"    [dim]{i}.[/]  [white]{t}[/]  [dim blue]{h.get('href','')}[/]")

        # ── AI ANALYSIS ───────────────────────────────────────────────────
        if ai_text and "unavailable" not in ai_text.lower() and "failed" not in ai_text.lower()[:20]:
            console.print()
            console.print(Rule("[bold bright_cyan]  AI THREAT ANALYSIS  [/bold bright_cyan]", style="cyan"))
            for line in ai_text.split("\n"):
                stripped = line.strip()
                if not stripped:
                    console.print()
                elif stripped.startswith("## "):
                    heading = stripped[3:].strip()
                    console.print(f"\n  [bold bright_cyan]{'━' * 52}[/]")
                    console.print(f"  [bold bright_cyan]{heading.upper()}[/]")
                    console.print(f"  [bold bright_cyan]{'━' * 52}[/]")
                elif stripped.startswith("**") and stripped.endswith("**") and stripped.count("**") == 2:
                    console.print(f"\n  [bold bright_cyan]{stripped.strip('*').strip()}[/]")
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
                    console.print(f"  [dim cyan]◈[/]  [white]{stripped[2:]}[/]")
                elif stripped and stripped[0].isdigit() and len(stripped) > 2 and stripped[1] in ".)" :
                    console.print(f"  [cyan]{stripped[0]}[/][dim].[/]  [white]{stripped[2:].strip()}[/]")
                else:
                    console.print(f"  [dim white]{stripped}[/]")

        # ── Save HTML bonus ───────────────────────────────────────────────
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        slug = re.sub(r'\D', '', number)
        fname = f"phone_report_{slug}_{ts}.html"
        try:
            html = build_html_report(number, results)
            with open(fname, "w", encoding="utf-8") as f:
                f.write(html)
            console.print()
            console.print(Rule(style="dim cyan"))
            console.print(f"  [dim]HTML report saved →[/]  [bright_cyan]{fname}[/]")
        except Exception as e:
            console.print(f"  [dim yellow]HTML save skipped: {e}[/]")

    except Exception as e:
        console.print(f"\n  [bold red]Display error: {e}[/bold red]")

    console.print()
    console.print(Rule("[bold bright_cyan]  ◈ DONE ◈  [/bold bright_cyan]", style="bright_cyan"))
    console.print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[bright_cyan]  ◈ Scan aborted.[/bright_cyan]\n")
