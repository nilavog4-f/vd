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
TOKEN    = "MTQ2NjA5MTMwMTczNTg5NTA3MQ.GnwR-p.gIVchDj8UsO0IUlO6_eFTw474j6HUGPtUBJOD0"
BASE_URL = "https://discord.com/api/v10"
HDRS     = {
    "Authorization": f"Bot {TOKEN}",
    "Content-Type":  "application/json",
    "User-Agent":    "DiscordBot (void, 2.0)",
}

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

async def verify_token_verbose():
    global _SESSION
    if _SESSION is None:
        _SESSION = aiohttp.ClientSession(connector=_make_connector(),
                                         timeout=aiohttp.ClientTimeout(total=15, connect=5))
    try:
        async with _SESSION.get(f"{BASE_URL}/users/@me", headers=HDRS) as resp:
            body = await resp.json(content_type=None) if resp.content_length != 0 else {}
            if resp.status == 200: return True, body
            if resp.status == 401: return False, f"HTTP 401 — token invalid or bot deleted"
            if resp.status == 403: return False, f"HTTP 403 — token lacks scope / bot suspended"
            if resp.status == 429: return False, f"HTTP 429 — rate limited"
            if resp.status >= 500: return False, f"HTTP {resp.status} — Discord server error"
            return False, f"HTTP {resp.status} — {body.get('message','unknown')}"
    except aiohttp.ClientConnectorError as e: return False, f"Network error: {e}"
    except asyncio.TimeoutError:              return False, "Timeout — check network/VPN"
    except Exception as e:                    return False, f"{type(e).__name__}: {e}"

async def kick(gid, uid):     return await _req("DELETE", f"/guilds/{gid}/members/{uid}")
async def ban(gid, uid):      return await _req("PUT",    f"/guilds/{gid}/bans/{uid}",
                                                 json={"delete_message_days":0})
async def unban(gid, uid):    return await _req("DELETE", f"/guilds/{gid}/bans/{uid}")
async def send_msg(cid, txt): return await _req("POST",   f"/channels/{cid}/messages",
                                                 json={"content":txt})
async def del_channel(cid):   return await _req("DELETE", f"/channels/{cid}")
async def mk_channel(gid, name, t=0):
    return await _req("POST", f"/guilds/{gid}/channels", json={"name":name,"type":t})
async def mk_webhook(cid, name="void"):
    return await _req("POST", f"/channels/{cid}/webhooks", json={"name":name})
async def edit_guild(gid, **kw): return await _req("PATCH", f"/guilds/{gid}", json=kw)
async def leave_guild(gid):      return await _req("DELETE", f"/users/@me/guilds/{gid}")

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

    # Guild status bar
    if guild_id:
        console.print(f"  [dim]Active Server:[/] [{TEAL}]{guild_id}[/]  "
                      f"[dim]│  Type[/] [bold white]S[/] [dim]to change[/]\n")
    else:
        console.print(f"  [dim]No server selected.[/] [dim]Type[/] [bold white]S[/] "
                      f"[dim]to set a Server ID for guild operations.[/]\n")

    # ── BOT MANAGEMENT ──────────────────────────────────────────────────────
    _sep()
    console.print(f"  [{TEAL}]BOT MANAGEMENT[/]")
    _sep()
    console.print()
    _menu_row("01", "Sync Commands", "Sync slash commands to Discord",
              "02", "List Guilds",   "List all guilds the bot is in")
    _menu_row("03", "Show Stats",    "Show bot and session statistics",
              "04", "Leave Guild",   "Leave a guild by ID")
    console.print()

    # ── BROADCAST & CONTROL ──────────────────────────────────────────────────
    _sep()
    console.print(f"  [{TEAL}]BROADCAST & CONTROL[/]")
    _sep()
    console.print()
    _menu_row("05", "Broadcast",     "Send a message to all guilds",
              "06", "Maintenance",   "Toggle maintenance announcement")
    console.print()

    # ── MEMBER OPERATIONS ────────────────────────────────────────────────────
    _sep()
    console.print(f"  [{TEAL}]MEMBER OPERATIONS[/]")
    _sep()
    console.print()
    _menu_row("07", "Kick Member",   "Kick a member by user ID",
              "08", "Ban Member",    "Ban a member by user ID")
    _menu_item("09", "Unban Member", "Unban a member by user ID")
    console.print()

    # ── SYSTEM ───────────────────────────────────────────────────────────────
    _sep()
    console.print(f"  [{TEAL}]SYSTEM[/]")
    _sep()
    console.print()
    _menu_row("10", "Reload Bot",    "Re-authenticate and reload session",
              "11", "Shutdown",      "Exit the terminal cleanly")
    console.print()
    _sep()
    console.print(f"  [dim]  0   Exit[/]")
    _sep()
    console.print()

def _menu_row(k1, l1, d1, k2, l2, d2):
    """Print two menu items side by side."""
    left  = f"  [dim]>[/] [[{TEAL}]{k1}[/]] [{WHITE}]{l1:<20}[/] [{DIM}]{d1:<32}[/]"
    right = f"  [dim]>[/] [[{TEAL}]{k2}[/]] [{WHITE}]{l2:<20}[/] [{DIM}]{d2}[/]"
    console.print(left + right)

def _menu_item(k, label, desc):
    """Print a single menu item."""
    console.print(f"  [dim]>[/] [[{TEAL}]{k}[/]] [{WHITE}]{label:<20}[/] [{DIM}]{desc}[/]")

# ═══════════════════════════════════════════════════════════════════════════════
# OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════════

async def op_sync_commands(guild_id: str | None) -> str | None:
    """Sync slash commands globally (or to a specific guild if provided)."""
    app_id = await api_app_id()
    if not app_id:
        _fail("Could not fetch application ID — check token."); return guild_id

    if guild_id:
        _status(f"Syncing commands to guild {guild_id}…")
        result = await _req("PUT", f"/applications/{app_id}/guilds/{guild_id}/commands", json=[])
    else:
        _status("Syncing global commands (this takes up to 1 hour to propagate)…")
        result = await _req("PUT", f"/applications/{app_id}/commands", json=[])

    if result is not None:
        _ok(f"Commands synced successfully (app: {app_id})")
    else:
        _fail("Sync failed — check bot permissions and token scope.")
    return guild_id


async def op_list_guilds(guild_id: str | None) -> str | None:
    """List all guilds the bot belongs to."""
    _status("Fetching guilds…")
    guilds = await api_guilds()
    if not guilds:
        _fail("No guilds found or request failed."); return guild_id

    t = Table(box=box.SIMPLE_HEAD, border_style="dim", show_edge=False)
    t.add_column("#",    style="dim",         width=4,  no_wrap=True)
    t.add_column("Name", style="bold white",  width=32, no_wrap=True)
    t.add_column("ID",   style=TEAL,          width=20, no_wrap=True)
    t.add_column("Owner", style="dim",        width=5)

    for i, g in enumerate(guilds, 1):
        owner = "✓" if g.get("owner") else ""
        t.add_row(str(i), g.get("name","?"), str(g.get("id","?")), owner)

    console.print(Panel(t, title=f"[bold {TEAL}]  GUILD LIST — {len(guilds)} guilds  [/]",
                        border_style=TEAL, box=box.DOUBLE_EDGE))
    return guild_id


async def op_show_stats(guild_id: str | None) -> str | None:
    """Show bot stats and session counters."""
    me = await api_self()
    guilds = await api_guilds()

    t = Table.grid(padding=(0, 3))
    t.add_column(style="dim"); t.add_column(style="bold white")

    if me:
        t.add_row("Username",   f"{me.get('username','?')}")
        t.add_row("Bot ID",     str(me.get("id","?")))
        t.add_row("Verified",   str(me.get("verified", False)))
        t.add_row("MFA",        str(me.get("mfa_enabled", False)))
    t.add_row("─" * 12, "─" * 20)
    t.add_row("Guilds",     str(len(guilds)))
    t.add_row("Session OK", str(ST.done))
    t.add_row("Failures",   str(ST.failed))
    t.add_row("RL Hits",    str(ST.rls))
    t.add_row("Uptime",     f"{ST.elapsed():.0f}s")
    if guild_id:
        t.add_row("─" * 12, "─" * 20)
        t.add_row("Active Server", guild_id)
        g = await api_guild(guild_id)
        if g:
            t.add_row("Server Name",    g.get("name","?"))
            t.add_row("Member Count",   str(g.get("approximate_member_count","?")))
            t.add_row("Owner ID",       str(g.get("owner_id","?")))

    console.print(Panel(t, title=f"[bold {YELLOW}]  BOT STATS  [/]",
                        border_style=YELLOW, box=box.DOUBLE_EDGE))
    return guild_id


async def op_leave_guild(guild_id: str | None) -> str | None:
    """Leave a guild."""
    gid = input("  Guild ID to leave: ").strip()
    if not gid:
        _warn("No guild ID entered, cancelled."); return guild_id
    confirm = input(f"  Confirm leave guild [{gid}]? (y/N): ").strip().lower()
    if confirm != "y":
        _warn("Cancelled."); return guild_id
    _status(f"Leaving guild {gid}…")
    result = await leave_guild(gid)
    if result is not None:
        _ok(f"Left guild {gid}")
        if guild_id == gid:
            guild_id = None
            _warn("Active server cleared (we left it).")
    else:
        _fail("Could not leave guild — not in it, or missing permissions.")
    return guild_id


async def op_broadcast(guild_id: str | None) -> str | None:
    """Send a message to the system channel of every guild."""
    msg = input("  Message to broadcast: ").strip()
    if not msg:
        _warn("No message entered, cancelled."); return guild_id

    _status("Fetching guilds…")
    guilds = await api_guilds()
    if not guilds:
        _fail("No guilds found."); return guild_id

    sent = 0
    for g in guilds:
        gid = g.get("id")
        info = await api_guild(gid)
        sys_ch = info.get("system_channel_id") if info else None
        if sys_ch:
            r = await send_msg(sys_ch, msg)
            if r is not None:
                sent += 1
                console.print(f"    [{GREEN}]✓[/] {g.get('name','?')}")
            else:
                console.print(f"    [{RED}]✗[/] {g.get('name','?')}")
        else:
            console.print(f"    [dim]–[/] {g.get('name','?')} (no system channel)")

    _ok(f"Broadcast complete — {sent}/{len(guilds)} guilds received the message")
    return guild_id


async def op_maintenance(guild_id: str | None) -> str | None:
    """Send a maintenance announcement to a guild."""
    gid = guild_id or input("  Server ID: ").strip()
    if not gid:
        _warn("No server ID, cancelled."); return guild_id

    msg = input("  Maintenance message (blank = default): ").strip()
    if not msg:
        msg = "🔧 **Maintenance in progress.** The server is temporarily under maintenance. We'll be back shortly."

    _status("Fetching channels…")
    channels = await api_channels(gid)
    text_chs = [c for c in channels if c.get("type") == 0]
    if not text_chs:
        _fail("No text channels found."); return guild_id

    # Post to the first available text channel
    target = text_chs[0]
    result = await send_msg(target["id"], msg)
    if result is not None:
        _ok(f"Maintenance message posted in #{target.get('name','?')}")
    else:
        _fail("Could not post message — check bot permissions.")
    return gid


async def op_kick_member(guild_id: str | None) -> str | None:
    """Kick a specific member by user ID."""
    gid = guild_id or input("  Server ID: ").strip()
    if not gid:
        _warn("No server ID, cancelled."); return guild_id

    uid = input("  User ID to kick: ").strip()
    if not uid:
        _warn("No user ID entered, cancelled."); return guild_id

    reason = input("  Reason (optional): ").strip() or "Kicked by VOID terminal"
    _status(f"Kicking {uid} from {gid}…")

    result = await kick(gid, uid)
    if result is not None:
        _ok(f"User {uid} kicked from guild {gid}")
    else:
        _fail("Kick failed — user may not be in the server, or missing KICK_MEMBERS permission.")
    return gid


async def op_ban_member(guild_id: str | None) -> str | None:
    """Ban a specific member by user ID."""
    gid = guild_id or input("  Server ID: ").strip()
    if not gid:
        _warn("No server ID, cancelled."); return guild_id

    uid = input("  User ID to ban: ").strip()
    if not uid:
        _warn("No user ID entered, cancelled."); return guild_id

    days = input("  Delete message days (0–7, default 0): ").strip()
    try:   days = max(0, min(7, int(days)))
    except: days = 0

    _status(f"Banning {uid} from {gid}…")
    result = await _req("PUT", f"/guilds/{gid}/bans/{uid}",
                        json={"delete_message_days": days})
    if result is not None:
        _ok(f"User {uid} banned from guild {gid} (delete_message_days={days})")
    else:
        _fail("Ban failed — check BAN_MEMBERS permission and user ID.")
    return gid


async def op_unban_member(guild_id: str | None) -> str | None:
    """Unban a member by user ID."""
    gid = guild_id or input("  Server ID: ").strip()
    if not gid:
        _warn("No server ID, cancelled."); return guild_id

    uid = input("  User ID to unban: ").strip()
    if not uid:
        _warn("No user ID entered, cancelled."); return guild_id

    _status(f"Unbanning {uid} from {gid}…")
    result = await unban(gid, uid)
    if result is not None:
        _ok(f"User {uid} unbanned from guild {gid}")
    else:
        _fail("Unban failed — user may not be banned, or missing BAN_MEMBERS permission.")
    return gid


async def op_reload_bot(guild_id: str | None) -> str | None:
    """Re-authenticate the bot and reset the session."""
    global _SESSION, TOKEN, HDRS
    _status("Closing current session…")
    if _SESSION:
        await _SESSION.close()
        _SESSION = None

    _SESSION = aiohttp.ClientSession(
        connector=_make_connector(),
        timeout=aiohttp.ClientTimeout(total=15, connect=5)
    )
    ST.reset()
    _status("Verifying token…")
    ok, me = await verify_token_verbose()
    if ok:
        _ok(f"Session reloaded — logged in as {me.get('username','?')}")
    else:
        _fail(f"Reload failed: {me}")
    return guild_id

# ═══════════════════════════════════════════════════════════════════════════════
# MENU DISPATCH
# ═══════════════════════════════════════════════════════════════════════════════
OPERATIONS = {
    "1":  ("Sync Commands",  op_sync_commands),
    "2":  ("List Guilds",    op_list_guilds),
    "3":  ("Show Stats",     op_show_stats),
    "4":  ("Leave Guild",    op_leave_guild),
    "5":  ("Broadcast",      op_broadcast),
    "6":  ("Maintenance",    op_maintenance),
    "7":  ("Kick Member",    op_kick_member),
    "8":  ("Ban Member",     op_ban_member),
    "9":  ("Unban Member",   op_unban_member),
    "10": ("Reload Bot",     op_reload_bot),
    "11": ("Shutdown",       None),       # handled inline
}

# Accept zero-padded input too (01 → 1)
for _k in list(OPERATIONS.keys()):
    OPERATIONS[_k.zfill(2)] = OPERATIONS[_k]

async def _dispatch(choice: str, guild_id: str | None) -> str | None:
    """Run one operation and always return the (possibly updated) guild_id."""
    entry = OPERATIONS.get(choice)
    if not entry:
        _fail(f"Unknown option: {choice!r}"); return guild_id

    label, handler = entry
    if handler is None:
        return guild_id   # Shutdown handled in main loop

    color = TEAL
    console.print()
    _sep(RED)
    console.print(f"  [{RED}]{label.upper()}[/]")
    _sep(RED)
    console.print()

    t0 = time.time()
    try:
        guild_id = await handler(guild_id)
    except KeyboardInterrupt:
        console.print()
        _warn("Operation interrupted by user.")
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
async def main():
    global _SESSION, TOKEN, HDRS

    _SESSION = aiohttp.ClientSession(
        connector=_make_connector(),
        timeout=aiohttp.ClientTimeout(total=15, connect=5)
    )

    # ── Token verification ───────────────────────────────────────────────────
    console.clear()
    fig = pyfiglet.figlet_format("VOID  NUKE", font="doom")
    shades = ["bright_red","red","bright_red","red","bright_red","red"]
    for i, line in enumerate(fig.splitlines()):
        if line.strip():
            console.print(f"  [{shades[i%len(shades)]}]{line}[/]")
    console.print()
    _sep(RED)
    console.print(f"  [dim]Verifying token…[/]")
    _sep(RED)
    console.print()

    ok, me_or_err = await verify_token_verbose()

    if not ok:
        _fail(str(me_or_err))
        console.print()
        console.print("  [dim]Fixes: check your token, internet, or VPN.[/]")
        console.print()
        try: ans = input("  Replace token now? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt): ans = "n"
        if ans == "y":
            TOKEN = input("  New bot token: ").strip()
            HDRS["Authorization"] = f"Bot {TOKEN}"
            _status("Retrying…")
            ok, me_or_err = await verify_token_verbose()
            if not ok:
                _fail(str(me_or_err)); await _SESSION.close(); sys.exit(1)
        else:
            await _SESSION.close(); sys.exit(1)

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
                input("\n  Press Enter to return to the menu…")
                continue

            if raw in ("11", "011"):
                console.print()
                _sep(RED)
                console.print(f"  [{YELLOW}]Shutting down VOID NUKE v2.0…[/]")
                _sep(RED)
                break

            if raw not in OPERATIONS and raw.lstrip("0") not in OPERATIONS:
                _fail(f"Unknown option: {raw!r} — enter 0-11 or S")
                await asyncio.sleep(0.6)
                continue

            # ── Run the chosen operation ─────────────────────────────────────
            ST.reset()
            guild_id = await _dispatch(raw, guild_id)

            # ── Always return to menu ────────────────────────────────────────
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
