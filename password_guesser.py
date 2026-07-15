#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
# ##  VOID Password Guess Checker — Personal-Detail Attack Simulator
# ##  ** 100% local — nothing transmitted, saved, or logged **
# ##  WSL / Kali Linux Edition  ·  @lfw.k4rma_
# ##  Run against your OWN password only.
# ══════════════════════════════════════════════════════════════════
"""
Run this yourself, locally, in your own terminal:

    python3 password_guesser.py

Everything happens on your machine. Nothing is sent anywhere, saved to
disk, or logged. It never touches any real account, login page, or
service -- it only prints candidate guesses to your terminal so you can
compare them against your own password by eye.

Flow:
  1. You type in a few personal details -- the kind of stuff an attacker
     can find on social media in five minutes. Leave anything blank to skip.
  2. Optionally add more detail categories (family, places, hobbies, etc.)
  3. The script builds a list of realistic guesses mirroring real cracking
     wordlists: nicknames, leet substitutions, seasonal combos, keyboard
     patterns, natural-language phrases, special-char formulas, and more.
  4. It shows you ONE guess at a time. Press y+Enter if it matches your
     real password; press Enter (or n) to move on.
  5. A final result screen tells you how you fared and what to do next.
"""

import argparse
import re
import subprocess
import sys
import time
import threading


def _ensure_deps():
    for mod, pkg in [("rich","rich"),("pyfiglet","pyfiglet"),("pynput","pynput"),("pyperclip","pyperclip")]:
        try:
            __import__(mod)
        except ImportError:
            print(f"[*] Installing {pkg}...")
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", pkg, "-q",
                     "--break-system-packages"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", pkg, "-q"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


_ensure_deps()

# ## Imports ######################################################
from rich.console  import Console
from rich.text     import Text
from rich.align    import Align
from rich.rule     import Rule
from rich.panel    import Panel
from rich.progress import Progress, BarColumn, TextColumn
from rich import box
import pyfiglet

console = Console()

CHECK, CROSS, ARROW, DOT, BULLET = "✓", "✗", "▸", "●", "•"

# ── source-type highlight styles (used when displaying each guess) ─────────
SOURCE_STYLES = {
    "custom":    "bright_magenta",
    "name":      "bright_yellow",
    "nickname":  "bright_yellow",
    "pet":       "yellow",
    "partner":   "yellow",
    "city":      "bright_blue",
    "year":      "bright_white",
    "birthday":  "bright_white",
    "keyboard":  "dim white",
    "common":    "dim white",
}


def source_style(src: str) -> str:
    for key, col in SOURCE_STYLES.items():
        if key in src.lower():
            return col
    return "white"


# ## Banner #######################################################
def banner():
    console.clear()
    fig = pyfiglet.figlet_format("VOID  PWD", font="doom")
    shades = ["bright_red", "red", "bright_red", "red",
              "bright_red", "red", "bright_red", "red"]
    txt = Text()
    for i, line in enumerate(fig.splitlines()):
        txt.append(line + "\n", style=shades[i % len(shades)])
    console.print(Align.center(txt))

    sub = Text()
    sub.append("  ◈ ", style="bright_red")
    sub.append("PERSONAL-DETAIL PASSWORD GUESS CHECKER", style="bold bright_white")
    sub.append(" ◈  ", style="bright_red")
    console.print(Align.center(sub))

    tags = Text()
    for label, sep in [
        ("100% Local", " | "), ("Realistic Patterns", " | "),
        ("Nothing Saved / Logged", ""),
    ]:
        tags.append(label, style="bright_red")
        if sep:
            tags.append(sep, style="dim red")
    console.print(Align.center(tags))
    console.print(Align.center(
        Text("by @lfw.k4rma_  ·  RUN AGAINST YOUR OWN PASSWORD ONLY\n", style="dim red")))
    console.print(Rule(style="bright_red"))


def section(title: str):
    console.print()
    console.print(Rule(f"[bold bright_white]  {title}  [/]", style="bright_red"))


def subheading(text: str):
    console.print()
    console.print(f"  [bright_red]{DOT}[/]  [bold white]{text}[/]")
    console.print(Rule(style="dim red"))


# ─────────────────────────────────────────────────────────────────────────────
#  Guess generation
# ─────────────────────────────────────────────────────────────────────────────

LEET_MAP = {
    "a": ["a", "4", "@"],
    "b": ["b", "8"],
    "e": ["e", "3"],
    "i": ["i", "1", "!"],
    "l": ["l", "1"],
    "o": ["o", "0"],
    "s": ["s", "5", "$"],
    "t": ["t", "7"],
    "g": ["g", "9"],
    "z": ["z", "2"],
}

# Suffixes people actually append to make a simple word "complex"
COMMON_SUFFIXES = [
    "", "1", "2", "12", "123", "1234", "12345",
    "!", "!!", "!1", "!12", "!123",
    "1!", "1!!", "123!", "1234!",
    "01", "007", "99", "88", "69", "00", "786", "108", "420", "143",
    "@1", "@123", "#1", "#123", "#", "@",
    "2026", "2025", "2024", "2023", "2022", "2021", "2020",
    "4ever", "4life", "forever", "4u", "4me",
    "xo", "xx", "xoxo",
    "_1", "_123", ".1", ".123", "_", ".",
    "isme", "islife", "isking", "isqueen", "rocks", "rules",
]

COMMON_PREFIXES = [
    "", "the", "im", "its", "my", "i", "hey",
    "imy", "ilove", "ilovemy", "dear", "only",
]

# Human-natural word bridges used in compound passwords
BRIDGES = ["", "_", ".", "is", "my", "and", "4", "the", "n", "&"]

# Patterns humans think look "strong" because they use symbols
SPECIAL_WRAPPERS = [
    lambda w: f"{w}!",         lambda w: f"{w}!!",        lambda w: f"{w}@",
    lambda w: f"{w}#",         lambda w: f"{w}$",          lambda w: f"!{w}",
    lambda w: f"{w}@123",      lambda w: f"{w}!23",        lambda w: f"{w}_1",
    lambda w: f"{w}.1",        lambda w: f"_{w}_",         lambda w: f"{w}*",
    lambda w: f"{w}#1",        lambda w: f"#{w}1",         lambda w: f"{w}@1",
    lambda w: f"{w}@2024",     lambda w: f"{w}@2025",      lambda w: f"@{w}123",
    lambda w: f"{w}.123",      lambda w: f"{w}_123",       lambda w: f"123{w}",
    lambda w: f"{w}786",       lambda w: f"{w}143",        lambda w: f"{w}007",
    lambda w: f"[{w}]",        lambda w: f"({w})",         lambda w: f"{w}!@#",
]

# Keyboard walk patterns — attackers always try these
KEYBOARD_PATTERNS = [
    "qwerty", "qwerty1", "qwerty123", "qwerty!1",
    "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn",
    "1q2w3e", "1q2w3e4r", "1qaz2wsx",
    "q1w2e3", "q1w2e3r4",
    "123abc", "abc123", "abc1234",
    "pass", "pass1", "pass123", "pass1234",
    "password", "password1", "password123", "p@ssw0rd",
    "letmein", "letmein1", "letmein123",
    "iloveyou", "iloveyou1",
    "welcome", "welcome1", "welcome123",
    "monkey", "monkey1", "monkey123",
    "dragon", "dragon1", "dragon123",
    "master", "master1", "master123",
    "111111", "222222", "123123", "321321",
    "000000", "696969", "121212",
]

# Seasonal + year combos (attackers know people love these)
CURRENT_YEAR   = 2025
SEASONS        = ["spring", "summer", "fall", "autumn", "winter"]
SEASON_YEARS   = [
    f"{s.capitalize()}{y}"
    for s in SEASONS
    for y in range(CURRENT_YEAR - 3, CURRENT_YEAR + 2)
]
SEASON_YEARS  += [
    f"{s.capitalize()}{str(y)[2:]}"
    for s in SEASONS
    for y in range(CURRENT_YEAR - 3, CURRENT_YEAR + 2)
]

# Months — used alone or combined
MONTHS = [
    "january","february","march","april","may","june",
    "july","august","september","october","november","december",
    "jan","feb","mar","apr","jun","jul","aug","sep","oct","nov","dec",
]

# Emotion/identity phrases attackers try
FILLER_PHRASES = [
    "iloveyou", "ihateyou", "imissyou", "foreveralone",
    "loveyou", "bestday", "mylife", "mybaby",
    "thebest", "number1", "numb3r1",
    "trustno1", "trust_no1",
]

def leet_variants(word: str, max_variants: int = 8) -> list[str]:
    lower    = word.lower()
    variants = [lower]
    seen     = {lower}
    for i, ch in enumerate(lower):
        if len(variants) >= max_variants:
            break
        for sub in LEET_MAP.get(ch, []):
            if sub == ch:
                continue
            swapped = lower[:i] + sub + lower[i + 1:]
            if swapped not in seen:
                seen.add(swapped)
                variants.append(swapped)
                if len(variants) >= max_variants:
                    break
    return variants


def capitalizations(word: str) -> list[str]:
    """Common capitalisation patterns humans use."""
    w = word.lower()
    variants = [w]
    if w:
        variants.append(w.capitalize())              # Title
        variants.append(w.upper())                   # ALL CAPS
        variants.append(w[0].upper() + w[1:])       # First
    if len(w) > 1:
        variants.append(w[:-1] + w[-1].upper())     # lasT
        # alternating: hElLo  (less common but real)
        alt = "".join(c.upper() if i % 2 == 0 else c for i, c in enumerate(w))
        variants.append(alt)
    return list(dict.fromkeys(variants))             # deduplicated, order preserved


def extract_years(date_str: str) -> list[str]:
    if not date_str:
        return []
    m = re.search(r"(19|20)\d{2}", date_str)
    if not m:
        return []
    full = m.group(0)
    return [full, full[2:]]


def extract_date_digits(date_str: str) -> list[str]:
    if not date_str:
        return []
    out = set()
    digits_only = re.sub(r"[^0-9]", "", date_str)
    if len(digits_only) >= 4:
        out.add(digits_only)
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", date_str)
    if m:
        yyyy, mm, dd = m.groups()
        out.update({
            mm + dd,
            dd + mm,
            mm + dd + yyyy[2:],
            dd + mm + yyyy[2:],
            yyyy + mm + dd,
            mm + dd + yyyy,
        })
    m2 = re.search(r"(\d{1,2})[\/\-\.](\d{1,2})", date_str)
    if m2:
        a, b = m2.group(1).zfill(2), m2.group(2).zfill(2)
        out.update({a + b, b + a})
    return list(out)


def build_guesses(info: dict) -> list[tuple[str, str]]:
    """
    Build a realistic attacker-style dictionary from personal details.
    Returns list of (original_case_guess, human_readable_source_label).
    """
    results: dict[str, tuple[str, str]] = {}
    words:   list[tuple[str, str]] = []

    full_name = info.get("full_name", "").strip()
    if full_name:
        parts = full_name.split()
        for p in parts:
            if p:
                words.append((p, "name part"))
        if len(parts) >= 2:
            words.append(("".join(parts), "full name"))
            words.append((parts[0][0] + parts[-1], "initial+last"))
            words.append((parts[-1] + parts[0][0], "last+initial"))
            if len(parts) >= 3:
                words.append((parts[0] + parts[-1], "first+last"))

    for custom_val in info.get("custom_words", []):
        if custom_val.strip():
            words.append((custom_val.strip(), "custom"))

    for key, label in [
        ("nickname",        "nickname"),
        ("pet_name",        "pet's name"),
        ("partner_name",    "partner's name"),
        ("city",            "city"),
        ("favorite_thing",  "favorite thing"),
        ("mother_name",     "mother's name"),
        ("father_name",     "father's name"),
        ("sibling_name",    "sibling's name"),
        ("child_name",      "child's name"),
        ("school",          "school name"),
        ("workplace",       "workplace"),
        ("street",          "street name"),
        ("car",             "car"),
        ("username",        "username / handle"),
        ("email_prefix",    "email prefix"),
        ("fav_color",       "favorite color"),
        ("fav_band",        "favorite band / artist"),
        ("fav_sport_team",  "sports team"),
        ("hobby",           "hobby"),
        ("phone_last4",     "phone last 4 digits"),
    ]:
        val = info.get(key, "").strip()
        if val:
            words.append((val, label))

    years       = (extract_years(info.get("birth_year", ""))
                 + extract_years(info.get("birth_date", ""))
                 + extract_years(info.get("anniversary", ""))
                 + extract_years(info.get("grad_year", "")))
    seen_y: set[str] = set()
    years = [y for y in years if not (y in seen_y or seen_y.add(y))]

    date_digits = (extract_date_digits(info.get("birth_date", ""))
                 + extract_date_digits(info.get("anniversary", "")))

    lucky  = info.get("lucky_number", "").strip()
    phone4 = info.get("phone_last4", "").strip()
    extra_numbers = [x for x in [lucky, phone4] if x and x.isdigit()]

    def add(guess: str, source: str):
        k = guess.lower().strip()
        g = guess.strip()
        if k and len(k) >= 3 and k not in results:
            results[k] = (g, source)

    for value, source in words:
        base = value.strip()
        if not base:
            continue

        for cap in capitalizations(base):
            for leet in leet_variants(cap):
                for pfx in COMMON_PREFIXES:
                    for sfx in COMMON_SUFFIXES:
                        add(f"{pfx}{leet}{sfx}", source)

                for wrap in SPECIAL_WRAPPERS:
                    add(wrap(leet), source)
                    add(wrap(leet.capitalize()), source)

                for year in years:
                    add(f"{leet}{year}",           f"{source} + year")
                    add(f"{year}{leet}",           f"year + {source}")
                    add(f"{leet.capitalize()}{year}!", f"{source} + year + !")
                    add(f"{leet}{year}!",          f"{source} + year + !")
                    add(f"{leet}@{year}",          f"{source} @year")

                for dd in date_digits:
                    add(f"{leet}{dd}",             f"{source} + birthday")
                    add(f"{dd}{leet}",             f"birthday + {source}")

                for num in extra_numbers:
                    add(f"{leet}{num}",            f"{source} + lucky/phone")
                    add(f"{leet}#{num}",           f"{source} #number")

                rev = leet[::-1]
                if rev != leet:
                    add(rev, f"{source} (reversed)")
                    for sfx in ["", "1", "123", "!"]:
                        add(f"{rev}{sfx}", f"{source} reversed{sfx}")

                doubled = leet + leet
                add(doubled, f"{source} doubled")
                add(f"{doubled}1",   f"{source} doubled+1")
                add(f"{doubled}!",   f"{source} doubled+!")

                add(f"ilove{leet}",       f"i love {source}")
                add(f"ilovemy{leet}",     f"i love my {source}")
                add(f"ilovemy{leet}123",  f"i love my {source} 123")
                add(f"my{leet}",          f"my {source}")
                add(f"my{leet}123",       f"my {source} 123")
                add(f"my{leet}!",         f"my {source} !")
                add(f"only{leet}",        f"only {source}")
                add(f"dear{leet}",        f"dear {source}")
                add(f"{leet}forever",     f"{source} forever")
                add(f"{leet}4ever",       f"{source} 4ever")
                add(f"{leet}4ever!",      f"{source} 4ever !")
                add(f"{leet}4life",       f"{source} 4life")
                add(f"{leet}isthebest",   f"{source} isthebest")
                add(f"{leet}islife",      f"{source} islife")
                add(f"{leet}isking",      f"{source} isking")
                add(f"{leet}isqueen",     f"{source} isqueen")
                add(f"bestof{leet}",      f"best of {source}")
                add(f"{leet}only",        f"{source} only")
                add(f"{leet}isme",        f"{source} isme")
                add(f"{leet}ismylife",    f"{source} ismylife")
                add(f"{leet}rocks",       f"{source} rocks")
                add(f"{leet}rules",       f"{source} rules")
                add(f"1{leet}1",          f"1 {source} 1")
                add(f"123{leet}",         f"123 {source}")
                add(f"007{leet}",         f"007 {source}")
                add(f"{leet}786",         f"{source} 786")
                add(f"{leet}143",         f"{source} 143")
                add(f"my_{leet}",         f"my_{source}")
                add(f"my.{leet}",         f"my.{source}")
                add(f"{leet}_123",        f"{source}_123")
                add(f"{leet}.123",        f"{source}.123")
                add(f"my{leet.capitalize()}",      f"my{source.title()}")
                add(f"my{leet.capitalize()}123",   f"my{source.title()}123")
                add(f"i{leet.capitalize()}",       f"i{source.title()}")

    for i, (a, sa) in enumerate(words):
        for year in years:
            add(f"{a}{year}",  f"{sa} + year")
            add(f"{a.capitalize()}{year}", f"{sa} cap + year")

        for j, (b, sb) in enumerate(words):
            if i == j:
                continue
            for bridge in BRIDGES:
                combo = f"{a}{bridge}{b}".strip()
                add(combo, f"{sa}+{sb}")
                add(combo.capitalize(), f"{sa}+{sb} cap")
                for sfx in ["", "1", "123", "!", "!1"]:
                    add(f"{combo}{sfx}", f"{sa}+{sb}")
            for year in years:
                add(f"{a}{b}{year}", f"{sa}+{sb}+year")

    for year in years:
        add(year,            "year alone")
        add(f"{year}!",      "year!")
        add(f"!{year}",      "!year")
    for dd in date_digits:
        add(dd,              "birthday digits alone")

    for sv in SEASON_YEARS:
        add(sv, "season + year")
        add(f"{sv}!", "season + year + !")

    for month in MONTHS:
        for year in years:
            add(f"{month}{year}",            f"month + year")
            add(f"{month.capitalize()}{year}", f"month cap + year")

    for kw in KEYBOARD_PATTERNS:
        add(kw, "keyboard pattern / common password")

    for phrase in FILLER_PHRASES:
        add(phrase, "common phrase")
        for sfx in ["", "1", "123", "!"]:
            add(f"{phrase}{sfx}", "common phrase")

    return list(results.values())


# ─────────────────────────────────────────────────────────────────────────────
#  Interactive CLI helpers
# ─────────────────────────────────────────────────────────────────────────────

def prompt(label: str, hint: str = "") -> str:
    if hint:
        console.print(f"  [dim]{hint}[/]")
    try:
        return console.input(f"  [bright_red]{ARROW}[/] [bold red]{label}[/]: ").strip()
    except EOFError:
        return ""


def yes_no(label: str, default_yes: bool = True) -> bool:
    hint = "[Y/n]" if default_yes else "[y/N]"
    try:
        ans = console.input(
            f"  [bright_red]{ARROW}[/] [bold red]{label}[/] [dim]{hint}[/] "
        ).strip().lower()
    except EOFError:
        return default_yes
    if ans in ("y", "yes"):
        return True
    if ans in ("n", "no"):
        return False
    return default_yes


def collect_custom_words(max_items: int = 100) -> list[str]:
    console.print()
    console.print(f"  [bold bright_red]{ARROW}[/] [bold white]Type or paste anything — names, foods, words, phrases.[/]")
    console.print("    [dim]One item per line.  Type  done  when finished.[/]")
    console.print(f"    [dim]You can add up to {max_items} items.[/]\n")

    collected: list[str] = []
    seen: set[str] = set()

    while len(collected) < max_items:
        count_hint = f"[{len(collected)}/{max_items}]"
        try:
            raw = console.input(
                f"  [bright_red]{ARROW}[/] [dim]{count_hint}[/] "
                f"[dim]Enter item (or[/] [bold red]done[/][dim]):[/] "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            break

        if raw.lower() == "done":
            break
        if not raw:
            continue

        key = raw.lower()
        if key in seen:
            console.print("    [dim](already added — skipping)[/]")
            continue

        seen.add(key)
        collected.append(raw)

        if len(collected) == max_items:
            console.print(f"    [bright_green]✓  Added: {raw}[/]")
            console.print(f"\n  [red]Reached the {max_items}-item limit — moving on.[/]")
        else:
            console.print(f"    [bright_green]✓  Added: {raw}[/]")

    if collected:
        console.print()
        console.print(f"  [bold bright_green]{CHECK} {len(collected)} custom item(s) collected.[/]")
    else:
        console.print("  [dim]No custom items added.[/]")

    return collected


def numbered_menu(options: list[tuple[str, str]], multi: bool = True) -> list[int]:
    console.print()
    for i, (title, desc) in enumerate(options, start=1):
        console.print(f"  [bold bright_red][{i:>2}][/]  [bold white]{title}[/]")
        if desc:
            console.print(f"       [dim]{desc}[/]")
    console.print()
    all_msg = "  all  " if multi else ""
    try:
        raw = console.input(
            f"  [dim]Enter number(s) separated by spaces, {all_msg}or press Enter to skip:[/] "
        ).strip().lower()
    except EOFError:
        return []
    if not raw:
        return []
    if multi and raw == "all":
        return list(range(len(options)))
    chosen = []
    for tok in raw.split():
        if tok.isdigit():
            idx = int(tok) - 1
            if 0 <= idx < len(options) and idx not in chosen:
                chosen.append(idx)
    return chosen


# ─────────────────────────────────────────────────────────────────────────────
#  Auto-Typer (F1 to stop)
# ─────────────────────────────────────────────────────────────────────────────

_stop_typing = threading.Event()

def _start_f1_listener():
    """Background thread that sets _stop_typing when F1 is pressed."""
    try:
        from pynput.keyboard import Key, Listener
        def on_press(key):
            if key == Key.f1:
                _stop_typing.set()
                return False
        threading.Thread(
            target=lambda: Listener(on_press=on_press).start(),
            daemon=True).start()
    except Exception as e:
        console.print(f"  [dim red]F1 listener unavailable: {e}[/]")

def _auto_type_guesses(guesses: list, delay_ms: int, press_enter: bool, countdown: int):
    """
    Clipboard-paste brute forcer — fastest possible method.

    Instead of typing character-by-character (slow), it:
      1. Copies the password to clipboard
      2. Sends Ctrl+V to paste instantly (no per-character delay)
      3. Optionally sends Enter
    A prefetch thread pre-loads the NEXT password into the clipboard queue
    so the main thread never waits on clipboard writes.
    F1 stops everything instantly.
    """
    import queue as _queue
    from rich.live  import Live
    from rich.table import Table

    try:
        import pyperclip
        from pynput.keyboard import Controller, Key, HotKey
    except ImportError as e:
        console.print(f"  [bold red][!][/]  Missing dep: {e} — run pip install pynput pyperclip")
        return

    _stop_typing.clear()
    _start_f1_listener()

    # ── countdown ─────────────────────────────────────────────────────────────
    console.print()
    for i in range(countdown, 0, -1):
        if _stop_typing.is_set():
            console.print("\n  [yellow]Cancelled.[/]"); return
        console.print(
            f"\r  [bold bright_red][!][/]  "
            f"[bold white]Switch to target window — starting in "
            f"[bright_red]{i}[/]s  (F1 cancels)[/]",
            end="")
        time.sleep(1)
    if _stop_typing.is_set():
        console.print("\n  [yellow]Cancelled.[/]"); return
    console.print(
        f"\r  [bold bright_red][!!!][/]  "
        f"[bold bright_red]PASTING — F1 to stop                              [/]")
    console.print()

    kb      = Controller()
    delay_s = max(delay_ms, 0) / 1000
    total   = len(guesses)
    stats   = {"done": 0, "current": "", "start": time.time()}

    # Prefetch queue — prefetch thread writes clipboard; typer thread reads
    clip_q  = _queue.Queue(maxsize=2)

    # ── prefetch thread: pre-loads clipboard one password ahead ───────────────
    def _prefetch():
        for pw, _ in guesses:
            if _stop_typing.is_set():
                break
            clip_q.put(pw)   # blocks if queue full (typer is keeping up)
        clip_q.put(None)     # sentinel

    threading.Thread(target=_prefetch, daemon=True).start()

    # ── panel builder ─────────────────────────────────────────────────────────
    def _panel():
        elapsed = max(time.time() - stats["start"], 0.001)
        done    = stats["done"]
        pct     = done / total if total else 0
        filled  = max(0, min(int(pct * 30), 30))

        bar = Text()
        bar.append("█" * filled,        style="bright_red")
        bar.append("░" * (30 - filled), style="dim")

        speed = f"{done/elapsed:.1f} pw/s" if done else "–"

        tbl = Table.grid(padding=(0, 2))
        tbl.add_column(); tbl.add_column()
        tbl.add_column(); tbl.add_column()
        tbl.add_row(
            Text("TRIED",   style="dim"), Text(f"{done:,} / {total:,}", style="bold white"),
            Text("ELAPSED", style="dim"), Text(f"{elapsed:.0f}s",       style="bold white"),
        )
        tbl.add_row(
            Text("SPEED",   style="dim"), Text(speed,                   style="bold bright_red"),
            Text("DELAY",   style="dim"), Text(f"{delay_ms}ms",         style="bold white"),
        )
        tbl.add_row(
            Text("METHOD",  style="dim"), Text("Clipboard paste (Ctrl+V)", style="dim white"),
            Text("",        style=""),    Text("",                      style=""),
        )

        cur = Text()
        cur.append("  CURRENT  ", style="bold white")
        cur.append(stats["current"][:64], style="bold yellow")

        prog = Text()
        prog.append("  PROGRESS ", style="bold white")
        prog.append_text(bar)
        prog.append(f"  {pct*100:.1f}%", style="bold bright_red")

        from rich.console import Group
        return Panel(
            Group(tbl, Text(""), prog, cur, Text(""),
                  Text("  F1 = stop instantly", style="dim red")),
            title="[bold bright_red]  VOID AUTO-TYPER  —  CLIPBOARD PASTE  [/]",
            border_style="bright_red",
            box=box.DOUBLE_EDGE,
        )

    # ── main paste loop ───────────────────────────────────────────────────────
    try:
        with Live(console=console, refresh_per_second=8, screen=False) as live:
            while not _stop_typing.is_set():
                pw = clip_q.get()
                if pw is None:       # sentinel — all passwords done
                    break

                stats["current"] = pw
                stats["done"]   += 1

                # Copy to clipboard and paste — much faster than kb.type()
                pyperclip.copy(pw)
                with kb.pressed(Key.ctrl):
                    kb.tap('v')

                if press_enter:
                    kb.tap(Key.enter)

                live.update(_panel())

                if delay_s > 0:
                    deadline = time.time() + delay_s
                    while time.time() < deadline:
                        if _stop_typing.is_set(): break
                        time.sleep(0.001)    # 1ms resolution

    except Exception as e:
        console.print(f"\n  [bold red][!][/]  Typer error: {e}\n")
        return

    console.print()
    console.print(Rule("[bold bright_red]  AUTO-TYPER DONE  [/]", style="bright_red"))
    console.print(f"  [dim]Tried    [/]  [bold white]{stats['done']:,} / {total:,}[/]")
    console.print(f"  [dim]Last pw  [/]  [bold yellow]{stats['current']}[/]")
    if _stop_typing.is_set():
        console.print(f"  [dim]Stopped  [/]  [bold bright_red]F1[/]")
    else:
        console.print(f"  [dim]Status   [/]  [bold bright_green]Wordlist exhausted[/]")
    console.print()
    console.print(Rule(style="bright_red"))


# ─────────────────────────────────────────────────────────────────────────────
#  Strength tips
# ─────────────────────────────────────────────────────────────────────────────

def strength_tips() -> list[str]:
    return [
        "Use a passphrase: 4 random words like 'violet-hammer-rogue-spoon'",
        "Enable a password manager (Bitwarden, 1Password) to use unique passwords everywhere",
        "Turn on two-factor authentication (2FA/TOTP) as a safety net",
        "Never reuse a password across sites — a breach on one site exposes all the others",
        "Aim for 16+ characters; length beats complexity every time",
    ]


# ─────────────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Password Guess Checker")
    parser.add_argument("--list", action="store_true",
                        help="Print all generated guesses to stdout and exit (no interaction)")
    parser.add_argument("--no-keyboard", action="store_true",
                        help="Omit keyboard-walk and common-password guesses")
    args = parser.parse_args()

    start_time = time.time()
    banner()

    # ── Step 1: core personal details ────────────────────────────────────────
    section("STEP 1  —  TELL US A LITTLE ABOUT YOURSELF")
    console.print("  [dim]Leave any field blank to skip it.[/]\n")

    info = {
        "full_name":    prompt("Full name",                 "e.g. John Smith"),
        "nickname":     prompt("Nickname",                  "e.g. Johnny, JJ"),
        "pet_name":     prompt("Pet's name"),
        "partner_name": prompt("Partner / significant other's name"),
        "birth_year":   prompt("Birth year",                "e.g. 1990"),
        "birth_date":   prompt("Birth date",                "e.g. 1990-05-12  or  05/12"),
        "city":         prompt("City or hometown"),
        "favorite_thing": prompt("Favorite team / show / thing"),
    }

    # ── Step 2: optional extras ───────────────────────────────────────────────
    section("STEP 2  —  WANT TO ADD MORE DETAIL?")
    console.print("  [dim]More info = more realistic guess list. All optional.[/]\n")

    want_more = yes_no("Would you like to add anything else?", default_yes=True)

    if want_more:
        extra_menu = [
            ("Family members",       "parent, sibling, child — names people weave into passwords"),
            ("Important dates",      "anniversary, graduation year"),
            ("Places",               "school, workplace, street name"),
            ("Online identity",      "username / handle, email prefix"),
            ("Lucky number",         "a number with personal meaning"),
            ("Phone last 4 digits",  "commonly appended to weak passwords"),
            ("Favorites",            "favorite color, band/artist, sport team, hobby"),
            ("Car",                  "make or model — surprisingly common"),
        ]

        subheading("Select categories to fill in:")
        chosen = numbered_menu(extra_menu, multi=True)

        if 0 in chosen:
            section("FAMILY MEMBERS")
            info["mother_name"]  = prompt("Mother's name (or maiden name)")
            info["father_name"]  = prompt("Father's name")
            info["sibling_name"] = prompt("Sibling's name")
            info["child_name"]   = prompt("Child's name")

        if 1 in chosen:
            section("IMPORTANT DATES")
            info["anniversary"] = prompt("Anniversary date", "e.g. 2015-06-20")
            info["grad_year"]   = prompt("Graduation year",   "e.g. 2008")

        if 2 in chosen:
            section("PLACES")
            info["school"]    = prompt("School name",    "e.g. Lincoln High")
            info["workplace"] = prompt("Workplace name", "e.g. Google, NHS")
            info["street"]    = prompt("Street name",    "e.g. Maple, Oak")

        if 3 in chosen:
            section("ONLINE IDENTITY")
            info["username"]     = prompt("Username / online handle")
            info["email_prefix"] = prompt("Email prefix (the part before @)")

        if 4 in chosen:
            section("LUCKY NUMBER")
            info["lucky_number"] = prompt("Lucky / favourite number")

        if 5 in chosen:
            info["phone_last4"] = prompt("Last 4 digits of your phone number")

        if 6 in chosen:
            section("FAVORITES")
            info["fav_color"]      = prompt("Favorite color")
            info["fav_band"]       = prompt("Favorite band or artist")
            info["fav_sport_team"] = prompt("Favorite sports team")
            info["hobby"]          = prompt("A hobby or activity you love")

        if 7 in chosen:
            info["car"] = prompt("Car make or model", "e.g. Honda, Mustang, Golf")

    # ── Step 2b: custom words ─────────────────────────────────────────────────
    section("STEP 2b  —  ADD YOUR OWN CUSTOM WORDS  (optional)")
    console.print("  [dim]Paste anything: foods, places, phrases, names — whatever you like.[/]")
    want_custom = yes_no("Would you like to add custom words?", default_yes=True)
    if want_custom:
        info["custom_words"] = collect_custom_words(max_items=100)
    else:
        info["custom_words"] = []

    # ── build guesses ─────────────────────────────────────────────────────────
    section("STEP 3  —  BUILDING GUESS LIST")
    with console.status("[bright_red]Generating combinations...[/]", spinner="dots"):
        guesses = build_guesses(info)
        if args.no_keyboard:
            guesses = [(g, s) for g, s in guesses if s != "keyboard pattern / common password"]
        time.sleep(0.3)

    if not guesses:
        console.print("\n  [yellow]No details entered — nothing to build guesses from. Exiting.[/]")
        return

    if args.list:
        for g, _ in guesses:
            print(g)
        return

    # ── pre-run summary ───────────────────────────────────────────────────────
    console.print()
    console.print(Panel(
        f"[bold white]✦  {len(guesses):,} candidate guesses built  ✦[/]\n"
        "[dim]from all the details you provided[/]",
        border_style="bright_red"))

    # ── mode selection ────────────────────────────────────────────────────────
    section("STEP 4  —  CHOOSE MODE")
    console.print()
    console.print("  [bright_red][1][/]  [bold white]Manual check[/]   [dim]— shows each guess, you press y/n to match[/]")
    console.print("  [bright_red][2][/]  [bold white]Auto-type[/]      [dim]— types passwords into your target window · F1 to stop[/]")
    console.print()
    try:
        mode_choice = console.input("  [bright_red]▸[/] [bold red]Mode[/]: ").strip()
    except EOFError:
        mode_choice = "1"

    if mode_choice == "2":
        console.print()
        try:
            delay_raw = console.input(
                "  [bright_red]▸[/] [bold red]Delay between passwords ms (default 10, min 0)[/]: ").strip()
            delay_ms = max(0, int(delay_raw)) if delay_raw.isdigit() else 10
        except EOFError:
            delay_ms = 300

        try:
            enter_raw = console.input(
                "  [bright_red]▸[/] [bold red]Press Enter after each password? (Y/n)[/]: ").strip().lower()
            press_enter = enter_raw not in ("n", "no")
        except EOFError:
            press_enter = True

        try:
            cd_raw = console.input(
                "  [bright_red]▸[/] [bold red]Seconds to switch window (default 5)[/]: ").strip()
            cd_secs = max(1, int(cd_raw)) if cd_raw.isdigit() else 5
        except EOFError:
            cd_secs = 5

        console.print()
        console.print(Rule("[dim red]  CONFIRM  [/]", style="dim red"))
        console.print(f"  [dim]Passwords [/]  [bold white]{len(guesses):,}[/]")
        console.print(f"  [dim]Delay     [/]  [bold white]{delay_ms}ms[/]  [dim]per attempt[/]")
        console.print(f"  [dim]Enter key [/]  [bold white]{'YES' if press_enter else 'NO'}[/]")
        console.print(f"  [dim]Countdown [/]  [bold white]{cd_secs}s[/]  [dim]then starts typing[/]")
        console.print(f"  [dim]Stop      [/]  [bold bright_red]F1[/]  [dim]— works even when target window is focused[/]")
        console.print()
        try:
            go = console.input("  [bright_red]▸[/] [bold red]Start? (Y/n)[/]: ").strip().lower()
        except EOFError:
            go = "y"
        if go in ("n", "no"):
            console.print("\n  [yellow]Aborted.[/]\n")
            return

        _auto_type_guesses(guesses, delay_ms, press_enter, cd_secs)
        return

    section("STEP 4  —  CHECK EACH GUESS AGAINST YOUR REAL PASSWORD")
    console.print()
    console.print(f"  [bold bright_green]{CHECK}[/]  [bold green]y[/]            →  [white]it matches — stop here[/]")
    console.print(f"  [bold bright_red]{CROSS}[/]  [red]n  or Enter[/]   →  [dim]no match, next guess[/]")
    console.print(f"  [bold bright_red]{ARROW}[/]  [red]q[/]            →  [dim]quit early[/]")
    console.print()
    try:
        console.input("  [bold bright_red]─── Press Enter to begin ───[/] ")
    except EOFError:
        pass
    console.print()

    # ── main checking loop ────────────────────────────────────────────────────
    total    = len(guesses)
    cracked  = False
    eof_quit = False

    for idx, (guess, source) in enumerate(guesses, start=1):
        pct = int(100 * (idx - 1) / total) if total else 100
        bar_color = "bright_red" if pct < 40 else ("red" if pct < 75 else "bright_green")
        filled = int(32 * (idx - 1) / total) if total else 32
        bar = ("[" + bar_color + "]" + "█" * filled + "[/]"
               + "[dim white]" + "░" * (32 - filled) + "[/]")
        console.print(f"\n  {bar}  [bold white]{pct:>3}%[/]  [dim]{idx-1:,}/{total:,}[/]")

        sc = source_style(source)
        console.print(Rule(style="dim red"))
        console.print(f"  [bright_red]{ARROW}[/]  [bold white]{guess}[/]   [{sc}]{source}[/]")
        console.print(Rule(style="dim red"))

        try:
            answer = console.input(
                "  Match? [[bold green]y[/] = yes  [red]n[/] = no  [red]q[/] = quit]: "
            ).strip().lower()
        except EOFError:
            eof_quit = True
            break

        if answer == "q":
            console.print("\n  [yellow]Stopped early.[/]")
            return

        if answer == "y":
            elapsed = time.time() - start_time
            console.print()
            console.print(Panel(
                f"[bold red]{CROSS}  CRACKED  after {idx:,} guess{'es' if idx != 1 else ''}  {CROSS}[/]\n\n"
                f"[bold]Password :[/]  [bold yellow]{guess}[/]\n"
                f"[bold]Source   :[/]  [dim]{source}[/]\n"
                f"[bold]Guesses  :[/]  [dim]#{idx:,} of {total:,}[/]\n"
                f"[bold]Time     :[/]  [dim]{elapsed:.1f}s[/]",
                title="[bold red]Result[/]", border_style="bright_red"))
            console.print()
            console.print("  [bold bright_red]⚠  This password is guessable from public info.[/]")
            console.print("     [white]Change it immediately — treat it as compromised.[/]")
            cracked = True
            break

    elapsed = time.time() - start_time

    if eof_quit and not cracked:
        console.print("\n  [yellow]Input ended before all guesses were checked — result is inconclusive.[/]")
        return

    if not cracked:
        console.print()
        console.print(Panel(
            f"[bold bright_green]{CHECK}  NONE OF {total:,} GUESSES MATCHED  {CHECK}[/]\n\n"
            f"[bold]Guesses tried :[/]  [dim]{total:,}[/]\n"
            f"[bold]Time taken    :[/]  [dim]{elapsed:.1f}s[/]",
            title="[bold green]Result[/]", border_style="green"))
        console.print()
        console.print(f"  [bright_green]{CHECK} Good — your password isn't a direct personal-detail guess.[/]")
        console.print("    [dim]It could still fall to a full dictionary / brute-force attack.[/]")

    # ── security tips ─────────────────────────────────────────────────────────
    console.print()
    subheading("Security tips")
    for tip in strength_tips():
        console.print(f"    [bright_red]{BULLET}[/]  [white]{tip}[/]")
    console.print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n  [yellow]Stopped.[/]")
        sys.exit(0)
