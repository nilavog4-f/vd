#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
# ##  VOID Git Leak Scanner — Public Repo Secret Exposure Auditor
# ##  ** Scans public GitHub repos/orgs for leaked credentials **
# ##  WSL / Kali Linux Edition  ·  @lfw.k4rma_
# ##  For authorized use / defensive research on public data only.
# ══════════════════════════════════════════════════════════════════

import subprocess, sys, os

def _ensure_deps():
    mods = {
        "requests": "requests",
        "rich":     "rich",
        "pyfiglet": "pyfiglet",
    }
    for mod, pkg in mods.items():
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
import json, re, time, math, base64
from datetime import datetime
import requests

from rich.console  import Console
from rich.table    import Table
from rich.text     import Text
from rich.align    import Align
from rich.rule     import Rule
from rich.panel    import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich          import box
import pyfiglet

console = Console()

API_ROOT = "https://api.github.com"
RAW_ROOT = "https://raw.githubusercontent.com"

SESS = requests.Session()
SESS.headers.update({
    "User-Agent": "void-osint-leak-scanner",
    "Accept": "application/vnd.github+json",
})

TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
if TOKEN:
    SESS.headers["Authorization"] = f"Bearer {TOKEN}"

REPORT_DIR = "reports"

# Skip obviously irrelevant paths — binary blobs, deps, build output.
SKIP_EXT = {
    ".png",".jpg",".jpeg",".gif",".ico",".svg",".webp",".bmp",".pdf",
    ".zip",".tar",".gz",".7z",".rar",".woff",".woff2",".ttf",".eot",
    ".mp4",".mp3",".mov",".avi",".exe",".dll",".so",".bin",".class",
    ".jar",".lock",".map",".min.js",".min.css",
}
SKIP_DIR_PARTS = {
    "node_modules","vendor","dist","build",".git","target",
    "venv",".venv","__pycache__",".next","coverage",
}
MAX_FILE_BYTES = 300_000  # skip huge generated files

# ## Secret signatures ############################################
# (name, compiled regex, severity)  — patterns tuned for common leak types.
SIGNATURES = [
    ("AWS Access Key ID",       re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("AWS Secret Access Key",   re.compile(r"(?i)aws(.{0,20})?(secret|access)[_-]?key(.{0,3})?[\"'=:\s]+([A-Za-z0-9/+=]{40})"), "critical"),
    ("GitHub Token",            re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), "critical"),
    ("GitHub Fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"), "critical"),
    ("Slack Token",             re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,72}\b"), "critical"),
    ("Slack Webhook",           re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,60}"), "high"),
    ("Stripe Live Key",         re.compile(r"\bsk_live_[A-Za-z0-9]{16,64}\b"), "critical"),
    ("Stripe Restricted Key",   re.compile(r"\brk_live_[A-Za-z0-9]{16,64}\b"), "high"),
    ("Google API Key",          re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
    ("Google OAuth Client ID",  re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b"), "medium"),
    ("Firebase / GCP Cred",     re.compile(r"\"type\"\s*:\s*\"service_account\""), "critical"),
    ("Twilio API Key",          re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high"),
    ("SendGrid API Key",        re.compile(r"\bSG\.[A-Za-z0-9_\-\.]{22,60}\b"), "high"),
    ("Mailgun API Key",         re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "medium"),
    ("Heroku API Key",          re.compile(r"(?i)heroku(.{0,20})?api[_-]?key(.{0,3})?[\"'=:\s]+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "high"),
    ("OpenAI API Key",          re.compile(r"\bsk-[A-Za-z0-9]{20,60}\b"), "high"),
    ("OpenRouter API Key",      re.compile(r"\bsk-or-v1-[A-Za-z0-9]{32,80}\b"), "high"),
    ("Anthropic API Key",       re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,100}\b"), "high"),
    ("Generic Bearer JWT",      re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "medium"),
    ("Private Key Block",       re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP|DSA)?\s?PRIVATE KEY-----"), "critical"),
    ("Generic .env Secret",     re.compile(r"(?im)^\s*[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY)[A-Z0-9_]*\s*=\s*[\"']?[A-Za-z0-9/\+\-_\.]{12,}[\"']?\s*$"), "medium"),
    ("Basic Auth in URL",       re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s:@]+@[^\s\"'<>]+"), "medium"),
]

SEVERITY_COLOR = {
    "critical": "bold bright_red",
    "high":     "bright_red",
    "medium":   "yellow",
    "low":      "dim white",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

TEXT_LIKE_HINTS = (
    ".env",".yml",".yaml",".json",".txt",".cfg",".ini",".conf",".toml",
    ".py",".js",".ts",".tsx",".jsx",".rb",".go",".java",".php",".sh",
    ".ps1",".xml",".properties",".gradle",".pem",".key",".sql",".md",
)

# ## Banner ########################################################
def banner():
    console.clear()
    fig = pyfiglet.figlet_format("LEAK  SCAN", font="doom")
    colors = ["bright_green","green","bright_cyan","cyan",
              "bright_green","green","bright_cyan","cyan"]
    txt = Text()
    for i, line in enumerate(fig.splitlines()):
        txt.append(line + "\n", style=colors[i % len(colors)])
    console.print(Align.center(txt))

    sub = Text()
    sub.append("  ◈ ", style="bright_green")
    sub.append("GIT / PUBLIC REPO LEAK SCANNER", style="bold bright_white")
    sub.append(" ◈  ", style="bright_green")
    console.print(Align.center(sub))

    tags = Text()
    for label, sep in [
        ("File Secrets", " | "), ("Commit History", " | "),
        ("Entropy Check", " | "), ("Risk Scoring", ""),
    ]:
        tags.append(label, style="bright_green")
        if sep: tags.append(sep, style="dim green")
    console.print(Align.center(tags))
    console.print(Align.center(
        Text("by @lfw.k4rma_  ·  PUBLIC DATA ONLY  ·  FOR AUTHORIZED USE\n",
             style="dim green")))
    console.print(Rule(style="bright_green"))

# ## HTTP helpers ##################################################
_rate_warned = False

def _api_get(url, params=None):
    global _rate_warned
    try:
        r = SESS.get(url, params=params, timeout=15)
    except Exception as e:
        console.print(f"  [dim red]request failed: {e}[/]")
        return None
    if r.status_code == 403 and "rate limit" in r.text.lower():
        remaining = r.headers.get("X-RateLimit-Remaining", "0")
        reset = r.headers.get("X-RateLimit-Reset", "")
        if not _rate_warned:
            msg = f"  [bold yellow]![/] GitHub API rate limit hit (remaining={remaining})."
            if not TOKEN:
                msg += " Set GITHUB_TOKEN env var for a higher limit (5000/hr vs 60/hr)."
            console.print(msg)
            _rate_warned = True
        return None
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        return None
    try:
        return r.json()
    except Exception:
        return None

def _raw_get(owner, repo, ref, path):
    url = f"{RAW_ROOT}/{owner}/{repo}/{ref}/{path}"
    try:
        r = SESS.get(url, timeout=15)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return None

# ## Target resolution #############################################
def resolve_repos(target: str, max_repos: int):
    """target can be 'owner/repo' (single) or 'owner' (user/org, list repos)."""
    target = target.strip().strip("/")
    if "/" in target:
        owner, repo = target.split("/", 1)
        data = _api_get(f"{API_ROOT}/repos/{owner}/{repo}")
        if not data:
            return []
        return [{"owner": owner, "name": data.get("name", repo),
                  "default_branch": data.get("default_branch", "main"),
                  "private": data.get("private", False)}]

    # try user first, then org
    repos = []
    for kind in ("users", "orgs"):
        data = _api_get(f"{API_ROOT}/{kind}/{target}/repos",
                         params={"per_page": min(max_repos, 100), "sort": "updated"})
        if data:
            for r in data[:max_repos]:
                repos.append({
                    "owner": target, "name": r.get("name"),
                    "default_branch": r.get("default_branch", "main"),
                    "private": r.get("private", False),
                })
            break
    return repos

def list_files(owner, repo, branch):
    data = _api_get(f"{API_ROOT}/repos/{owner}/{repo}/git/trees/{branch}",
                     params={"recursive": "1"})
    if not data or "tree" not in data:
        return []
    out = []
    for item in data["tree"]:
        if item.get("type") != "blob":
            continue
        path = item["path"]
        size = item.get("size", 0)
        if size and size > MAX_FILE_BYTES:
            continue
        parts = path.split("/")
        if any(p in SKIP_DIR_PARTS for p in parts):
            continue
        ext = os.path.splitext(path)[1].lower()
        if ext in SKIP_EXT:
            continue
        out.append(path)
    return out

def list_recent_commits(owner, repo, limit=8):
    data = _api_get(f"{API_ROOT}/repos/{owner}/{repo}/commits",
                     params={"per_page": limit})
    return data or []

def get_commit_patch(owner, repo, sha):
    data = _api_get(f"{API_ROOT}/repos/{owner}/{repo}/commits/{sha}")
    if not data:
        return []
    return data.get("files", [])

# ## Detection ######################################################
def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

def _redact(secret: str) -> str:
    secret = secret.strip()
    if len(secret) <= 10:
        return secret[:2] + "…" + secret[-2:]
    return secret[:6] + "…" + secret[-4:]

def scan_text(text: str, source: str):
    findings = []
    lines = text.splitlines()
    for name, pattern, sev in SIGNATURES:
        for m in pattern.finditer(text):
            snippet = m.group(0)
            line_no = text.count("\n", 0, m.start()) + 1
            line_text = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
            findings.append({
                "type": name, "severity": sev, "source": source,
                "line": line_no, "match": _redact(snippet),
                "context": line_text[:120],
            })

    # supplementary entropy scan for assignment-style secrets not caught above
    assign_re = re.compile(
        r"(?im)^\s*[\"']?([A-Za-z_][A-Za-z0-9_]{2,40})[\"']?\s*[:=]\s*[\"']([A-Za-z0-9/\+\-_\.]{20,100})[\"']\s*,?\s*$")
    keyword_hint = re.compile(r"(?i)secret|token|passwd|password|apikey|api_key|access_key|private")
    for m in assign_re.finditer(text):
        key, val = m.group(1), m.group(2)
        if not keyword_hint.search(key):
            continue
        ent = _shannon_entropy(val)
        if ent < 3.6:
            continue
        line_no = text.count("\n", 0, m.start()) + 1
        findings.append({
            "type": f"High-entropy value ({key})", "severity": "medium",
            "source": source, "line": line_no, "match": _redact(val),
            "context": (lines[line_no - 1].strip() if 0 < line_no <= len(lines) else "")[:120],
        })
    return findings

# ## Report ########################################################
def save_report(target: str, all_findings: list, repos_scanned: list):
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^A-Za-z0-9_.-]", "_", target)
    json_path = os.path.join(REPORT_DIR, f"leak_scan_{safe_target}_{ts}.json")
    md_path   = os.path.join(REPORT_DIR, f"leak_scan_{safe_target}_{ts}.md")

    with open(json_path, "w") as f:
        json.dump({
            "target": target, "generated": ts,
            "repos_scanned": repos_scanned,
            "findings": all_findings,
        }, f, indent=2)

    lines = [f"# Git Leak Scan Report — `{target}`", "", f"Generated: {ts}", "",
             f"Repos scanned: {len(repos_scanned)}", f"Findings: {len(all_findings)}", ""]
    if not all_findings:
        lines.append("No potential secrets detected in scanned files/commits.")
    else:
        lines.append("| Severity | Type | Source | Line | Match |")
        lines.append("|---|---|---|---|---|")
        for f_ in sorted(all_findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 9)):
            lines.append(f"| {f_['severity']} | {f_['type']} | {f_['source']} | {f_['line']} | `{f_['match']}` |")
    with open(md_path, "w") as f:
        f.write("\n".join(lines))
    return json_path, md_path

# ## Main scan flow #################################################
def run_scan(target: str, max_repos: int, scan_history: bool, commit_limit: int):
    repos = resolve_repos(target, max_repos)
    if not repos:
        console.print(Panel(
            f"[bold red]No public repos found for[/] [white]{target}[/]\n"
            "[dim]Check the username/org/owner-repo spelling, or you may be rate-limited.[/]",
            border_style="red"))
        return

    console.print(Panel(
        f"[bold white]Target:[/]  {target}\n"
        f"[bold white]Repos found:[/]  {len(repos)}  [dim](scanning up to {max_repos})[/]\n"
        f"[bold white]Commit history scan:[/]  {'on — last ' + str(commit_limit) + ' commits/repo' if scan_history else 'off'}\n"
        f"[bold white]Auth:[/]  {'GITHUB_TOKEN set (higher rate limit)' if TOKEN else 'unauthenticated (60 req/hr)'}",
        title="[bold bright_green]Scan Plan[/]", border_style="green"))
    console.print()

    all_findings = []
    repos_scanned_meta = []

    with Progress(
        SpinnerColumn(style="bright_green"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30, style="green", complete_style="bright_green"),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning repos…", total=len(repos))
        for repo in repos:
            owner, name, branch = repo["owner"], repo["name"], repo["default_branch"]
            progress.update(task, description=f"[green]{owner}/{name}[/]")
            repo_findings = []

            files = list_files(owner, name, branch)
            for path in files:
                ext = os.path.splitext(path)[1].lower()
                base = os.path.basename(path).lower()
                looks_textish = (ext in TEXT_LIKE_HINTS or "env" in base or
                                  base in ("dockerfile","makefile"))
                if not looks_textish:
                    continue
                content = _raw_get(owner, name, branch, path)
                if content is None:
                    continue
                found = scan_text(content, f"{owner}/{name}:{path}")
                repo_findings.extend(found)

            if scan_history:
                commits = list_recent_commits(owner, name, commit_limit)
                for c in commits:
                    sha = c.get("sha", "")[:7]
                    files_changed = get_commit_patch(owner, name, c.get("sha", ""))
                    for fc in files_changed:
                        patch = fc.get("patch", "")
                        if not patch:
                            continue
                        added_lines = "\n".join(
                            l[1:] for l in patch.splitlines() if l.startswith("+") and not l.startswith("+++"))
                        found = scan_text(added_lines, f"{owner}/{name}@{sha}:{fc.get('filename')}")
                        repo_findings.extend(found)

            all_findings.extend(repo_findings)
            repos_scanned_meta.append({
                "repo": f"{owner}/{name}", "files_checked": len(files),
                "findings": len(repo_findings),
            })
            progress.advance(task)
            time.sleep(0.15)  # be polite to the API

    console.print()
    console.print(Rule(style="bright_green"))
    console.print()

    if not all_findings:
        console.print(Panel(
            "[bold bright_green]No likely secrets found[/] across scanned files and commit history.\n"
            "[dim]Note: this checks default-branch files and recent commit diffs only — not a full history walk.[/]",
            title="[bold]Result[/]", border_style="green"))
    else:
        table = Table(box=box.SIMPLE_HEAVY, show_lines=False, expand=True)
        table.add_column("Sev", width=9)
        table.add_column("Type", style="white")
        table.add_column("Source", style="cyan", overflow="fold")
        table.add_column("Line", justify="right", width=6)
        table.add_column("Match", style="dim white")

        for f_ in sorted(all_findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 9)):
            color = SEVERITY_COLOR.get(f_["severity"], "white")
            table.add_row(
                Text(f_["severity"].upper(), style=color),
                f_["type"], f_["source"], str(f_["line"]), f_["match"])
        console.print(table)

        crit = sum(1 for f_ in all_findings if f_["severity"] == "critical")
        high = sum(1 for f_ in all_findings if f_["severity"] == "high")
        console.print()
        console.print(Panel(
            f"[bold]{len(all_findings)}[/] potential finding(s) — "
            f"[bold bright_red]{crit} critical[/], [bright_red]{high} high[/].\n"
            "[dim]Verify manually before acting — patterns can produce false positives.[/]",
            title="[bold red]Summary[/]", border_style="red"))

    json_path, md_path = save_report(target, all_findings, repos_scanned_meta)
    console.print()
    console.print(f"  [dim]Saved report →[/] [white]{json_path}[/]")
    console.print(f"  [dim]Saved report →[/] [white]{md_path}[/]")

# ## Entry ##########################################################
def main():
    banner()

    console.print()
    console.print("  [bright_green]◈[/]  Only scans [bold]public[/] GitHub data via the official API.")
    console.print("  [dim]Set the GITHUB_TOKEN env var beforehand for a higher rate limit (optional).[/]")
    console.print()

    target = console.input("  [bright_cyan]◈[/]  GitHub user, org, or owner/repo: ").strip()
    if not target:
        console.print("\n  [bold red][!][/]  No target given. Abort.")
        return

    max_repos_raw = console.input("  [bright_cyan]◈[/]  Max repos to scan [dim](default 5)[/]: ").strip()
    try:
        max_repos = int(max_repos_raw) if max_repos_raw else 5
    except ValueError:
        max_repos = 5
    max_repos = max(1, min(max_repos, 30))

    hist_raw = console.input("  [bright_cyan]◈[/]  Also scan recent commit history? [dim](y/N)[/]: ").strip().lower()
    scan_history = hist_raw in ("y", "yes")

    commit_limit = 8
    if scan_history:
        cl_raw = console.input("  [bright_cyan]◈[/]  Commits per repo to check [dim](default 8)[/]: ").strip()
        try:
            commit_limit = int(cl_raw) if cl_raw else 8
        except ValueError:
            commit_limit = 8
        commit_limit = max(1, min(commit_limit, 30))

    console.print()
    run_scan(target, max_repos, scan_history, commit_limit)
    console.print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n  [yellow][!][/]  Cancelled.")
        sys.exit(0)
