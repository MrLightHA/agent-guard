
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

SECRET_NAME_RE = re.compile(
    r"""(^|[\\/])(
        [\w.-]*\.env(\.(?!example$|sample$|template$|dist$)[\w.-]+)? |   # .env, test.env, .env.local (not .env.example)
        id_rsa | id_ed25519 | id_ecdsa | id_dsa |
        .*\.pem | .*\.key | .*\.p12 | .*\.pfx | .*\.keystore | .*\.jks |
        credentials(\.json)? | \.netrc | \.pgpass | \.npmrc | \.pypirc |
        secrets?\.(json|ya?ml|toml) | service[-_]account.*\.json
    )$""",
    re.X | re.I,
)
SECRET_DIR_RE = re.compile(r"(^|[\\/])(\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.config[\\/]gcloud)([\\/]|$)", re.I)


def is_secret_path(p: str) -> bool:
    p = p.strip().strip("'\"")
    return bool(SECRET_NAME_RE.search(p) or SECRET_DIR_RE.search(p))


SECRET_VALUES = [
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key"),
    (r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "GitHub token"),
    (r"\bgithub_pat_[A-Za-z0-9_]{60,}\b", "GitHub token"),
    (r"\bsk-ant-[A-Za-z0-9_-]{20,}", "Anthropic API key"),
    (r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}", "OpenAI API key"),
    (r"\b[rs]k_live_[0-9A-Za-z]{20,}\b", "Stripe live key"),
    (r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", "Slack token"),
    (r"\bAIza[0-9A-Za-z_-]{35}\b", "Google API key"),
    (r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b", "Telegram bot token"),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", "private key"),
]
SECRET_VALUES = [(re.compile(rx), name) for rx, name in SECRET_VALUES]
PLACEHOLDER_RE = re.compile(r"example|x{4,}|0{6,}|your|dummy|placeholder|fake|test_?key|\.\.\.", re.I)


def find_secret(text: str):
    if not text:
        return None
    for rx, name in SECRET_VALUES:
        for m in rx.finditer(text):
            v = m.group(0)
            if name != "private key" and (PLACEHOLDER_RE.search(v) or len(set(v)) < 10):
                continue
            return name
    return None


def redact(text):
    if not isinstance(text, str):
        return text
    for rx, _ in SECRET_VALUES:
        text = rx.sub(lambda m: m.group(0)[:6] + "...[redacted]", text)
    return text


def _git(cwd: Path, *args) -> str:
    try:
        r = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, timeout=5)
        return r.stdout.decode("utf-8", errors="replace") if r.returncode == 0 else ""
    except Exception:
        return ""


def check_commit(toks, cwd: Path):
    all_flag = "--all" in toks or any(t.startswith("-") and not t.startswith("--") and "a" in t for t in toks[2:])
    names = _git(cwd, "diff", "--cached", "--name-only").split()
    diff = _git(cwd, "diff", "--cached", "-U0")
    if all_flag:
        names += _git(cwd, "diff", "--name-only").split()
        diff += _git(cwd, "diff", "-U0")
    for n in names:
        if is_secret_path(n):
            return "deny", f"commit includes secret file '{n}'"
    current = "?"
    for line in diff[:2_000_000].splitlines():
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else line[4:]
        elif line.startswith("+") and not line.startswith("+++"):
            name = find_secret(line)
            if name:
                return "deny", f"commit adds a {name} in '{current}'"
    return None


SHELL_RULES = [
    # infrastructure / databases
    (r"\bterraform\s+(destroy|apply\b[^|;&]*-destroy)", "deny", "terraform destroy wipes real infrastructure"),
    (r"\b(pulumi|cdk|serverless|sls)\s+(destroy|remove)\b", "deny", "infrastructure destroy command"),
    (r"\bdrop\s+(database|schema|table)\b", "deny", "SQL DROP removes data permanently"),
    (r"\btruncate\s+(table\s+)?\w", "deny", "SQL TRUNCATE removes all rows"),
    (r"\bdelete\s+from\s+\w+\s*(;|$|\"|')", "deny", "DELETE without WHERE removes all rows"),
    (r"\b(dropdb|mongo\w*\b.*dropDatabase|redis-cli\b.*\bflushall)", "deny", "database wipe"),
    (r"volume\s*delete|volumeDelete|\brailway\s+(down|delete)", "deny", "deleting a hosted volume/service"),
    (r"\bkubectl\s+delete\s+(ns|namespace|pv|pvc|deployment|all)\b", "deny", "kubectl delete on core resources"),
    (r"\baws\s+s3\s+(rb|rm)\b.*--recursive|\baws\s+s3\s+rb\b.*--force", "deny", "recursive S3 delete"),
    (r"\baws\s+(rds|dynamodb|ec2)\s+delete-|\baws\s+ec2\s+terminate-instances", "deny", "AWS resource deletion"),
    (r"\bgcloud\b.*\bdelete\b", "ask", "gcloud delete command"),
    (r"\bdocker\s+(system|volume)\s+prune\b|\bdocker\s+volume\s+rm\b", "ask", "removes Docker volumes/data"),
    # disks / system
    (r"\b(mkfs(\.\w+)?|fdisk|diskpart|format\s+[a-z]:)", "deny", "disk formatting"),
    (r"\bdd\s+[^|;&]*of=/dev/", "deny", "raw write to a disk device"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "deny", "fork bomb"),
    (r"\bchmod\s+(-R\s+)?777\s+/(\s|$)|\bchown\s+-R\b[^|;&]*\s/(\s|$)", "deny", "recursive permission change on /"),
    # git history
    (r"\bgit\s+push\b[^|;&]*(--force\b|-f\b|--force-with-lease)", "ask", "force push rewrites remote history"),
    (r"\bgit\s+reset\s+--hard\b", "ask", "git reset --hard discards uncommitted work"),
    (r"\bgit\s+clean\s+-[a-z]*f", "ask", "git clean deletes untracked files"),
    (r"\bgit\s+(checkout|restore)\s+(--\s+)?\.(\s|$)", "ask", "discards all local changes"),
    (r"\bgit\s+branch\s+-D\b", "ask", "force-deletes a branch"),
    (r"\bgit\s+filter-(branch|repo)\b", "ask", "rewrites git history"),
    # remote code
    (r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^|;&]*\|\s*(sudo\s+)?(sh|bash|zsh|python\d?|iex|Invoke-Expression)\b", "deny", "piping downloaded code into a shell"),
    # Windows destructive
    (r"\b(rmdir|rd)\s+[^|;&]*/s\b", "ask", "recursive directory delete (Windows)"),
    (r"\bdel\s+[^|;&]*/s\b", "ask", "recursive delete (Windows)"),
    (r"Remove-Item\b[^|;&]*-Recurse", "ask", "recursive delete (PowerShell)"),
    # secret dumping
    (r"(^|[;&|]\s*)(printenv|env|set|Get-ChildItem\s+env:|gci\s+env:)\s*($|[;&|>])", "ask", "dumps all environment variables (may contain keys)"),
    (r"\$\{?\w*(API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY)\w*\}?", "ask", "command reads a secret environment variable"),
]
SHELL_RULES = [(re.compile(rx, re.I), d, r) for rx, d, r in SHELL_RULES]

SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;|\||\n)\s*")
ROOTISH = {"/", "~", "~/", "$HOME", "${HOME}", "$HOME/", "/*", "~/*", "*", ".", "./", "..", "../", "C:\\", "C:/", "%USERPROFILE%"}


def _win_path(t: str) -> str:
    """Git Bash style /c/Users/... -> C:/Users/... (only on Windows)."""
    if os.name == "nt":
        m = re.match(r"^/([a-zA-Z])(/|$)(.*)", t)
        if m:
            return f"{m.group(1).upper()}:/{m.group(3)}"
    return t


def _resolve(target: str, cwd: Path) -> Path:
    t = _win_path(os.path.expandvars(os.path.expanduser(target)))
    p = Path(t)
    if not p.is_absolute():
        p = cwd / p
    return Path(os.path.normpath(str(p)))


def _inside(p: Path, root: Path) -> bool:
    try:
        p.relative_to(root)
        return True
    except ValueError:
        return False


def check_rm(segment: str, cwd: Path, project: Path):
    """Analyse an 'rm' invocation. Returns (decision, reason) or None."""
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        tokens = segment.split()
    while tokens and (tokens[0] in ("sudo", "doas", "command", "builtin") or "=" in tokens[0]):
        tokens = tokens[1:]
    if not tokens or os.path.basename(tokens[0]) not in ("rm", "unlink", "shred"):
        return None

    flags = "".join(t.lstrip("-") for t in tokens[1:] if t.startswith("-") and t != "--")
    recursive = "r" in flags.lower() or "--recursive" in tokens
    targets = [t for t in tokens[1:] if not t.startswith("-")]
    if "--no-preserve-root" in tokens:
        return "deny", "rm --no-preserve-root"

    for t in targets:
        if t in ROOTISH or t.rstrip("/") in ("~", "$HOME", "${HOME}", ""):
            return "deny", f"rm targets '{t}' (home/root/whole directory)"
        if is_secret_path(t):
            return "deny", f"rm targets a secret/key file '{t}'"
        p = _resolve(t, cwd)
        if ".git" in p.parts:
            return "deny", "rm touches the .git directory (no undo after that)"
        if p == project:
            return "deny", "rm would delete the whole project"
        if not _inside(p, project):
            return "deny", f"rm targets '{t}' outside the project ({project})"
        if recursive and "*" in t and p.parent == project:
            return "ask", f"recursive wildcard delete in project root: '{t}'"
    if recursive and not targets:
        return None
    return None


def check_bash(cmd: str, cwd: Path, project: Path):
    worst = None
    for rx, decision, reason in SHELL_RULES:
        if rx.search(cmd):
            if decision == "deny":
                return decision, reason
            worst = worst or (decision, reason)
    for seg in SPLIT_RE.split(cmd):
        seg = seg.strip().lstrip("(").strip()
        if not seg:
            continue
        r = check_rm(seg, cwd, project)
        if r and r[0] == "deny":
            return r
        worst = worst or r
        # reading secret files via shell (cat .env, type id_rsa, etc.)
        try:
            toks = shlex.split(seg)
        except ValueError:
            toks = seg.split()
        if toks and os.path.basename(toks[0]) in (
            "cat", "less", "more", "head", "tail", "type", "bat", "nl", "xxd", "od", "strings",
            "grep", "rg", "awk", "sed", "cp", "scp", "curl", "base64", "Get-Content", "gc",
        ):
            for t in toks[1:]:
                if not t.startswith("-") and is_secret_path(t):
                    return "deny", f"command reads secret file '{t}'"
        if len(toks) > 1 and os.path.basename(toks[0]) == "git":
            if toks[1] == "add":
                for t in toks[2:]:
                    if not t.startswith("-") and is_secret_path(t):
                        return "deny", f"git add of secret file '{t}'"
            elif toks[1] == "commit":
                r = check_commit(toks, cwd)
                if r:
                    return r
    name = find_secret(cmd)
    if name and re.search(r">|\btee\b|\bsed\s+-i|\bgit\s+commit|Set-Content|Out-File|Add-Content", cmd):
        return "deny", f"command writes a {name} into a file, use an env variable instead"
    return worst


# ------------------------------------------------------------ file tools ---

def check_file_tool(tool: str, ti: dict, cwd: Path, project: Path):
    path = ti.get("file_path") or ti.get("path") or ti.get("notebook_path") or ""
    if path and is_secret_path(path):
        return "deny", f"{tool} on secret file '{path}', keep keys out of the agent's context"
    if tool in ("Grep", "Glob"):
        pat = str(ti.get("pattern", "")) + " " + str(ti.get("glob", ""))
        if re.search(r"\.env\b|\benv\b|id_rsa|\.pem\b|credentials", pat, re.I):
            return "deny", f"{tool} pattern targets secret files"
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        parts = [ti.get("content"), ti.get("new_string"), ti.get("new_source")]
        parts += [e.get("new_string") for e in ti.get("edits") or [] if isinstance(e, dict)]
        name = find_secret("\n".join(str(x) for x in parts if x))
        if name:
            return "deny", f"{tool} writes a {name} into '{path}', use an env variable instead"
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit") and path:
        p = _resolve(path, cwd)
        if not _inside(p, project):
            return "ask", f"{tool} outside the project: {p}"
        if ".git" in p.parts:
            return "deny", f"{tool} inside .git"
    return None


# ------------------------------------------------------------------ main ---

def decide(event: dict):
    tool = event.get("tool_name", "")
    ti = event.get("tool_input") or {}
    cwd = Path(_win_path(event.get("cwd") or os.getcwd()))
    project = Path(os.path.normpath(_win_path(os.environ.get("CLAUDE_PROJECT_DIR") or str(cwd))))
    if tool == "Bash" or tool == "PowerShell":
        return check_bash(str(ti.get("command", "")), cwd, project)
    if tool in ("Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Grep", "Glob"):
        return check_file_tool(tool, ti, cwd, project)
    return None


def log(event: dict, result):
    try:
        path = Path(os.environ.get("AGENT_GUARD_LOG") or Path.home() / ".agent-guard" / "log.jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        ti = event.get("tool_input") or {}
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "session": event.get("session_id"),
            "cwd": event.get("cwd"),
            "tool": event.get("tool_name"),
            "input": redact(ti.get("command") or ti.get("file_path") or ti.get("path") or ti.get("pattern")),
            "decision": result[0] if result else "pass",
            "reason": result[1] if result else None,
        }
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def main():
    try:
        raw = sys.stdin.buffer.read()  # always UTF-8 from Claude Code; avoid cp1251 on Windows
        event = json.loads(raw.decode("utf-8-sig", errors="replace") or "{}")
    except Exception:
        return 0  # never break the agent on bad input
    try:
        result = decide(event)
    except Exception as e:  # a bug in the guard must not block work
        log(event, ("error", repr(e)))
        return 0
    log(event, result)
    if not result or os.environ.get("AGENT_GUARD_MODE") == "warn":
        return 0
    decision, reason = result
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": f"[agent-guard] {reason}",
        }
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
