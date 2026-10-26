
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
RISKY_SCRIPT_RE = re.compile(
    r"\brm\s+(?:-\w+\s+)*-\w*[rR]\w*\s+(?:--\s+)?[\"']?(?:\$|~|/(?=[\s\"';]|$)|\*)[^\n]{0,60}"
    r"|shutil\.rmtree\(\s*(?:os\.path\.expanduser|Path\.home|os\.environ|['\"]/['\"])[^\n]{0,60}"
    r"|Remove-Item\b[^\n]*-Recurse[^\n]*\$(?:HOME|env:USERPROFILE)[^\n]{0,30}"
)
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

ROOTISH = {"/", "~", "~/", "$HOME", "${HOME}", "$HOME/", "/*", "~/*", "*", ".", "./", "..", "../", "C:\\", "C:/", "%USERPROFILE%"}
WRAPPERS = {"sudo", "doas", "command", "builtin", "exec", "nohup", "time", "nice", "env", "stdbuf", "ionice", "timeout"}
WRAPPER_FLAG_ARGS = {"-u", "-g", "-n", "-C", "-p", "-U", "-k", "-s"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "busybox"}
PWSH = {"pwsh", "powershell", "pwsh.exe", "powershell.exe"}
INTERPRETERS = {"python", "python3", "py", "node", "deno", "bun", "ruby", "perl", "php"}
READERS = {
    "cat", "less", "more", "head", "tail", "type", "bat", "nl", "xxd", "od", "strings",
    "grep", "rg", "awk", "sed", "cp", "scp", "curl", "base64", "Get-Content", "gc",
}
GIT_GLOBAL_WITH_ARG = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
FIND_FILTERS = {"-name", "-iname", "-path", "-ipath", "-type", "-regex", "-iregex", "-newer", "-mtime", "-mmin", "-size", "-empty", "-user"}
CODE_DELETE_RE = re.compile(
    r"rmtree|os\.remove|os\.unlink|os\.rmdir|removedirs|\.unlink\(|\.rmdir\(|send2trash"
    r"|rmSync|rmdirSync|unlinkSync|fs\.rm\(|fs\.promises\.rm|FileUtils\.rm|File\.delete|\bunlink\s*\(|\brmdir\s*\("
)
CODE_EXEC_RE = re.compile(r"os\.system|subprocess|child_process|execSync|spawnSync|\bsystem\s*\(|`")
STRING_RE = re.compile(r"""(['"])(.*?)(?<!\\)\1""")


def _win_path(t: str) -> str:
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


def split_commands(cmd: str):
    parts, cur, q, i, n = [], [], None, 0, len(cmd)
    while i < n:
        c = cmd[i]
        if q:
            cur.append(c)
            if c == "\\" and q == '"' and i + 1 < n:
                cur.append(cmd[i + 1])
                i += 2
                continue
            if c == q:
                q = None
        elif c in "'\"":
            q = c
            cur.append(c)
        elif c in ";\n" or (c in "&|" and not (cur and cur[-1] in "<>") and not (c == "&" and i + 1 < n and cmd[i + 1] == ">")):
            parts.append("".join(cur))
            cur = []
            if c in "&|" and i + 1 < n and cmd[i + 1] == c:
                i += 1
        else:
            cur.append(c)
        i += 1
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _cmd_name(tok: str) -> str:
    name = re.split(r"[\\/]", tok)[-1]
    return name[:-4] if name.lower().endswith(".exe") else name


def _is_root_like(t: str) -> bool:
    return bool(re.fullmatch(r"[\\/]+|[A-Za-z]:[\\/]*|[\\/]+\*|[A-Za-z]:[\\/]+\*", t))


def _tokens(seg: str):
    seg = re.sub(r"(?<![\w$])([A-Za-z]:\\[^\s\"']*)", lambda m: m.group(1).replace("\\", "/"), seg)
    try:
        t = shlex.split(seg, posix=True)
    except ValueError:
        t = seg.split()
    while t and t[0] in ("(", "{", "!"):
        t = t[1:]
    return t


def _unwrap(tokens):
    from_input = False
    while tokens:
        head = _cmd_name(tokens[0])
        if re.match(r"^\w+=", tokens[0]):
            tokens = tokens[1:]
        elif head in WRAPPERS or head == "xargs":
            from_input = from_input or head == "xargs"
            tokens = tokens[1:]
            while tokens and tokens[0].startswith("-"):
                flag = tokens[0]
                tokens = tokens[1:]
                if (flag in WRAPPER_FLAG_ARGS or (head == "xargs" and flag in ("-I", "-n", "-P", "-d", "-L", "-s", "-E"))) and tokens:
                    tokens = tokens[1:]
            if head == "timeout" and tokens and re.match(r"^\d", tokens[0]):
                tokens = tokens[1:]
        else:
            break
    return tokens, from_input


def check_targets(verb: str, targets, recursive: bool, cwd: Path, project: Path, from_input=False):
    if from_input and not targets:
        return ("deny" if recursive else "ask"), f"{verb} gets its targets from input, where they point can't be checked"
    for t in targets:
        if t in ROOTISH or t.rstrip("/") in ("~", "$HOME", "${HOME}", "") or _is_root_like(t):
            return "deny", f"{verb} targets '{t}' (home/root/whole directory)"
        if re.search(r"~\d", t):
            return "deny", f"{verb} target '{t}' uses a Windows short (8.3) name, where it points can't be checked"
        if is_secret_path(t):
            return "deny", f"{verb} targets a secret/key file '{t}'"
        if "$(" in t or "`" in t:
            return ("deny" if recursive else "ask"), f"{verb} target '{t}' is computed at run time, where it points can't be checked"
        if re.search(r"\$\{?\w", os.path.expandvars(os.path.expanduser(t))):
            return ("deny" if recursive else "ask"), f"{verb} target '{t}' uses a variable that is not set here, where it points can't be checked"
        p = _resolve(t, cwd)
        if ".git" in p.parts:
            return "deny", f"{verb} touches the .git directory (no undo after that)"
        if p == project:
            return "deny", f"{verb} would delete the whole project"
        if not _inside(p, project):
            return "deny", f"{verb} targets '{t}' outside the project ({project})"
        if recursive and ".claude" in p.parts:
            return "ask", f"recursive delete inside .claude ('{t}'), agent worktrees there may hold uncommitted work"
        if recursive and "*" in t and p.parent == project:
            return "ask", f"recursive wildcard delete in project root: '{t}'"
    return None


def check_rm(tokens, cwd: Path, project: Path, from_input=False):
    if "--no-preserve-root" in tokens:
        return "deny", "rm --no-preserve-root"
    flags = "".join(t.lstrip("-") for t in tokens[1:] if t.startswith("-") and t != "--")
    recursive = "r" in flags.lower() or "--recursive" in tokens
    targets = [t for t in tokens[1:] if not t.startswith("-") and not re.match(r"^\d*[<>]", t)]
    return check_targets(_cmd_name(tokens[0]), targets, recursive, cwd, project, from_input)


def check_find(tokens, cwd: Path, project: Path):
    destructive = "-delete" in tokens
    for i, t in enumerate(tokens):
        if t in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(tokens):
            if _cmd_name(tokens[i + 1]) in ("rm", "unlink", "shred", "rmdir"):
                destructive = True
    if not destructive:
        return None
    paths = []
    for t in tokens[1:]:
        if t.startswith("-") or t in ("(", ")", "!"):
            break
        paths.append(t)
    filtered = any(t in FIND_FILTERS for t in tokens)
    for t in paths or ["."]:
        if "$(" in t or "`" in t or re.search(r"\$\{?\w", os.path.expandvars(os.path.expanduser(t))):
            return "deny", f"find deletes under '{t}', where it points can't be checked"
        p = _resolve(t, cwd)
        if not _inside(p, project) or t in ("/", "~", "~/"):
            return "deny", f"find deletes under '{t}' outside the project ({project})"
        if ".git" in p.parts:
            return "deny", "find deletes inside .git (no undo after that)"
        if p == project and not filtered:
            return "deny", "find deletes everything in the project"
    return None


def check_inline_code(lang: str, code: str, cwd: Path, project: Path, depth: int):
    literals = [m.group(2) for m in STRING_RE.finditer(code)]
    for lit in literals:
        if is_secret_path(lit):
            return "deny", f"inline {lang} code reads secret file '{lit}'"
    if CODE_EXEC_RE.search(code):
        for lit in literals:
            r = check_bash(lit, cwd, project, depth + 1)
            if r and r[0] == "deny":
                return r
    if CODE_DELETE_RE.search(code):
        if not literals:
            return "ask", f"inline {lang} code deletes files, which ones can't be checked"
        r = check_targets(lang, literals, True, cwd, project)
        if r:
            return r
    return None


def parse_git(tokens):
    i = 1
    while i < len(tokens):
        t = tokens[i]
        if t in GIT_GLOBAL_WITH_ARG:
            i += 2
        elif t.startswith("-"):
            i += 1
        else:
            return t, tokens[i + 1:]
    return None, []


def check_git(verb, args, cwd: Path, project: Path):
    short = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
    longs = {a.split("=")[0] for a in args if a.startswith("--")}
    plain = [a for a in args if not a.startswith("-")]
    if verb == "push":
        if longs & {"--force", "--force-with-lease", "--force-if-includes", "--mirror"} or "f" in short or any(a.startswith("+") for a in plain):
            return "ask", "force push rewrites remote history"
        if "--delete" in longs or "d" in short or any(a.startswith(":") and len(a) > 1 for a in plain):
            return "ask", "push deletes a remote branch"
    elif verb == "reset" and "--hard" in longs:
        return "ask", "git reset --hard discards uncommitted work"
    elif verb == "clean" and ("--force" in longs or "f" in short):
        return "ask", "git clean deletes untracked files"
    elif verb in ("checkout", "restore") and any(a in (".", "./", ":/") for a in plain):
        return "ask", "discards all local changes"
    elif verb == "branch" and ("D" in short or ("--delete" in longs and "--force" in longs)):
        return "ask", "force-deletes a branch"
    elif verb in ("filter-branch", "filter-repo"):
        return "ask", "rewrites git history"
    elif verb == "stash" and plain[:1] == ["clear"]:
        return "ask", "git stash clear deletes all stashes"
    elif verb == "add":
        for a in plain:
            if is_secret_path(a):
                return "deny", f"git add of secret file '{a}'"
    elif verb == "rm":
        if "r" in short and any(a in (".", "./", "*", ":/", ":/*") for a in plain):
            return "deny", "git rm -r on the whole project deletes every tracked file from disk"
    elif verb == "commit":
        return check_commit(["git", "commit", *args], cwd)
    return None


def check_segment(seg: str, cwd: Path, project: Path, depth: int):
    tokens, from_input = _unwrap(_tokens(seg))
    if not tokens:
        return None
    head = _cmd_name(tokens[0])
    low = head.lower()
    if tokens[0].startswith("$") or "$(" in tokens[0] or "`" in tokens[0]:
        return "ask", f"the command '{tokens[0]}' is a variable or computed at run time, what runs can't be checked"
    if head in ("rm", "unlink", "shred"):
        return check_rm(tokens, cwd, project, from_input)
    if head in READERS:
        for t in tokens[1:]:
            if not t.startswith("-") and is_secret_path(t):
                return "deny", f"command reads secret file '{t}'"
        return None
    if head == "git":
        verb, args = parse_git(tokens)
        return check_git(verb, args, cwd, project) if verb else None
    if head == "find":
        return check_find(tokens, cwd, project)
    if head == "eval":
        return check_bash(" ".join(tokens[1:]), cwd, project, depth + 1)
    if head in SHELLS:
        for i, t in enumerate(tokens[1:], 1):
            if t.startswith("-") and not t.startswith("--") and "c" in t and i + 1 < len(tokens):
                return check_bash(tokens[i + 1], cwd, project, depth + 1)
        return None
    if low in PWSH:
        for i, t in enumerate(tokens[1:], 1):
            if t.lower() in ("-c", "-command") and i + 1 < len(tokens):
                return check_bash(" ".join(tokens[i + 1:]), cwd, project, depth + 1)
        return None
    if low in ("cmd", "cmd.exe"):
        for i, t in enumerate(tokens[1:], 1):
            if t.lower() in ("/c", "/k") and i + 1 < len(tokens):
                return check_bash(" ".join(tokens[i + 1:]), cwd, project, depth + 1)
        return None
    if head in INTERPRETERS or re.match(r"^python\d(\.\d+)?$", head):
        for i, t in enumerate(tokens[1:], 1):
            if t in ("-c", "-e", "--eval", "-r", "-E") and i + 1 < len(tokens):
                return check_inline_code(head, tokens[i + 1], cwd, project, depth)
        return None
    return None


def check_bash(cmd: str, cwd: Path, project: Path, depth: int = 0):
    if depth > 4:
        return "ask", "command is nested too deeply to check"
    worst = None
    for rx, decision, reason in SHELL_RULES:
        if rx.search(cmd):
            if decision == "deny":
                return decision, reason
            worst = worst or (decision, reason)
    assigned = {}
    for seg in split_commands(cmd):
        m = re.fullmatch(r"(\w+)=(\S*)", seg)
        if m:
            assigned[m.group(1)] = m.group(2).strip("'\"")
            continue
        if assigned:
            seg = re.sub(r"\$\{?(\w+)\}?", lambda x: assigned.get(x.group(1), x.group(0)), seg)
        r = check_segment(seg, cwd, project, depth)
        if r and r[0] == "deny":
            return r
        worst = worst or r
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
        text = "\n".join(str(x) for x in parts if x)
        name = find_secret(text)
        if name:
            return "deny", f"{tool} writes a {name} into '{path}', use an env variable instead"
        m = RISKY_SCRIPT_RE.search(text)
        if m:
            return "ask", f"{tool} adds '{m.group(0).strip()}' to '{path}', a recursive delete on a variable, home or root path runs later without this check"
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit") and path:
        p = _resolve(path, cwd)
        if not _inside(p, project):
            return "ask", f"{tool} outside the project: {p}"
        if ".git" in p.parts:
            return "deny", f"{tool} inside .git"
    return None


# ------------------------------------------------------------------ main ---

UNATTENDED_MODES = {"bypasspermissions", "auto"}


def decide(event: dict):
    r = _decide(event)
    mode = str(event.get("permission_mode") or "").lower()
    if r and r[0] == "ask" and mode in UNATTENDED_MODES and os.environ.get("AGENT_GUARD_UNATTENDED") != "ask":
        return "deny", f"{r[1]} (this session runs in {event.get('permission_mode')} mode, so nobody would be asked and it is blocked instead)"
    return r


def _decide(event: dict):
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
            "permissionDecisionReason": f"[agent-guard] {reason}" + (
                ". Do not try to do this another way (a script, another tool or command). Stop and ask the user."
                if decision == "deny" else ""),
        }
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
