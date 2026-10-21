"""
agent-guard installer.

  python install.py              install for all projects (~/.claude/settings.json)
  python install.py --project    install only for the current project (.claude/settings.json)
  python install.py --check      only run the self-check
  python install.py --uninstall  remove the hook (guard.py and logs stay)
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
GUARD_SRC = HERE / "guard.py"
INSTALL_DIR = Path.home() / ".agent-guard"
GUARD_DST = INSTALL_DIR / "guard.py"
MATCHER = "Bash|PowerShell|Read|Write|Edit|MultiEdit|NotebookEdit|Grep|Glob"
MARK = "agent-guard"


def say(ok, msg):
    print(("  [ok]   " if ok else "  [fail] ") + msg)


def fail(msg):
    print("\n" + msg)
    sys.exit(1)


def settings_path(project):
    return (Path.cwd() if project else Path.home()) / ".claude" / "settings.json"


def _q(p):
    # quote only when needed: bash and cmd understand quotes, PowerShell runs a
    # quoted path as a string instead of a program
    return f'"{p}"' if " " in p else p


def hook_command():
    # absolute path of the python running this script, so the hook never hits
    # the Microsoft Store 'python' alias or a missing PATH entry
    exe = Path(sys.executable).resolve().as_posix()
    return f"{_q(exe)} {_q(GUARD_DST.as_posix())}"


def load_settings(path):
    if not path.exists():
        return {}
    raw = path.read_text(encoding="utf-8-sig")
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        fail(f"{path} is not valid JSON (line {e.lineno}, column {e.colno}).\n"
             "Claude Code ignores a broken settings file completely, so fix it first.\n"
             "Nothing was changed.")
    if not isinstance(data, dict):
        fail(f"{path} has unexpected content. Nothing was changed.")
    return data


def save_settings(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + ".bak"))
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def is_ours(handler):
    return isinstance(handler, dict) and MARK in str(handler.get("command", ""))


def strip_ours(data):
    """Remove every agent-guard handler, keep everything else as is."""
    groups = data.get("hooks", {}).get("PreToolUse", [])
    removed = 0
    kept = []
    for g in groups:
        if not isinstance(g, dict):
            kept.append(g)
            continue
        hs = g.get("hooks", [])
        left = [h for h in hs if not is_ours(h)]
        removed += len(hs) - len(left)
        if left:
            kept.append({**g, "hooks": left})
        elif not hs:
            kept.append(g)
    if "hooks" in data and "PreToolUse" in data["hooks"]:
        if kept:
            data["hooks"]["PreToolUse"] = kept
        else:
            del data["hooks"]["PreToolUse"]
            if not data["hooks"]:
                del data["hooks"]
    return removed


def add_ours(data):
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        fail("'hooks' in settings.json is not an object. Nothing was changed.")
    hooks.setdefault("PreToolUse", []).append({
        "matcher": MATCHER,
        "hooks": [{"type": "command", "command": hook_command()}],
    })


def run_hook(event, log_path):
    env = dict(os.environ, AGENT_GUARD_LOG=str(log_path))
    env.pop("AGENT_GUARD_MODE", None)
    env.pop("CLAUDE_PROJECT_DIR", None)
    r = subprocess.run(hook_command(), shell=True, input=json.dumps(event),
                       capture_output=True, text=True, env=env, timeout=30)
    if r.returncode != 0:
        return "error", (r.stderr or r.stdout).strip()[:300]
    if not r.stdout.strip():
        return None, ""
    try:
        out = json.loads(r.stdout)["hookSpecificOutput"]
        return out["permissionDecision"], out.get("permissionDecisionReason", "")
    except Exception:
        return "error", r.stdout.strip()[:300]


def self_check():
    print("\nSelf-check")
    ok = True

    v = sys.version_info
    good = v >= (3, 8)
    say(good, f"Python {v.major}.{v.minor} at {Path(sys.executable).as_posix()}")
    ok &= good

    good = GUARD_DST.exists()
    say(good, f"guard.py installed at {GUARD_DST.as_posix()}")
    if not good:
        return False

    with tempfile.TemporaryDirectory() as d:
        proj = Path(d) / "my-app"
        proj.mkdir()
        log = Path(d) / "log.jsonl"
        cases = [
            ("reading .env is blocked", {"tool_name": "Read", "tool_input": {"file_path": str(proj / ".env")}}, "deny"),
            ("rm -rf outside the project is blocked", {"tool_name": "Bash", "tool_input": {"command": "rm -rf ../other"}}, "deny"),
            ("git reset --hard asks first", {"tool_name": "Bash", "tool_input": {"command": "git reset --hard"}}, "ask"),
            ("normal commands pass", {"tool_name": "Bash", "tool_input": {"command": "rm -rf node_modules"}}, None),
        ]
        for name, ev, want in cases:
            ev = {**ev, "cwd": str(proj), "hook_event_name": "PreToolUse", "session_id": "self-check"}
            got, detail = run_hook(ev, log)
            good = got == want
            say(good, name if good else f"{name}: got {got!r}, expected {want!r} {detail}")
            ok &= good

        good = log.exists() and log.stat().st_size > 0
        say(good, "log is written")
        ok &= good
    return ok


def find_settings_with_us():
    found = []
    for p in (settings_path(False), settings_path(True)):
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8-sig") or "{}")
            except Exception:
                continue
            for g in data.get("hooks", {}).get("PreToolUse", []):
                if isinstance(g, dict) and any(is_ours(h) for h in g.get("hooks", [])):
                    found.append(p)
                    break
    return found


def install(project):
    if not GUARD_SRC.exists():
        fail(f"guard.py not found next to install.py ({HERE}).")
    if sys.version_info < (3, 8):
        fail("agent-guard needs Python 3.8 or newer.")

    path = settings_path(project)
    data = load_settings(path)  # validate before touching anything

    print("Installing agent-guard")
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    if GUARD_SRC.resolve() != GUARD_DST.resolve():
        if GUARD_DST.exists():
            shutil.copy2(GUARD_DST, GUARD_DST.with_name("guard.py.bak"))
        shutil.copy2(GUARD_SRC, GUARD_DST)
    say(True, f"copied guard.py to {GUARD_DST.as_posix()}")

    replaced = strip_ours(data)
    add_ours(data)
    save_settings(path, data)
    say(True, f"{'updated' if replaced else 'added'} hook in {path.as_posix()}")

    if self_check():
        print("\nDone. Restart Claude Code, then run /hooks to see agent-guard listed.")
        print("Try it: ask the agent to read your .env, it should refuse.")
    else:
        fail("Installed, but the self-check failed. The hook will NOT protect you until this is fixed.\n"
             "Open an issue with the output above: https://github.com/MrLightHA/agent-guard/issues")


def uninstall():
    print("Removing agent-guard hook")
    any_removed = False
    for p in (settings_path(False), settings_path(True)):
        if not p.exists():
            continue
        data = load_settings(p)
        n = strip_ours(data)
        if n:
            save_settings(p, data)
            say(True, f"removed from {p.as_posix()}")
            any_removed = True
    if not any_removed:
        print("  agent-guard was not found in any settings.json")
    print(f"\nguard.py and logs are still in {INSTALL_DIR.as_posix()}, delete that folder if you want.")


def main():
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    args = set(sys.argv[1:])
    if args & {"-h", "--help"}:
        print(__doc__)
    elif "--uninstall" in args:
        uninstall()
    elif "--check" in args:
        where = find_settings_with_us()
        if where:
            print("Hook found in: " + ", ".join(p.as_posix() for p in where))
        else:
            print("Hook not found in ~/.claude/settings.json or ./.claude/settings.json")
        sys.exit(0 if self_check() and where else 1)
    else:
        install("--project" in args)


if __name__ == "__main__":
    main()
