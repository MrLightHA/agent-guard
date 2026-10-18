# agent-guard

**A 1-minute safety net for Claude Code.** Blocks destructive commands, keeps the agent away from your secrets, and logs everything it does.

No containers, no VMs, no account. One Python file, stdlib only.

## Why

AI coding agents are fast, including at destroying things:

- **Apr 2026**: a Cursor agent deleted PocketOS's production database *and its backups* in 9 seconds, using an API token it found in an unrelated file.
- **Mar 2026**: Claude Code ran `terraform destroy` during a migration and wiped 2.5 years of DataTalks.Club data.
- **Sep 2026**: a Claude Code session deleted 48,218 files and the local `.git` store in under two minutes.
- Agents routinely read `.env` files and leak keys into commits, logs and PR comments.

Approving every command by hand doesn't scale, so people turn approvals off. agent-guard sits in between: normal work runs untouched, the catastrophic stuff gets stopped.

## What it blocks

| Category | Examples | Action |
|---|---|---|
| Deleting outside the project | `rm -rf ~/`, `rm -rf ../other`, `rm -rf /` | **deny** |
| Killing your git history | `rm -rf .git`, editing inside `.git` | **deny** |
| Infrastructure wipes | `terraform destroy`, `pulumi destroy`, Railway `volumeDelete`, `kubectl delete ns` | **deny** |
| Database wipes | `DROP DATABASE`, `TRUNCATE`, `DELETE FROM x;` without `WHERE` | **deny** |
| Reading secrets | `.env`, `id_rsa`, `*.pem`, `~/.aws/credentials`, `cat .env` | **deny** |
| Remote code | `curl … \| bash` | **deny** |
| Risky but sometimes legit | `git push --force`, `git reset --hard`, `printenv`, `$API_KEY`, writes outside the project | **ask you** |

Everything else passes. `rm -rf node_modules`, `.env.example`, normal edits are untouched.

Every tool call is logged to `~/.agent-guard/log.jsonl`.

## Install

1. Put `guard.py` somewhere permanent, e.g. `~/.agent-guard/guard.py`.
2. Add this to `~/.claude/settings.json` (all projects) or `.claude/settings.json` (one project):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Read|Write|Edit|MultiEdit|NotebookEdit|Grep|Glob",
        "hooks": [
          { "type": "command", "command": "python3 ~/.agent-guard/guard.py" }
        ]
      }
    ]
  }
}
```

On Windows use `python` and a full path, e.g. `python C:\\Users\\you\\.agent-guard\\guard.py`.

3. Restart Claude Code. Ask it to `cat .env` and it should refuse.

**Not sure yet?** Set `AGENT_GUARD_MODE=warn` to only log, never block, and check `~/.agent-guard/log.jsonl` after a day of work.

## Test

```
python3 tests.py
```

## Limits

This is a guard rail, not a sandbox. A determined agent can obfuscate commands (base64, scripts written to disk and run later). It stops the common accidents that actually happen, which is most of them. Keep backups off-machine and don't give agents production tokens.

## License

MIT
