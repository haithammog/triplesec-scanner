# Architecture Kit for Claude Code

A drop-in starter that gives Claude Code persistent project memory with zero session setup cost.

## What's Included

```
ARCHITECTURE.md          ← Living architecture document (you fill this once)
CLAUDE.md                ← Instructs Claude how to use the system
.claude/
  settings.json          ← Hook config (PostToolUse + SessionStart)
  update-architecture.js ← Hook script — auto-updates ARCHITECTURE.md
```

## How It Works

1. **Session starts** → `settings.json` injects `ARCHITECTURE.md` into Claude's context automatically via `SessionStart` hook
2. **Claude edits a file** → `PostToolUse` hook fires `update-architecture.js`
3. **The script** calls Claude Haiku with the changed file + current `ARCHITECTURE.md`
4. **Haiku decides** if the change is architecturally meaningful (new module, changed signature, new dependency, etc.)
5. **If meaningful** → only the affected section(s) of `ARCHITECTURE.md` are updated, immediately, in place
6. **If not meaningful** → nothing changes
7. **Session crashes or ends** → `ARCHITECTURE.md` already reflects the last meaningful change ✓

## Setup (per project)

### 1. Copy these files into your project root
```bash
cp ARCHITECTURE.md   /your-project/
cp CLAUDE.md         /your-project/
cp -r .claude/       /your-project/.claude/
```

### 2. Fill in ARCHITECTURE.md
Open `ARCHITECTURE.md` and fill in the sections for your project.  
The more accurate this initial state, the better the hook's updates will be.  
Aim for under 100 lines — you have a 150-line cap enforced by the hook.

### 3. Ensure Node 18+ is available
```bash
node --version   # should be v18 or higher
```

### 4. No API key setup needed
The hook script calls the Anthropic API — Claude Code handles authentication automatically.  
No `ANTHROPIC_API_KEY` environment variable is required in the hook.

### 5. Commit to version control
```bash
git add ARCHITECTURE.md CLAUDE.md .claude/
git commit -m "Add architecture kit"
```
Your team gets the same persistent memory automatically.

## What Counts as a Meaningful Change

The hook updates `ARCHITECTURE.md` when:
- A new module, class, or major function is added or removed
- A function signature or public API changes
- A new external dependency or API integration is added
- The data flow changes
- A known issue is resolved or a new one is introduced
- An entry point (CLI command, API route) is added or changed

The hook **ignores**:
- Minor bug fixes with no structural impact
- Comment, docstring, or formatting changes
- Test file updates that don't reflect structural change
- Internal implementation changes with no public impact

## Keeping ARCHITECTURE.md Healthy

- **150-line cap**: the hook trims stale entries when it updates, enforcing the cap
- **Manual corrections**: if the hook writes something wrong, just edit `ARCHITECTURE.md` directly — the next meaningful change will build on your correction
- **New sessions**: always start with `ARCHITECTURE.md` already injected — no manual pasting needed

## Token Impact

| Scenario | Without Kit | With Kit |
|---|---|---|
| Session startup | Claude reads multiple files to orient | Reads ARCHITECTURE.md (~2k tokens) |
| Targeted change | Claude reads full file | Claude reads line range only |
| Cross-session continuity | Re-explain project every time | Zero re-explanation needed |
| Crash recovery | Context lost | ARCHITECTURE.md reflects last state |
