# Claude Code Instructions

## Your First Action Every Session
Read `ARCHITECTURE.md` before doing anything else.  
It tells you what the project does, where every module lives, and what the current state is.  
**Do not read source files to orient yourself — use ARCHITECTURE.md instead.**

## When Reading Source Files
Only open a source file when you are about to modify it.  
Use the `Module Map` section of ARCHITECTURE.md to find the exact file and line range — read only that range unless you need more.

## When Making Changes
You do not need to update ARCHITECTURE.md yourself.  
A hook fires automatically after every file write or edit.  
It decides whether the change is architecturally meaningful and updates the relevant section(s) if so.

## When Starting a New Task
1. Re-read `ARCHITECTURE.md` (it may have been updated by previous changes)
2. Identify which module(s) are affected using the Module Map
3. Read only those files/line ranges
4. Make the change
5. The hook handles the rest

## Keeping README.md Up to Date
Update `README.md` whenever a change affects any of the following:
- CLI flags (added, removed, or renamed)
- API endpoints or request/response shape
- Filter pipeline (new filter, changed threshold behaviour, changed default)
- Config keys (new section, renamed key, new placeholder)
- Scan output files or their contents
- Webhook payload fields
- Python or system dependencies
- Installation steps

**How to update:** read only the affected section(s) of `README.md`, then edit those sections in place. Do not rewrite unaffected sections. Do not reformat or re-order sections that haven't changed.

## Constraints
- Never read files not referenced in ARCHITECTURE.md unless strictly necessary
- Never read entire files when a line range is given
- If you discover a new issue, add it to Known Issues yourself — the hook covers structural changes, not observations
