---
description: Full bug and security check, fix everything, re-test until clean, then summarize
---

Run a full quality and security loop on this repo. Maximum 5 rounds.

Round 0: review the changed code (`git diff` against the main branch) for bugs,
unhandled errors, edge cases, missing input validation and authorization gaps
(data not scoped to the caller, missing auth checks, client-trusted ids). Fix what you find.

Then repeat until clean:
1. Run `guard scan --no-live`. If `guard.config.json` points at a staging
   host I have confirmed is safe, run `guard scan` (live checks) instead.
   Never target production.
2. Read `guard_out/fix_tasks.md`.
3. If there are no blocking issues, stop the loop.
4. Otherwise fix every blocking issue at its root cause. Do not edit guard,
   its config or scope, and do not add ignore comments to hide findings.
5. Go back to step 1 so the fixes are tested again.

Stop early if a round fixes nothing (no progress) or after 5 rounds.

Finish with a plain-English summary for me (use `guard_out/summary.md`):
- what was found, and how serious
- what you changed to fix each issue
- how many rounds it took and whether the final scan is clean
- anything still open, and why, with your recommendation
- what could not be verified
