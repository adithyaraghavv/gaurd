## Quality and security rules (applies to every task in this repo)

- Before saying a task is done: review the changed code for bugs, error handling,
  edge cases and security issues, and fix what you find.
- A Stop hook runs `guard gate` automatically. If it blocks you, read
  `guard_out/fix_tasks.md`, fix every issue at its root cause, and keep going
  until the check passes. Never edit guard, its config or its scope, and never
  add ignore comments just to hide a finding. If something is a false positive,
  say so and explain why.
- When the check passes after fixes, give the user a plain-English summary using
  `guard_out/summary.md`: what was found, what you changed for each issue,
  how many rounds it took, what is left for them to decide, what you could not verify.
- Any data that belongs to a user, account, team or organization must be
  filtered by the caller's identity on the server. Never trust ids sent by the client.
- Database access: parameterized queries / ORM bindings only; never build SQL
  from strings. If using row-level security, keep it enabled on every table.
- Validate all input on the server. Return generic error messages; no stack traces.
- Secrets come from environment variables, never from code or committed files.
- Never run live checks against production. Staging with dummy data only.
- Finish by telling me what you checked and what you could not verify.
