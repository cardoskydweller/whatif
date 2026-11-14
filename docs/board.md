# Board

Everything open in whatif, in one place. An item leaves when it is done; a new one arrives with its source.

## Now

- **Resume here (2026-11-14):** The board is new.

## Open

- Overlapping secure values leave a tail in a message: with adminPassword=FakePass and dbPass=FakePass123, an az error prints `<masked len 8 …>123` (src/mask.rs forbidden pass, values matched in parameter order). Fix: find all matches on the lowered message, merge overlapping ranges, replace each once. security review round 4, 2026-11-14 (head d0fadb8), M1.
- Only ASCII is lower-cased: a secure value with a non-ASCII capital (`FakeÄdmin-Prod`) that a template passes through toLower, and whose parts are all template literals, prints. Fix: Unicode to_lowercase in holds_forbidden; in text(), mask the whole message when a Unicode match exists that the ASCII pass missed. security review round 4, 2026-11-14 (head d0fadb8), M2.
- Owner question: a 1-2 character secure value (adminPassword=e) masks every matching letter in az errors and values, which wrecks the output and protects nothing. Proposed: do not forbid values under 4 characters; print one line naming the parameter (never the value) and why. security review round 4, 2026-11-14 (head d0fadb8), M3.
- Not checked: `@/dev/fd/N` parameter passing on Linux (the musl build); the macOS path is verified against real az. security review round 4, 2026-11-14 (head d0fadb8), coverage note.

## For the software factory

Lessons from whatif that every new project needs. They go into the software factory's `what-every-new-project-needs.md`.

- A masker built from a name deny-list leaked in every review round until printed values came only from fields with a known origin (template literals, plain parameters, fixed words); four Opus review rounds, 2026-11-13/14. Same arc as optrace and xreplace: start from where values come from. whatif build, session f9f6738a.
