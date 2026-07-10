---
type: "query"
date: "2026-07-10T19:07:52.288892+00:00"
question: "What did the first immutable Feature 003 CI run reveal and how was it remediated?"
contributor: "graphify"
outcome: "useful"
---

# Q: What did the first immutable Feature 003 CI run reveal and how was it remediated?

## Answer

The first immutable PLAN-003 run at commit b63d0bd25f979117a807c1c8e399c291cea39563 revealed four bounded issues: a real creator/waiter live-root role initialization race on Linux/macOS; CRLF-sensitive multiline source guards on Windows; legacy helixos-kernel tests that unconditionally used Windows-only filesystem APIs on Unix; and a five-second test-only contention correctness window that was too short for hosted Windows FULL-sync load. The remediation accepts an exact waiter-published LIVE_READY role under lock while repairing only the exact empty live reservation and preserving unknown bytes, normalizes test source line endings, cfg-gates Windows test APIs with Unix symlink equivalents, and raises only the hosted correctness fixture window to 30 seconds without changing production or SC-004 deadlines. Local exact gates pass; green unchanged three-platform CI evidence is still pending.

## Outcome

- Signal: useful