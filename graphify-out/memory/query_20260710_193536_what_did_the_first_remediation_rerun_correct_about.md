---
type: "query"
date: "2026-07-10T19:35:36.739367+00:00"
question: "What did the first remediation rerun correct about the Feature 003 initialization diagnosis?"
contributor: "graphify"
outcome: "corrected"
correction: "Inspect live intent before rechecking the monotonic role path; size hosted concurrency-test budgets for correctness, keep production and SC-004 unchanged, and preserve future failure codes."
---

# Q: What did the first remediation rerun correct about the Feature 003 initialization diagnosis?

## Answer

The immutable rerun at commit 6e3940d40b5661ece7b4ed53ce9e7c8f598e4ff2 proved macOS end-to-end and corrected two parts of the prior diagnosis. The creator/waiter role-publication fix was necessary but incomplete: pre-lock intent preparation still had two TOCTOU variants where a process sampled the role absent, then rejected a false or failed intent-only inspection after another process had published the monotonic role. Intent inspection must occur before a final role-path recheck, and the original error is retained when no role exists. The hosted Windows log masked the exact public code, but code-path review identified the eight-initializer schema convergence test's 250 ms busy budget as a performance assumption rather than a correctness property; the test now uses 5,000 ms and reports the redacted public error code, without changing production gates or SC-004. Default, all-feature, release contention and release process-kill gates pass locally, but unchanged green three-host CI remains pending.

## Outcome

- Signal: corrected
- Correction: Inspect live intent before rechecking the monotonic role path; size hosted concurrency-test budgets for correctness, keep production and SC-004 unchanged, and preserve future failure codes.
