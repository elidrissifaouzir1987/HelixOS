---
type: "query"
date: "2026-07-10T18:19:09.750824+00:00"
question: "Which Feature 003 performance and recovery outcomes are verified on the controlled Windows host?"
contributor: "graphify"
outcome: "useful"
---

# Q: Which Feature 003 performance and recovery outcomes are verified on the controlled Windows host?

## Answer

Against clean commit c7f736656b572a88c8b805a34c5efa872834c56d, 500 warmups and 10000 FULL/WAL claims passed at p95 6.264 ms and p99 7.8968 ms. Held-writer calls returned in 14.9546 ms and 14.9386 ms within the 90 ms SC-004 bound. Contention, process-kill and backup/restore workloads passed. This is local Windows evidence only; unchanged three-OS CI, physical Mac mini M4, F_FULLFSYNC and power-loss evidence remain pending.

## Outcome

- Signal: useful