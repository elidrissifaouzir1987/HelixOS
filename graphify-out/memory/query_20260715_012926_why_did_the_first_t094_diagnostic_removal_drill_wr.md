---
type: "correction"
date: "2026-07-15T01:29:26.518284+00:00"
question: "Why did the first T094 diagnostic removal-drill wrapper exit nonzero after the drill reported completion?"
contributor: "graphify"
outcome: "corrected"
correction: "Use a non-reserved shell variable such as rc when preserving a command exit code in zsh."
source_nodes: ["plan005_removal_drill.py", "T094"]
---

# Q: Why did the first T094 diagnostic removal-drill wrapper exit nonzero after the drill reported completion?

## Answer

The removal drill itself completed successfully with 495 protected files. The surrounding zsh wrapper then tried to assign the reserved read-only variable status. Replacing it with rc produced a clean exit-zero rerun; the repository driver required no change.

## Outcome

- Signal: corrected
- Correction: Use a non-reserved shell variable such as rc when preserving a command exit code in zsh.

## Source Nodes

- plan005_removal_drill.py
- T094