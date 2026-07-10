## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

When the user types `/graphify`, use the installed graphify skill or instructions before doing anything else.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- Dirty graphify-out/ files are expected after hooks or incremental updates; dirty graph files are not a reason to skip graphify. Only skip graphify if the task is about stale or incorrect graph output, or the user explicitly says not to use it.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
- At the start of project work, run `graphify reflect --if-stale --graph graphify-out/graph.json` and read `graphify-out/reflections/LESSONS.md` when it exists.
- After a meaningful design decision, implementation result, failed approach, test outcome, or correction, persist a concise evidence-based record with `graphify save-result`. Mark it `useful`, `dead_end`, or `corrected`, then refresh reflections. Never store secrets, credentials, full sensitive content, or private chain-of-thought.
- Specs, ADRs, source code, tests, and Git history remain authoritative. Graphify is a derived retrieval and work-memory layer; a graph edge or saved answer never overrides those sources.
