# Beattracker

An “incident forensics magnifier” for NDJSON audit logs: scan once, auto-backtrack suspicious events, render provenance graphs, and match well-known attack patterns via subgraph isomorphism.

---

## Feature Highlights

- **Tag-driven detection**: `config/tag_pool.json` defines which tags flag a suspicious event.
- **Backtracker**: walks backward up to 5 hops (default) across processes, files, and sockets from each hit.
- **Noise filtering**: `utils/filters.py` blacklists high-volume binaries, directories, and DNS sockets so only meaningful nodes remain.
- **Egress enrichment**: forward scan injects later process→socket and process→file writes to expose exfiltration.
- **Graph pattern matching**: `PatternDetector` uses NetworkX subgraph isomorphism to catch “Drop & Execute” chains.
- **Reporting**: every detection gets DOT/PNG graphs plus a consolidated `reports/detections.json`.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the analyzer (defaults to logs/auditbeat-20251125.ndjson)
python main.py
```

Sample console output:

```
[Running Advanced Pattern Detection]...
  [!] Detection #285: Found 2 attack pattern(s)!
      - Drop & Execute: /usr/bin/curl -> /home/student/Downloads/program11 -> ...
Detected 1 suspicious event(s):
  trace: 12 nodes, 13 edges
  backward dot: reports/backward/backward_285.dot
Summary written to reports/detections.json
```

---

## Project Layout

| Path | Description |
|------|-------------|
| `logs/*.ndjson` | Raw audit logs |
| `parser/` | `NDJSONParser` with tag-based overrides (`dl_dir`, `attacker_write`, …) |
| `tracker/backtracker.py` | Reverse-tracing engine with noise filters & egress enrichment |
| `tracker/pattern_detector.py` | NetworkX-based pattern matching |
| `reporter/` | DOT / PNG report writer |
| `reports/` | Auto-generated graphs & JSON summaries |
| `utils/filters.py` | Central noise blacklist (paths, ports, binaries) |

---

## Processing Pipeline

1. **Parse**: `NDJSONParser.parse()` normalizes audit events.
2. **Match**: `TagPool.match()` checks tag rules.
3. **Backtrack**: `Backtracker.backtrack()` builds node/edge lists and DOT output.
4. **Pattern Match**: `PatternDetector.detect()` runs subgraph isomorphism on each trace.
5. **Report**: `DetectionReporter.emit_dot_reports()` + `reports/detections.json`.

---

## Customization Cheatsheet

- **Extend the noise list**: edit `IGNORED_BINARIES`, `IGNORED_PREFIXES`, or `IGNORED_EXACT_PATHS` in `utils/filters.py`.
- **Add new attack patterns**: create additional signature graphs inside `PatternDetector`.
- **Tune tag rules**: modify `config/tag_pool.json`.
- **Change max hops**: adjust `DEFAULT_MAX_HOPS` in `main.py`.

---

## Handy Commands

```bash
# Re-run analysis & regenerate graphs
python main.py

# Inspect detection JSON
cat reports/detections.json | jq '.'
```

---

The codebase is modular (parser / tracker / reporter), so extending any stage is straightforward. Happy hunting!