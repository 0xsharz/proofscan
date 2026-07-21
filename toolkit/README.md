# Toolkit — make new use cases easy

This folder turns "add a new vulnerability use case to the harness" into a
few-minutes job. It is the versatility layer on top of the concrete `pyyaml`
example in the parent repo.

## What's here

| File | Purpose |
|---|---|
| `harness_oracle.py` | Reusable "sanitizer" oracle. Turns a silent Python exploit (deserialization, SSTI, command injection, SSRF, path traversal) into a deterministic crash the harness detects. **You rarely edit this.** |
| `templates/python-library/` | The target template: `Dockerfile.tmpl`, `entry.py.tmpl`, `config.yaml.tmpl`. |
| `new_target.sh` | One-command generator: scaffolds `targets/<name>/` from the template with your parameters substituted. |
| `COOKBOOK.md` | Catalog of vuln classes → library, sink line, and example exploit. Copy-paste `new_target.sh` invocations. |

## The mental model

The harness only asks: *did `entry <input>` crash?* For C it's AddressSanitizer.
For Python, `harness_oracle.py` manufactures the crash the instant an exploit
primitive (exec / import os / subprocess / socket / sensitive-file open) is hit.
So **one oracle serves many Python vuln classes** — to retarget, you change only
the single *sink* line that feeds untrusted input into the library.

## Use it

```bash
# from this toolkit directory, inside the harness host (WSL)
./new_target.sh <name> \
  --pip "<pkg==ver>" --git <repo-url> --tag <tag> [--commit <sha>] \
  --src-subdir <subdir-with-package> --import <module> \
  --sink '<one python line feeding `data` to the library>' \
  --attack "<one-line attack surface>" --focus "<focus hint for the agent>"

# then
docker build -t vuln-pipeline-<name>:latest ../../targets/<name>   # or wherever --targets-dir points
# self-test the oracle: known exploit -> exit 134 ; benign -> exit 0
bin/vp-sandboxed run <name> --model claude-opus-4-8 --runs 3 --stream
```

`--targets-dir` defaults to `/root/defending-code-reference-harness/targets`.

See `COOKBOOK.md` for ready-made commands (PyYAML, Jinja2 SSTI, pickle, …) and for
how to build oracles for non-Python classes (prototype pollution, Zip Slip,
Log4Shell, SQL injection).
