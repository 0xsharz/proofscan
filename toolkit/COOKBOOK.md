# Cookbook — adding a new use case in minutes

The harness finds a bug whenever `entry <input>` **crashes** on a malicious input.
The toolkit gives you that crash for free via `harness_oracle.py`, so adding a new
Python vuln class is usually just: **pick a vulnerable library + write one sink line
+ know one exploit payload.** Run `new_target.sh`, build, self-test, run.

## The 4-step recipe

1. **Pick a target library** and pin a known-vulnerable version (`--pip`, `--git`, `--tag`, `--commit`).
2. **Write the sink** — the single call that feeds untrusted `data` into the library (`--sink`).
3. **Scaffold** with `new_target.sh` (creates `targets/<name>/`).
4. **Self-test the oracle** (a known exploit → exit 134; benign → exit 0), then run the pipeline.

## One oracle covers many Python classes

`AuditHookOracle` fires on the runtime primitive an exploit must reach. You rarely
touch the oracle — only the sink changes:

| Vuln class | Oracle primitive it trips | Sink line (`--sink`) | Example exploit input |
|---|---|---|---|
| **Unsafe deserialization** (PyYAML) | `compile`/`exec`/`import os` | `import yaml; result = yaml.load(data, Loader=yaml.FullLoader)` | `!!python/object/new:type` gadget (see pyyaml target) |
| **Deserialization** (pickle) | `import`/`exec`/`subprocess` | `import pickle; result = pickle.loads(data)` | a `__reduce__` gadget calling `os.system` |
| **Template injection / SSTI** (Jinja2) | `exec`/`import os`/`subprocess` | `from jinja2 import Template; result = Template(data.decode(), autoescape=False).render()` | `{{ ''.__class__.__mro__[1].__subclasses__() ... __import__('os').system('id') }}` |
| **Command injection** (app wrapper) | `subprocess.Popen`/`os.system` | `import subprocess; result = subprocess.run(build_cmd(data), shell=True)` | input that breaks out: `; id` / `$(id)` |
| **SSRF** (fetcher) | `socket.connect`/`getaddrinfo` | `import urllib.request; result = urllib.request.urlopen(data.decode().strip())` | `http://169.254.169.254/...` or an internal canary URL |
| **Path traversal / arbitrary read** | `open` of a sensitive path | `open(os.path.join('/srv', data.decode().strip())).read()` | `../../../../etc/passwd` |
| **XXE** (lxml, old libs) | `open`/`socket.connect` (external entity) | `from lxml import etree; etree.fromstring(data, etree.XMLParser(resolve_entities=True))` | a `<!ENTITY xxe SYSTEM "file:///etc/passwd">` doc |

> If a class needs an extra event, pass it: `AuditHookOracle(extra_events={"os.putenv"})`.
> For exploits that only touch disk, use `MarkerFileOracle("/work/pwned")` instead.

## Watch out: "safe eval" / sandbox libraries need `exclude_events`

If the vulnerable library is itself an expression evaluator — a template
engine, a "safe eval", a rules/formula engine — its **normal, benign**
operation already calls `compile()`/`eval()` on every input. Watching those
events (the `AuditHookOracle` default) makes *every* input look like an
escape — a real false-positive trap, not a hypothetical one: this happened
on the ReportLab target (`rl_safe_eval` compiles every `<font color="[...]">`
expression, even a harmless `[0,0,0,0]`).

**Fix:** exclude the noisy default events and watch only the concrete
dangerous primitive the *escape* must additionally reach:
```python
with AuditHookOracle(exclude_events={"compile", "exec"}, watch_imports=True, watch_open=False):
    vulnerable_eval(untrusted_input)
```
Rule of thumb: if the library's **intended, documented** behavior already
triggers an event, exclude it — only alarm on primitives that mean the
sandbox failed (`os.system`, `subprocess.Popen`, a dangerous import actually
reached, an outbound socket), not on "an expression was evaluated at all."
Always test with a known-benign input from the library's own normal use
before trusting a new oracle.

## Ready-to-run examples

**Recreate the PyYAML target (the validated one):**
```bash
./new_target.sh pyyaml \
  --pip "PyYAML==5.3.1" --git https://github.com/yaml/pyyaml \
  --tag 5.3.1 --commit 20a120055ce2d702d8977c76b48033160b7b7c92 \
  --src-subdir lib3 --import yaml \
  --sink 'import yaml; result = yaml.load(data, Loader=yaml.FullLoader)' \
  --attack "Untrusted YAML into yaml.load(FullLoader) on PyYAML 5.3.1 (CVE-2020-14343)." \
  --focus "FullLoader gadget construction reaching exec/subprocess (CVE-2020-14343)"
```

**Jinja2 SSTI:**
```bash
./new_target.sh jinja2ssti \
  --pip "Jinja2==3.1.2" --git https://github.com/pallets/jinja \
  --tag 3.1.2 --src-subdir src --import jinja2 \
  --sink 'from jinja2 import Template; result = Template(data.decode(), autoescape=False).render()' \
  --attack "Untrusted template string rendered by jinja2.Template — server-side template injection to RCE." \
  --focus "sandbox escape via __class__/__subclasses__/__globals__ reaching os.system or __import__"
```

**pickle deserialization:**
```bash
./new_target.sh picklerce \
  --pip "setuptools" --git https://github.com/python/cpython \
  --tag main --import pickle \
  --sink 'import pickle; result = pickle.loads(data)' \
  --attack "Untrusted bytes into pickle.loads — arbitrary code execution via __reduce__." \
  --focus "__reduce__ gadget invoking os.system/subprocess during unpickling"
```

## Non-Python classes need a different oracle (not this template)

The audit-hook trick is Python-only. For other ecosystems, build the analogous
deterministic oracle in that language's entry:

| Class | Language | Oracle idea |
|---|---|---|
| **Prototype pollution** (lodash) | Node.js | after processing input, assert `({}).polluted === undefined`; if a base-Object prop appeared, exit nonzero |
| **Zip Slip / tar traversal** (node-tar, Java) | any | after extraction, check whether any file landed **outside** the target dir → crash |
| **Log4Shell (JNDI)** | Java | stand up an internal LDAP/HTTP canary server; if the target calls back, crash |
| **SQL injection** | any | plant a secret canary row; if the response contains it (or a boolean/time oracle trips), crash |

Each is the same principle as `AuditHookOracle`: **turn "an exploit happened" into a
deterministic nonzero exit** the harness reads as a crash.
