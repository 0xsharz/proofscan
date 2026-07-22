# Threat model — pyyaml target

**Asset:** a Python process that loads YAML configuration/messages supplied by
an untrusted party (uploaded config, API body, queue message, CI artifact).

**Trust boundary:** the raw YAML bytes crossing into `yaml.load(...)`. Everything
downstream of the loader runs with the process's privileges.

**Adversary capability:** full control of the YAML document contents.

**Vulnerability:** PyYAML 5.3.1 `FullLoader` (and the historically-default
`Loader`) resolves and invokes Python objects named in the document
(`!!python/object/new`, `!!python/object/apply`, `!!python/name`,
`!!python/module`). Gadget chains reach `exec` / `os.system` / `subprocess`,
giving arbitrary code execution (CVE-2020-14343). `SafeLoader`/`safe_load` is
immune.

**Impact:** remote code execution in the deserializing process → full host
compromise within its privilege boundary (here, contained by the gVisor
sandbox + egress allowlist).

**Detection oracle:** audit-hook "deserialization sanitizer" in `entry.py` — any
code-exec, dangerous import, outbound socket, or sensitive-file access during
the load window aborts the process, which the pipeline records as a crash.

**Remediation (for the patch track, if run):** replace `yaml.load(x, FullLoader)`
with `yaml.safe_load(x)`, or upgrade to PyYAML ≥ 5.4 and use `SafeLoader`.
