#!/usr/bin/env python3
# Demo loader: shows what a real app does with untrusted YAML.
#   demo_load.py <file> vuln   -> yaml.load(FullLoader)  (VULNERABLE: runs attacker code)
#   demo_load.py <file> safe   -> yaml.safe_load         (SAFE: ignores the gadget)
import sys
sys.path.insert(0, "/work/src/lib3")  # pinned-vulnerable PyYAML 5.3.1
import yaml


def out(msg):
    print(msg, flush=True)  # flush so ordering vs. os.system output is correct


data = open(sys.argv[1]).read()
mode = sys.argv[2] if len(sys.argv) > 2 else "vuln"

if mode == "vuln":
    out(">>> app runs:  yaml.load(data, Loader=yaml.FullLoader)   [THE BUG]")
    out(">>> ---------- attacker command output starts here ----------")
    result = yaml.load(data, Loader=yaml.FullLoader)
    out(">>> ---------- attacker command output ends here ----------")
    out(">>> load finished; yaml returned an object of type: %s" % type(result).__name__)
else:
    out(">>> app runs:  yaml.safe_load(data)   [THE FIX]")
    try:
        result = yaml.safe_load(data)
        out(">>> load finished; yaml returned: %r" % (result,))
    except yaml.YAMLError as e:
        out(">>> SAFE: yaml.safe_load REFUSED the malicious gadget. No code ran.")
        out(">>> (it rejected the tag: %s)" % str(e).splitlines()[0])
