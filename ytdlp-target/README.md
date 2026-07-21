# yt-dlp target — OS command injection via `netrc_cmd` (CVE-2026-26331)

Fourth use case for the harness, and a new vulnerability class: **OS command
injection** (previous targets covered deserialization RCE and sandbox-escape
RCE). Verified against NVD, OSV.dev, and the GitHub Advisory Database before
building — see `harness-patches/` sibling research pattern.

## The bug

`netrc_cmd` is a real, documented yt-dlp option: a shell-command *template*
(with a `{}` placeholder) used to fetch site credentials, e.g.
`--netrc-cmd "pass show {}"`. Three extractors — `GetCourseRuIE`,
`TeachableIE`, `TeachableCourseIE` — derive the substituted value not from a
trusted site name but directly from `urllib.parse.urlparse(url).hostname`,
i.e. from the untrusted URL itself:

```python
# yt_dlp/extractor/getcourseru.py, GetCourseRuIE._real_extract
hostname = urllib.parse.urlparse(url).hostname
username, password = self._get_login_info(netrc_machine=hostname)

# yt_dlp/extractor/common.py, _get_netrc_login_info
cmd = self.get_param('netrc_cmd')            # our fixed "echo {}"
cmd = cmd.replace('{}', netrc_machine)        # NO escaping
Popen.run(cmd, text=True, shell=True, stdout=subprocess.PIPE)
```

A URL like `https://;echo pwned>&2;#.getcourse.ru/video` parses to a
"hostname" of `;echo pwned>&2;#.getcourse.ru` — verified directly against
yt-dlp's real source at the pinned vulnerable tag (`2026.02.04`). Fixed in
`2026.2.21` via a strict allow-list on the machine value.

## The oracle — a precision lesson worth keeping

A naive "did `subprocess.Popen` fire" oracle produces a **false positive**:
with `netrc_cmd` configured, *any* URL matching one of the three extractors
fires a subprocess — including one with a perfectly ordinary hostname, where
the command is just `echo <hostname>` and does nothing unexpected. That's the
feature working as designed, not a vulnerability.

`entry.py` instead inspects the actual command string and only fires when it
contains characters no real hostname could ever contain (anything outside
`[A-Za-z0-9.-]`) — i.e., it proves **injection**, not merely **feature use**.
Verified with three cases:

| Input | netrc_cmd fires? | Oracle fires? |
|---|---|---|
| Malicious hostname (`;echo ...;#`) | Yes | **Yes** — `exit 134`, real command evidence (`echo ;echo pwned_via_ytdlp_marker>&2;`) |
| Clean getcourse.ru URL | Yes (`echo academymel.online`) | No — `exit 0` |
| Unrelated domain | No (extractor never matches) | No — `exit 0` |

## Files

- `Dockerfile`, `entry.py`, `config.yaml`, `harness_oracle.py` — the target.
- `artifacts/poc_evil_url.txt` — the verified exploit URL.
- `artifacts/negative_control_*.txt` — the two negative controls above.

## Plain-English verdict

If an application lets users submit arbitrary URLs to yt-dlp (a video
downloader) with `--netrc-cmd` configured — a real, if uncommon, deployment
pattern for sites requiring authentication — a crafted URL achieves arbitrary
OS command execution on the server running yt-dlp, no authentication needed.
Fix: upgrade to yt-dlp ≥ 2026.2.21.
