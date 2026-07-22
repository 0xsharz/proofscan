# Copyright 2026.
# SPDX-License-Identifier: Apache-2.0
FROM python:3.11-slim

WORKDIR /work

RUN apt-get update && \
    apt-get install -y --no-install-recommends git xxd file gdb vim-common && \
    rm -rf /var/lib/apt/lists/*

# Pin the vulnerable ReportLab. CVE-2023-33733: rl_safe_eval sandbox escape ->
# arbitrary code execution from crafted paragraph markup. Fixed in 3.6.13.
RUN pip install --no-cache-dir "reportlab==3.6.12"

COPY harness_oracle.py /work/harness_oracle.py
COPY entry.py /work/entry
RUN chmod +x /work/entry

CMD ["/bin/bash"]
