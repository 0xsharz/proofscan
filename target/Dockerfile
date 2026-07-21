# Copyright 2026.
# SPDX-License-Identifier: Apache-2.0
FROM python:3.9-slim

WORKDIR /work

# Tools the find-agent uses to inspect/craft inputs (mirrors the C targets).
RUN apt-get update && \
    apt-get install -y --no-install-recommends git xxd file gdb vim-common && \
    rm -rf /var/lib/apt/lists/*

# Pin the vulnerable PyYAML. CVE-2020-14343: FullLoader still permits object
# construction gadgets that reach arbitrary code execution; fixed in 5.4.
RUN pip install --no-cache-dir "PyYAML==5.3.1"

# Bring the library source in so the find-agent can READ it (as drlibs shipped
# dr_wav.h / dr_flac.h). Pinned to the 5.3.1 tag.
ARG PYYAML_TAG=5.3.1
RUN git clone --depth 1 --branch ${PYYAML_TAG} https://github.com/yaml/pyyaml /work/src

# Reusable oracle library (imported by entry).
COPY harness_oracle.py /work/harness_oracle.py

# entry is a Python script acting as binary_path (executable taking one arg).
COPY entry.py /work/entry
RUN chmod +x /work/entry

CMD ["/bin/bash"]
