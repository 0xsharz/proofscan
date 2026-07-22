# textract command-injection target (CVE-2016-10320). Python 2.7 only.
# Ubuntu 20.04 (focal) because it ships python2.7 AND is supported by NodeSource
# node20 — so the harness can still build its agent image FROM this one.
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /work

RUN apt-get update && apt-get install -y --no-install-recommends \
        python2 python2-dev \
        curl ca-certificates \
        poppler-utils file xxd gdb git \
    && rm -rf /var/lib/apt/lists/*

# pip for Python 2.7 (the last version that still supports it).
RUN curl -sSL https://bootstrap.pypa.io/pip/2.7/get-pip.py -o /tmp/get-pip.py \
    && python2 /tmp/get-pip.py \
    && rm -f /tmp/get-pip.py

# Pin the vulnerable textract. Install with --no-deps (its 2015-era pins drag in
# unbuildable wheels); the .pdf extraction path needs only these at runtime.
RUN pip2 install --no-cache-dir --no-deps \
        "textract==1.4.0" \
        "chardet==2.3.0" \
        "six" \
        "argcomplete==1.10.0"

# Prove the vulnerable library imports at build time (fail fast otherwise).
RUN python2 -c "import textract; print('textract import OK')"

COPY entry.py /work/entry
RUN chmod +x /work/entry

CMD ["/bin/bash"]
