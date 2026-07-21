#!/bin/bash
echo "=docker="
systemctl is-active docker 2>/dev/null || sudo service docker start >/dev/null 2>&1
if docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
  echo "DOCKER_OK $(docker version --format '{{.Server.Version}}')"
else
  echo "DOCKER_FAIL"
fi
echo "=token="
if [ -s /root/.vp_token ]; then echo "TOKEN_OK ($(wc -c </root/.vp_token) bytes)"; else echo "TOKEN_MISSING"; fi
echo "=runsc="
if docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q runsc; then echo "RUNSC_OK"; else echo "RUNSC_MISSING"; fi
