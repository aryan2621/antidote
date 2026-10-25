#!/usr/bin/env bash
# Install (and, for MCP servers, start) one npm/PyPI package in a sandbox and record what it does.
# usage: detonate/run.sh <npm|PyPI> <name> <version> <out-dir>
# Needs docker + sudo (to install gVisor). Run only on a disposable machine.
set -euo pipefail

eco=$1 name=$2 version=$3 out=$(mkdir -p "$4" && cd "$4" && pwd)
[[ $name =~ ^[@a-zA-Z0-9._/-]+$ && $version =~ ^[a-zA-Z0-9._+-]+$ ]] || { echo "bad package spec" >&2; exit 2; }
case $eco in npm|PyPI) ;; *) echo "only npm and PyPI can be detonated" >&2; exit 2 ;; esac
here=$(cd "$(dirname "$0")" && pwd)
ops=${ANTIDOTE_OPS:-antidote-ops}
echo "$eco:$name@$version" > "$out/target"
: > "$out/proxy.jsonl"

# gVisor if we can get it, plain runc (hardened flags below) otherwise
runtime=runc
if [[ ${ANTIDOTE_NO_GVISOR:-} != 1 ]] && command -v sudo >/dev/null; then
  arch=$(uname -m)
  url=https://storage.googleapis.com/gvisor/releases/release/latest/$arch
  if curl -fsSLo /tmp/runsc "$url/runsc" && curl -fsSLo /tmp/runsc.sha512 "$url/runsc.sha512" \
     && (cd /tmp && sha512sum -c runsc.sha512) && chmod +x /tmp/runsc && sudo mv /tmp/runsc /usr/local/bin/runsc \
     && sudo runsc install && sudo systemctl restart docker && docker info --format '{{json .Runtimes}}' | grep -q runsc; then
    runtime=runsc
  fi
fi
echo "$runtime" > "$out/isolation"

net=antidote-sandbox
cleanup() { docker rm -f antidote-target antidote-proxy antidote-dns >/dev/null 2>&1 || true; docker network rm $net >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker network create --internal --subnet 10.99.0.0/24 $net >/dev/null

docker build -q -t antidote-dns -f "$here/infra.Dockerfile" "$here" >/dev/null
docker run -d --name antidote-dns --network $net --ip 10.99.0.3 antidote-dns >/dev/null

ignore='^(registry\.npmjs\.org|pypi\.org|files\.pythonhosted\.org):443$'
docker run -d --name antidote-proxy --network $net --ip 10.99.0.2 \
  -v "$here/sinkhole.py:/sinkhole.py:ro" -v "$out:/logs" \
  mitmproxy/mitmproxy:11.0.2 mitmdump --listen-port 8080 --ignore-hosts "$ignore" -s /sinkhole.py >/dev/null
docker network connect bridge antidote-proxy   # the proxy alone can reach the internet
sleep 3

proxy=http://10.99.0.2:8080
image=$([[ $eco == npm ]] && echo node:22-bookworm-slim || echo python:3.12-slim)
docker run -d --name antidote-target --network $net --dns 10.99.0.3 --runtime $runtime \
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 1g --cpus 1 \
  -e HTTP_PROXY=$proxy -e HTTPS_PROXY=$proxy -e http_proxy=$proxy -e https_proxy=$proxy \
  -e npm_config_proxy=$proxy -e npm_config_https_proxy=$proxy -e NO_PROXY= \
  -w /tmp/w "$image" sleep 600 >/dev/null
docker exec antidote-target mkdir -p /tmp/w

# install with lifecycle scripts enabled: running them is the point
set +e
if [[ $eco == npm ]]; then
  docker exec antidote-target sh -c "cd /tmp/w && npm init -y >/dev/null && timeout 300 npm install --foreground-scripts '$name@$version'" > "$out/install.log" 2>&1
  server=(docker exec -i -w /tmp/w antidote-target npx --no-install "$name")
else
  docker exec antidote-target timeout 300 pip install --no-cache-dir "$name==$version" > "$out/install.log" 2>&1
  script=$(docker exec antidote-target python -c "import importlib.metadata as m,sys; e=[x for x in m.distribution(sys.argv[1]).entry_points if x.group=='console_scripts']; print(e[0].name if e else '')" "$name" 2>/dev/null)
  server=(docker exec -i antidote-target "$script")
  [[ -n $script ]] || server=()
fi
echo "install exit $?" >> "$out/install.log"
tail -c 200000 "$out/install.log" > "$out/install.tmp" && mv "$out/install.tmp" "$out/install.log"

if [[ ${#server[@]} -gt 0 ]]; then
  "$ops" mcp-probe --timeout 30 -- "${server[@]}" > "$out/tools.json" 2> "$out/probe.err" || rm -f "$out/tools.json"
fi
sleep 5   # let delayed beacons fire
set -e

docker diff antidote-target > "$out/diff.txt"
docker logs antidote-dns > "$out/dns.log" 2>&1
"$ops" detonation-report "$out" ${ANTIDOTE_PREVIOUS_TOOLS_HASH:+--previous-tools-hash "$ANTIDOTE_PREVIOUS_TOOLS_HASH"}
