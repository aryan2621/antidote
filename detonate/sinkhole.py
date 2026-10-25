"""mitmproxy addon: log every host the sample contacts, forward only package-registry traffic.

Registry hosts are passed through untouched via --ignore-hosts (see run.sh), so this addon only
ever sees non-registry traffic: it records it and answers 403, so nothing leaves the sandbox.
"""
import json

from mitmproxy import http

LOG = "/logs/proxy.jsonl"


def _log(host: str, blocked: bool) -> None:
    with open(LOG, "a") as f:
        f.write(json.dumps({"host": host, "blocked": blocked}) + "\n")


def http_connect(flow: http.HTTPFlow) -> None:
    _log(flow.request.host, True)
    flow.response = http.Response.make(403, b"blocked by antidote sandbox")


def request(flow: http.HTTPFlow) -> None:
    _log(flow.request.host, True)
    flow.response = http.Response.make(403, b"blocked by antidote sandbox")
