"""Download training data into ml/data/ (see DATA.md). Re-run is incremental."""
import json
import pathlib
import time

import pandas as pd
import requests

DATA = pathlib.Path(__file__).parent / "data"
UA = {"User-Agent": "antidote-ml/0.1 (+https://github.com/antidote-db/antidote)"}
HF = ["deepset/prompt-injections", "Lakera/gandalf_ignore_instructions", "Lakera/mosscap_prompt_injection",
      "jackhhao/jailbreak-classification", "reshabhs/SPML_Chatbot_Prompt_Injection"]


def hf():
    for name in HF:
        out = DATA / "hf" / (name.replace("/", "__") + ".parquet")
        if out.exists():
            continue
        urls = [u for split in requests.get(f"https://huggingface.co/api/datasets/{name}/parquet", headers=UA, timeout=60).json()["default"].values() for u in split]
        frames = [pd.read_parquet(u) for u in urls]
        out.parent.mkdir(parents=True, exist_ok=True)
        pd.concat(frames, ignore_index=True).to_parquet(out)
        print(name, sum(len(f) for f in frames))


def get(url, **kw):
    for attempt in range(4):
        r = requests.get(url, headers=UA, timeout=60, **kw)
        if r.status_code == 429 or r.status_code >= 500:
            time.sleep(max(int(r.headers.get("retry-after", "0") or 0), 2 ** (attempt + 1)))
            continue
        return r
    r.raise_for_status()


def mcp_registry():
    out = DATA / "mcp_registry.jsonl"
    if out.exists():
        return
    rows, cursor = [], None
    while True:
        params = {"limit": 100, "version": "latest", **({"cursor": cursor} if cursor else {})}
        page = get("https://registry.modelcontextprotocol.io/v0.1/servers", params=params).json()
        for s in page["servers"]:
            d = (s["server"].get("description") or "").strip()
            if d and s["_meta"]["io.modelcontextprotocol.registry/official"].get("isLatest"):
                rows.append({"name": s["server"]["name"], "text": d})
        cursor = page["metadata"].get("nextCursor")
        if not cursor:
            break
    out.write_text("".join(json.dumps(r) + "\n" for r in rows))
    print("mcp registry", len(rows), flush=True)


def clawhub(n=1500):
    out = DATA / "clawhub.jsonl"
    done = {json.loads(l)["slug"] for l in out.read_text().splitlines()} if out.exists() else set()
    api = "https://clawhub.ai/api/v1"
    cursor, fetched = None, 0
    with out.open("a") as f:
        while len(done) < n:
            params = {"limit": 50, "sort": "downloads", "nonSuspiciousOnly": "true", **({"cursor": cursor} if cursor else {})}
            page = get(f"{api}/skills", params=params).json()
            for s in page["items"]:
                key = f'{s["ownerHandle"]}/{s["slug"]}'
                if key in done:
                    continue
                r = get(f"{api}/skills/{s['slug']}/file", params={"path": "SKILL.md", "ownerHandle": s["ownerHandle"]})
                if r is not None and r.status_code == 200:
                    f.write(json.dumps({"slug": key, "text": r.text[:50_000]}) + "\n")
                done.add(key)
                fetched += 1
                time.sleep(0.2)
            cursor = page.get("nextCursor")
            if not cursor:
                break
    print("clawhub skills", len(done), "new", fetched, flush=True)


if __name__ == "__main__":
    DATA.mkdir(exist_ok=True)
    hf()
    mcp_registry()
    clawhub()
