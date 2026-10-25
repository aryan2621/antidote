"""Train, calibrate and export the prompt-injection classifier (see ../crates/core/src/classify.rs).

uv run python train.py  →  ../corpus/models/injection-v1.json, MODEL_CARD.md
"""
import base64
import json
import pathlib
import random
import re

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import LogisticRegression

HERE = pathlib.Path(__file__).parent
DATA = HERE / "data"
REPO = HERE.parent
VERSION = "injection-v1"
N_FEATURES = 2**18
NGRAM = (3, 5)
rng = random.Random(0)


def segments_md(text):
    """Mirror of classify::segments_md in Rust: change both together."""
    out, para, start = [], [], 0
    in_front = in_fence = False

    def flush():
        joined = " ".join(para)
        if len(joined) >= 20:
            out.append(joined)
        para.clear()

    for i, line in enumerate(text.split("\n")):
        t = line.strip()
        if i == 0 and t == "---":
            in_front = True
            continue
        if in_front:
            if t == "---":
                in_front = False
            elif t.startswith("description:"):
                d = t[len("description:"):].strip().strip("\"'")
                if len(d) >= 20:
                    out.append(d)
            continue
        if t.startswith("```"):
            flush()
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if not t or t.startswith("#"):
            flush()
            if t.startswith("#"):
                para.append(t)
                flush()
            continue
        para.append(t)
    flush()
    return out


def load():
    rows = []
    add = lambda texts, label, source: rows.extend((str(t), label, source) for t in texts if isinstance(t, str) and len(t.strip()) >= 20)
    hf = lambda n: pd.read_parquet(DATA / "hf" / f"{n}.parquet")

    d = hf("deepset__prompt-injections")
    add(d[d.label.astype(int) == 1].text, 1, "deepset")
    add(d[d.label.astype(int) == 0].text, 0, "deepset")
    add(hf("Lakera__gandalf_ignore_instructions").text, 1, "gandalf")
    d = hf("jackhhao__jailbreak-classification")
    add(d[d.type == "jailbreak"].prompt, 1, "jackhhao")
    add(d[d.type == "benign"].prompt, 0, "jackhhao")
    d = hf("reshabhs__SPML_Chatbot_Prompt_Injection")
    add(d[d["Prompt injection"].astype(int) == 1]["User Prompt"].sample(4000, random_state=0), 1, "spml")
    add(d[d["Prompt injection"].astype(int) == 0]["User Prompt"], 0, "spml")
    add(d["System Prompt"].drop_duplicates(), 0, "spml-system")  # benign agent instructions
    mosscap = hf("Lakera__mosscap_prompt_injection").prompt.drop_duplicates().sample(5000, random_state=0)
    add(mosscap, 1, "mosscap")

    seeds = [l for l in (HERE / "seed_positives.txt").read_text().splitlines() if l and not l.startswith("#")]
    add(seeds, 1, "seed")

    if (DATA / "mcp_registry.jsonl").exists():
        add([json.loads(l)["text"] for l in (DATA / "mcp_registry.jsonl").read_text().splitlines()], 0, "mcp-registry")
    if (DATA / "clawhub.jsonl").exists():
        paras = [p for l in (DATA / "clawhub.jsonl").read_text().splitlines() for p in segments_md(json.loads(l)["text"])]
        add(paras, 0, "clawhub")

    df = pd.DataFrame(rows, columns=["text", "label", "source"]).drop_duplicates("text")
    return df


def split(df):
    """mosscap is test-only (generalization); every other source splits 70/15/15 train/calib/test."""
    part = []
    for _, row in df.iterrows():
        if row.source == "mosscap":
            part.append("test")
        else:
            r = rng.random()
            part.append("train" if r < 0.70 else "calib" if r < 0.85 else "test")
    df = df.assign(part=part)
    # seeds are few and on-target: keep most for training, a few for test
    return df


def f16_roundtrip(w):
    return w.astype(np.float16).astype(np.float32)


def main():
    df = split(load())
    print(df.groupby(["source", "label", "part"]).size().unstack(fill_value=0))
    vec = HashingVectorizer(analyzer="char_wb", ngram_range=NGRAM, n_features=N_FEATURES, alternate_sign=False, lowercase=True, norm="l2")
    tr = df[df.part == "train"]
    clf = LogisticRegression(C=4.0, class_weight="balanced", max_iter=3000, solver="liblinear")
    clf.fit(vec.transform(tr.text), tr.label)

    w = f16_roundtrip(clf.coef_[0].astype(np.float32))
    b = float(clf.intercept_[0])
    score = lambda texts: 1 / (1 + np.exp(-(vec.transform(texts) @ w + b)))

    # calibrate on skill paragraphs and system prompts: the hardest benign text the scanner scores (MCP descriptions score far lower)
    cal = df[(df.part == "calib") & (df.label == 0) & df.source.isin(["clawhub", "spml-system"])]
    s_cal = np.sort(score(cal.text))
    t_med = float(np.quantile(s_cal, 0.99))
    t_high = float(np.quantile(s_cal, 0.999))
    print(f"thresholds: medium={t_med:.4f} high={t_high:.4f} (from {len(cal)} benign calib texts)")

    te = df[df.part == "test"].assign(score=lambda d: score(d.text))
    lines = ["| Source | Label | n | flagged ≥ medium | flagged ≥ high |", "|---|---|---|---|---|"]
    for (src, lab), g in te.groupby(["source", "label"]):
        lines.append(f"| {src} | {'injection' if lab else 'benign'} | {len(g)} | {(g.score >= t_med).mean():.1%} | {(g.score >= t_high).mean():.1%} |")
    metrics = "\n".join(lines)
    print(metrics)
    agent_neg = te[(te.label == 0) & te.source.isin(["clawhub", "mcp-registry", "spml-system"])]
    pos = te[(te.label == 1) & (te.source != "mosscap")]
    print(f"\nTARGET recall(in-dist positives, medium) = {(pos.score >= t_med).mean():.3f}  FPR(agent text, medium) = {(agent_neg.score >= t_med).mean():.4f}")

    out = REPO / "corpus/models" / f"{VERSION}.json"
    out.write_text(json.dumps({
        "version": VERSION,
        "n_features": N_FEATURES,
        "ngram": list(NGRAM),
        "bias": b,
        "threshold_medium": t_med,
        "threshold_high": t_high,
        "weights": base64.b64encode(w.astype("<f2").tobytes()).decode(),
    }) + "\n")

    (HERE / "MODEL_CARD.md").write_text(f"""# {VERSION}

Character 3–5-gram hashing (2^18 features, `char_wb`, lowercase, L2) + logistic regression. Weights are stored as float16.

- **Training data:** see [DATA.md](DATA.md). Training rows: {len(tr)}.
- **Thresholds:** calibrated on {len(cal)} held-out benign skill paragraphs and system prompts.
  - medium (`{t_med:.4f}`) = 1% false positives
  - high (`{t_high:.4f}`) = 0.1% false positives
- **mosscap** is never trained on. Its row measures transfer to unseen attack styles.
- **Limits:** English-heavy data, so multilingual injection is weak. Character n-grams don't understand intent, so text *about* injection (security docs) can score high; the scanner limits scoring to agent-facing files for this reason. It is never a "safe" verdict.

## Test-set results

{metrics}
""")
    print(f"\nwrote {out.relative_to(REPO)} ({out.stat().st_size // 1024} KB), MODEL_CARD.md")


if __name__ == "__main__":
    main()
