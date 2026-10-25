# Training data

Only permissively licensed, ungated sources are used. `fetch_data.py` downloads them into `data/`, which is gitignored. Nothing raw is committed. Only the model weights are checked in.

| Source | License | Used as |
|---|---|---|
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | Apache-2.0 | positives (label 1), negatives (label 0) |
| [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | MIT | positives |
| [Lakera/mosscap_prompt_injection](https://huggingface.co/datasets/Lakera/mosscap_prompt_injection) | MIT | positives, **held out entirely** to measure generalization |
| [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | Apache-2.0 | positives (jailbreak), negatives (benign) |
| [reshabhs/SPML_Chatbot_Prompt_Injection](https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection) | MIT | user prompts: positives (Prompt injection = 1), negatives (0) |
| tool-poisoning examples in `seed_positives.txt` (this repo) | Apache-2.0 | positives |
| ClawHub `SKILL.md` files (`nonSuspiciousOnly=true`), paragraphs | per skill (public listing) | negatives: real agent instructions |
| Official MCP registry server descriptions | per server (public listing) | negatives: real tool/server descriptions |

Excluded:
- HackAPrompt: gated.
- xTRam1/safe-guard and BIPIA: no clear license.

ClawHub and MCP-registry text is used only to compute weights; it is not redistributed.
