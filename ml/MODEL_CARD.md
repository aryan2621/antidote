# injection-v1

Character 3–5-gram hashing (2^18 features, `char_wb`, lowercase, L2) + logistic regression. Weights are stored as float16.

- **Training data:** see [DATA.md](DATA.md). Training rows: 73263.
- **Thresholds:** calibrated on 6915 held-out benign skill paragraphs and system prompts.
  - medium (`0.9024`) = at most 1% false positives on each source
  - high (`0.9602`) = at most 0.1% false positives on each source
- **mosscap** is never trained on. Its row measures transfer to unseen attack styles.
- **Limits:** English-heavy data, so multilingual injection is weak. Character n-grams don't understand intent, so text *about* injection (security docs) can score high; the scanner limits scoring to agent-facing files for this reason. It is never a "safe" verdict.

## Test-set results

| Source | Label | n | flagged ≥ medium | flagged ≥ high |
|---|---|---|---|---|
| clawhub | benign | 6842 | 0.1% | 0.0% |
| deepset | benign | 57 | 0.0% | 0.0% |
| deepset | injection | 43 | 72.1% | 67.4% |
| gandalf | injection | 149 | 97.3% | 93.3% |
| jackhhao | benign | 93 | 2.2% | 1.1% |
| jackhhao | injection | 107 | 88.8% | 84.1% |
| mcp-registry | benign | 7301 | 0.0% | 0.0% |
| mosscap | injection | 4670 | 28.8% | 20.9% |
| seed | injection | 4 | 25.0% | 25.0% |
| spml | benign | 434 | 0.7% | 0.0% |
| spml | injection | 609 | 94.9% | 88.3% |
| spml-system | benign | 133 | 2.3% | 2.3% |
