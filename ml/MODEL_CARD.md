# injection-v1

Character 3–5-gram hashing (2^18 features, `char_wb`, lowercase, L2) + logistic regression. Weights are stored as float16.

- **Training data:** see [DATA.md](DATA.md). Training rows: 43465.
- **Thresholds:** calibrated on 538 held-out benign skill paragraphs and system prompts.
  - medium (`0.8900`) = 1% false positives
  - high (`0.9602`) = 0.1% false positives
- **mosscap** is never trained on. Its row measures transfer to unseen attack styles.
- **Limits:** English-heavy data, so multilingual injection is weak. Character n-grams don't understand intent, so text *about* injection (security docs) can score high; the scanner limits scoring to agent-facing files for this reason. It is never a "safe" verdict.

## Test-set results

| Source | Label | n | flagged ≥ medium | flagged ≥ high |
|---|---|---|---|---|
| clawhub | benign | 439 | 0.2% | 0.0% |
| deepset | benign | 57 | 0.0% | 0.0% |
| deepset | injection | 43 | 58.1% | 44.2% |
| gandalf | injection | 149 | 94.0% | 88.6% |
| jackhhao | benign | 93 | 4.3% | 1.1% |
| jackhhao | injection | 107 | 86.0% | 79.4% |
| mcp-registry | benign | 7301 | 0.0% | 0.0% |
| mosscap | injection | 4670 | 22.3% | 13.7% |
| seed | injection | 4 | 25.0% | 25.0% |
| spml | benign | 434 | 0.0% | 0.0% |
| spml | injection | 609 | 93.9% | 84.4% |
| spml-system | benign | 133 | 3.0% | 2.3% |
