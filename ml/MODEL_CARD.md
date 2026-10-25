# injection-v1

Character 3–5-gram hashing (2^18 features, `char_wb`, lowercase, L2) + logistic regression. Weights are stored as float16.

- **Training data:** see [DATA.md](DATA.md). Training rows: 42281.
- **Thresholds:** calibrated on 8082 held-out benign texts.
  - medium (`0.5841`) = 1% false positives
  - high (`0.9116`) = 0.1% false positives
- **mosscap** is never trained on. Its row measures transfer to unseen attack styles.
- **Limits:** English-heavy data, so multilingual injection is weak. Character n-grams don't understand intent, so text *about* injection (security docs) can score high; the scanner limits scoring to agent-facing files for this reason. It is never a "safe" verdict.

## Test-set results

| Source | Label | n | flagged ≥ medium | flagged ≥ high |
|---|---|---|---|---|
| clawhub | benign | 184 | 1.6% | 0.5% |
| deepset | benign | 57 | 3.5% | 0.0% |
| deepset | injection | 43 | 81.4% | 55.8% |
| gandalf | injection | 149 | 98.0% | 91.9% |
| jackhhao | benign | 93 | 22.6% | 2.2% |
| jackhhao | injection | 107 | 95.3% | 85.0% |
| mcp-registry | benign | 7301 | 0.0% | 0.0% |
| mosscap | injection | 4670 | 44.4% | 20.4% |
| seed | injection | 4 | 25.0% | 25.0% |
| spml | benign | 434 | 3.9% | 0.0% |
| spml | injection | 609 | 98.2% | 92.4% |
| spml-system | benign | 133 | 28.6% | 3.0% |
