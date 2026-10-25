# Governance

Antidote is a neutral, community-run database. No vendor owns the data, and anyone may use it under its licence.

## Maintainers

Maintainers are the repository's owners, members and collaborators with write access. They triage reports, merge entries and rules, and sign feed releases. New maintainers are proposed in an issue by an existing maintainer and added once no other maintainer objects within 7 days. A maintainer who has been inactive for 6 months is moved to emeritus.

Decisions are made by lazy consensus in issues and PRs. If maintainers disagree, the majority of active maintainers decides.

## Triage

Every report moves `reported → verified | disputed | rejected`:

| Step | Target |
|---|---|
| First response to a report | 3 business days |
| `verified` or `rejected` | 14 days |
| Malicious artifact still live on a registry | same day, and report it to the registry too |

- **`verified`** needs a public source, a reproducible sample or a detonation report, and is checked by a maintainer other than the reporter.
- **`reported`** entries are published, clearly labelled as not yet independently verified.
- Rejected reports are allowlisted for that exact version (`/reject`), so the crawler doesn't raise them again.

## Disputes and takedowns

Publishers and authors can contest an entry by opening an issue titled `Dispute: <entry id>`, or privately through a GitHub Security Advisory.

1. While the dispute is reviewed, the entry is marked `disputed`. It is not removed.
2. A maintainer who didn't verify the entry reviews the evidence, within 14 days.
3. The outcome is one of: the entry is corrected, it is withdrawn (`withdrawn` set, kept for history), or it stands. The reason is recorded in the issue.

Every dispute and its outcome stays public, as the review log. Entries describe behaviour and indicators from evidence. They use "suspicious" when intent is unclear, and never call a person malicious.

## Responsible disclosure

For **vulnerable** items (bugs, not malice), the author is told privately first. The entry is published after the fix ships or 90 days pass, whichever is first. This can be shortened to 30 days if the bug is being exploited. **Malicious** items are published immediately.

Vulnerabilities in Antidote itself: see [SECURITY.md](SECURITY.md).

## Samples

Public entries hold hashes, indicators and defanged excerpts only. Raw samples are never committed. Live payloads and working exploits are not published.

## Licences

- Code: Apache-2.0 ([LICENSE](LICENSE)).
- Data in `corpus/` and `schema/`: CC-BY-4.0 ([LICENSE-DATA](LICENSE-DATA)). Credit "Antidote contributors".

## Recognition

Reporters are credited in the entry's `reporter` field unless they ask not to be.

## Later

- Apply to become a CVE Numbering Authority (CNA) for agent artifacts.
