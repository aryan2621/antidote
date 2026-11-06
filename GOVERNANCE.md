# Governance

Antidote is run by the community. No company owns the data, and anyone can use it.

## Who decides

Maintainers are the repository's owners, members and collaborators with write access. They review reports, merge entries and rules, and sign feed releases. New maintainers are proposed in an issue by an existing maintainer and added once no other maintainer objects within 7 days. Decisions are made by agreement in issues and PRs. If maintainers disagree, the majority of active maintainers decides. A maintainer who has been inactive for 6 months becomes emeritus.

## How a report is handled

Every report moves `reported → verified | disputed | rejected`:

| Step | Time |
|---|---|
| First reply | 3 business days |
| Decision (verified or rejected) | 14 days |
| Malware still live on a registry | same day, and we tell the registry too |

- **Verified** means a public source, a reproducible sample or a detonation report, checked by a maintainer other than the reporter.
- **Reported** entries are public but labelled "not yet verified".
- Rejected reports are allowlisted for that exact version (`/reject`), so the crawler doesn't raise them again.

## If you disagree with an entry

Package authors can contest an entry by opening an issue titled `Dispute: <entry id>`, or privately through a GitHub Security Advisory.

1. The entry is marked `disputed`, not removed.
2. A maintainer who didn't verify it reviews the evidence within 14 days.
3. It is corrected, withdrawn (`withdrawn` is set and it is kept for history) or left as is. The reason is recorded in the issue.

Every dispute and its outcome stays public. Entries describe behaviour and indicators from evidence. They say "suspicious" when intent is unclear, and never call a person malicious.

## Bugs vs malware

For bugs (not malice), the author is told privately first. The entry goes public after the fix ships or after 90 days, whichever comes first (30 days if the bug is being exploited). Malware is published immediately. Vulnerabilities in Antidote itself: see [SECURITY.md](SECURITY.md).

## Samples and licences

Entries hold hashes, indicators and defanged excerpts only. Raw samples are never committed, and live payloads and working exploits are not published. Code is Apache-2.0 ([LICENSE](LICENSE)). Data in `corpus/` and `schema/` is CC-BY-4.0 ([LICENSE-DATA](LICENSE-DATA)): credit "Antidote contributors". Reporters are credited in the entry's `reporter` field unless they ask not to be.
