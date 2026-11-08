# Services (planned) - English

Status: **not yet accepting paid engagements.** Registration as a business (KvK) comes
first. Indicative prices exist so you can judge fit; they are not quotes.

## 1. AI-code security review

**For** a repository, or one team's pull requests, where AI agents wrote code or
security fixes, and someone (a customer, an auditor, a board) asks "how do you know the
fixes are real?"

**Method.** Run the Saikou engine over the changes (suppression laundering, unwired
guards, partial shared-sink fixes, elision, API breaks, weakened analyser config), then
review what it flags and what it cannot judge.

**Deliverables**
- Written report. Every finding states how it was established (tool, parser or
  mechanical). A plain list of what was *not* checked.
- Fix pull requests for changes that pass verification. Attempts that fail are reported
  as rejected, with the reason.
- Machine-readable results (JSON and SARIF).

**Indicative price:** EUR 750-1,500 fixed per repository scope, agreed before start.
**Indicative time:** 3-5 working days.

**You provide:** read access to the repository or pull requests; a contact person who can
answer questions about intent.

**Not included:** penetration testing; audit of the whole system; fixing everything found;
any certificate or compliance statement.

## 2. External vulnerability scan (in preparation)

**For** internet-facing systems you own, as one input to vulnerability handling.

**Deliverable:** report of findings with evidence, filtered for false positives, with an
explicit statement of what was and was not in scope.

**Indicative price:** EUR 1,500-3,000 per engagement.

**Preconditions, none of which exist yet:**
1. The scanning tooling enforces an agreed scope itself and refuses any other target.
2. Real scans only; demonstration or sample data never appears in a client report.
3. A signed scope and authorisation agreement ([template](scope-agreement.en.md)).
4. Professional liability insurance in place.

## How an engagement runs

1. Scope in writing: what is in, what is out, price, delivery date.
2. Signed authorisation before any scan or access.
3. Your code stays with me and my tools. The verification engine runs locally. Nothing is
   sent to an AI provider without your written consent, and then only to the one you name.
4. Report and hand-over; follow-up questions are part of the price.

## What you do not get

- A certificate, a score, or the statement that you are "NIS2 compliant". Compliance is a
  legal judgement; this is evidence towards it.
- Legal advice.
- A guarantee that nothing was missed.

## Context

The Dutch Cyberbeveiligingswet implements NIS2 and has applied since 15 August 2026 to
more than 8,000 organisations ([NCSC](https://www.ncsc.nl/nieuws/cbw-en-wwke-vanaf-15-augustus-2026-van-kracht)).
Article 21(2)(e) of the directive covers security in the acquisition, development and
maintenance of network and information systems, including vulnerability handling
([EUR-Lex 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj/eng)). This is
context, not legal advice.
