# Scope and authorisation agreement (template) - English

> **Draft template. Not legal advice, and not reviewed by a lawyer.** Have a lawyer
> qualified in Dutch law review and adapt it before anyone is asked to sign. Bracketed
> fields are the facts of one engagement, to be filled in by the parties.

**Between**
1. **Client:** [legal name, address, KvK number, representative] ("Client"), and
2. **Provider:** [legal name, address, KvK number, representative] ("Provider").

**Date:** [date]  **Engagement reference:** [reference]

## 1. Purpose

Provider performs the service described in Schedule A ("Services") for Client. Nothing in
this agreement obliges either party to enter further engagements.

## 2. Scope (Schedule A)

2.1 The Services apply **only** to the systems, repositories and addresses listed in
Schedule A ("In Scope"): [repositories / pull requests / domains / IP ranges].

2.2 Everything else is **Out of Scope**, including systems of third parties and any
system not listed. Provider will not test, scan or access anything Out of Scope, and
configures its tools to refuse targets outside Schedule A.

2.3 Time window: [start] to [end], [timezone]. Contact persons for questions and for
stopping the work immediately: Client [name, phone, e-mail]; Provider [name, phone, e-mail].

## 3. Authorisation (this section is a condition for any scan or access)

3.1 Client declares that it owns the In Scope systems or is entitled to authorise the
Services for them, and **authorises Provider to perform the Services on them during the
time window**.

3.2 Where In Scope systems are hosted by third parties (cloud, hosting, CDN), Client is
responsible for any consent those parties require, and has obtained it before the start.

3.3 If Client's statements in 3.1 or 3.2 prove untrue, Provider may stop immediately.
Client indemnifies Provider against third-party claims arising from that untruth.

## 4. Permitted methods and limits

4.1 For vulnerability scans: no denial-of-service or stress testing; no social
engineering or physical access; request rate limited to [rate]; no exploitation beyond
the minimum needed to evidence a finding; no reading, copying or changing of production
data beyond that minimum; no persistence or lateral movement.

4.2 For code review: read-only access to the repositories in Schedule A. Provider
proposes changes as pull requests and does not push to protected branches.

4.3 Provider stops at once when asked by Client's contact person or on noticing impact on
availability.

## 5. Data handling

5.1 Provider treats everything it learns about Client as confidential and uses it only for
the Services.

5.2 Code and findings are processed on Provider's own systems. They are sent to an AI
service provider **only with Client's prior written consent** naming that provider.

5.3 Personal data encountered incidentally is minimised and not copied unless needed as
evidence. If Provider processes personal data on Client's behalf, the parties conclude a
processing agreement before the work starts.

5.4 Provider deletes working copies [30] days after delivery of the report, unless Client
asks otherwise in writing.

## 6. Reporting

6.1 Provider delivers a written report: findings with how each was established, the
limits of the work, and what was not checked. Findings that pose an immediate serious risk
are reported to Client's contact person without waiting for the report.

6.2 The report is Client's. Provider may keep a description of the method, without
identifying Client, and the open-source tools remain under their own licences.

## 7. No guarantee, no certification

7.1 The Services give evidence about what was checked. They are not a certificate, not a
statement of legal compliance (for example with the Cyberbeveiligingswet or NIS2), not
legal advice, and not a guarantee that nothing was missed.

## 8. Fees

8.1 Fixed fee: EUR [amount] excl. VAT, invoiced [on delivery / in two parts]; payable
within [14] days. Work outside Schedule A is agreed in writing first.

## 9. Liability

9.1 Provider's total liability under this agreement is limited to the fees paid for the
engagement in which the damage arose, up to a maximum of EUR [amount], except in case of
intent or deliberate recklessness (opzet of bewuste roekeloosheid) or where the law does not
allow limitation.

9.2 Client acknowledges that testing can, despite care, affect availability of systems and
has taken the backups and precautions it considers necessary.

## 10. Term and termination

10.1 The agreement ends on delivery and acceptance of the report. Either party may end it
earlier in writing; fees for work done remain due.

## 11. Law and disputes

11.1 Dutch law applies. Disputes go to the competent Dutch court.

---

**Signed for Client** ____________________  Name: ____________  Date: __________

**Signed for Provider** __________________  Name: ____________  Date: __________

**Schedule A - Services and In Scope:** [list]
