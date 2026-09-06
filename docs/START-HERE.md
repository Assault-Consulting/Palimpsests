# Start here — Palimpsests in plain words

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

This page is for someone who has never read an audit-log specification
and does not intend to. Everything here is also true in the precise
documents; this is the version you can read on a phone.

## Seven words

**An AI runtime that writes receipts nobody can edit.**

Longer, but still short: Palimpsests runs a language model on your own
machine and keeps a record of what the model did — which model was
loaded, which tools it called, what it refused to do. The record is
written so that changing, removing, or reordering any line is
detectable afterwards by anyone with the file, using only the published
format — not by trusting us.

## What each word means

| Word | Meaning here |
|---|---|
| **chain** | the audit file. Every record carries the fingerprint of the one before it, so the whole file links into one sequence. Cut a link and the verifier says where. |
| **record** | one line in the chain: a fixed header (who, when, what type) and an optional body (details). About 180 bytes on average. |
| **verify** | recompute every fingerprint and every link and compare. Needs no key, no network, no trust in this software — the format is public, and five independent implementations (three by outside parties) agree on it. |
| **anchor** | the chain's latest fingerprint, kept *outside* the file. Without it a verifier can prove the file is internally consistent but not that its end is really the end. With it, a cut-off tail shows. |
| **witness** | someone else's signed statement that a given fingerprint existed at a given time (a transparency log, a timestamp authority). Optional; where the trail leaves your machine. |
| **advisory** | a note the verifier adds that does not change the verdict — "no anchor was ever written", "a session was never closed". Signals to a human, not failures. |
| **refusal** | when the engine declines to do something unsafe, the refusal itself is written as a record. Silence would be the failure; the record is the guard's receipt. |

## Five minutes

Nothing below needs a model, a GPU, or a network.

```bash
pip install palimpsests
palimpsests demo
```

The demo runs one tiny agent turn — the model asks for a tool, the tool
answers, the model continues — and writes the chain to
`palimpsests-demo.pala`. Seven records: the start of the chain, the boot,
the model load, the session opening, the tool call, the tool result, the
session closing.

**Read it.** The binary file is the evidence; this is the human view:

```bash
palimpsests pala export palimpsests-demo.pala
```

One JSON line per record, in order, then a summary. Note what is *not*
there: no prompt text, no model output, no tool arguments. The chain
records that a tool named `calc.multiply` was called with arguments
whose fingerprint is such-and-such, and that it returned something whose
fingerprint is such-and-such. What was asked and what came back never enter the file. That is a
design choice, not a limitation — see the next section.

**Verify it.** This is what an auditor runs:

```bash
palimpsests pala verify palimpsests-demo.pala
```

You will see three answers, kept apart on purpose:

- *consistency* — do the records link? **yes, 7 records, chain intact.**
- *completeness* — is this the whole chain? **NOT CHECKED**, because you
  did not give it an anchor. The command exits with code 2, not 0: "I
  could not check that" is deliberately not reported as success.
- *witness* — does anyone outside vouch for a point in time? **no
  witness records** — the demo does not talk to the outside.

**Break it.** Change one byte in the middle of the file and verify again:

```bash
printf 'x' | dd of=palimpsests-demo.pala bs=1 seek=400 conv=notrunc
palimpsests pala verify palimpsests-demo.pala
```

`consistency: BROKEN — chain breaks at seq [3]`, exit code 1. The
verifier names the first record that no longer links. Run `palimpsests
demo` again to get a fresh file.

**Get the report.** The same facts as a document you can hand to someone:

```bash
palimpsests pala report palimpsests-demo.pala --html -o report.html
```

One self-contained page, no JavaScript. Its verdict is *partial* — sound
as far as checked, completeness unchecked — which is the honest word for
a chain without an anchor.

**Prove a prefix.** If you archive the first part of a chain and keep
writing, you can later prove the archive is still the beginning of the
live file without re-reading the archive:

```bash
palimpsests pala consistency palimpsests-demo.pala --first 4 -o proof.json
palimpsests pala consistency-verify proof.json
```

That is the five minutes. Point any OpenAI-compatible client at
`palimpsests serve` and the same chain is written for real traffic.

## What enters the chain, and what does not

The rule is one sentence: **operations, never content.**

| Enters the chain | Does not |
|---|---|
| that a model was loaded — which component loaded it, the fingerprint of its weights and of its configuration, and a short clipped note | the weights, the configuration itself, or anything a user typed |
| that a session opened and closed, and when | what was said in it |
| that a tool was called — its registered name, the fingerprint of its arguments, how long it took, what it returned as an outcome (ok / error / timeout / cancelled) | the arguments, the result payload |
| that a tool was *offered* and the model declined to use it in the structured way | what the model's text said instead |
| that a guard refused something, with a category and a severity | — |
| that a human acknowledged an incident candidate, by a pseudonymous operator id | the person's name or account |
| that a key was destroyed to erase records, with a reason code and a ticket reference | the records' contents, which are now unreadable by design |
| how the runtime learned of each tool event: observed on its own wire, or reported by the client | — |

Two consequences worth knowing before you rely on this.

*Fingerprints are one-way.* A fingerprint of the arguments lets someone
who **has** the arguments confirm they are the ones that were used. It
does not let anyone recover them. If you need the content itself on the
record, a deployment may write it into encrypted bodies — and then
destroying the key erases the content while every fingerprint and every
link in the chain stays intact. That is how "we keep every record" and
"we deleted your data" are both true at once.

*"ok" means returned, not confirmed.* When a tool result says `ok`, the
chain proves the tool returned something that re-entered the model's
generation. It does not prove the action took effect in the world — a
payment tool can return `ok` to a request the bank later rejected, and a
runtime at the model's boundary cannot see that. Nothing in the chain
will tell you otherwise, and the report will not say "confirmed".

## What the chain proves, in one table

| Question | Answer from the file alone | Needs |
|---|---|---|
| Was any record altered, removed, or reordered? | yes / no, with the first bad record named | nothing |
| Is this the whole chain, or was the end cut off? | only with an anchor | the latest fingerprint kept outside the file |
| Did this history exist before a certain time? | only with a witness | a signed statement from someone else |
| Did the tool actually do what it was asked? | not answered | a different record, from a different vantage |
| What did the user say? | not recorded | — |

## Where to go next

- The demo, longer: `palimpsests demo` narrates each step; `docs/USAGE.md`
  has every command and setting.
- The format itself, for someone who will implement or audit it:
  `docs/specs/pala-1/PALA-1.md` (frozen, with byte-exact test vectors) and
  the [verification kit](specs/pala-1/verification-kit/README.md).
- How this maps to the EU AI Act's record-keeping duty and to ISO/IEC
  24970: `docs/compliance/`.
- What we claim and what we do not: `SECURITY.md` and
  `docs/ASSURANCE-CASE.md`.
