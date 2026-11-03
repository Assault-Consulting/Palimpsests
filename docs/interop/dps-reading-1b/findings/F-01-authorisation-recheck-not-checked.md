# F-01 — Action binding 0.3.0: when `authorisation_recheck` is not checked

For: the Standard's repository. Not filed.

**Minimised:** L07, field `authorisation_recheck`.

| Case | What is recorded | Expected |
|---|---|---|
| L07 | A recheck that refuses; no attempt | `verified` |
| L02 | No recheck; no attempt | `not_checked` |

**At fault:** the text is silent; the case is consistent with the base report.

**Draft:**
The text says each attempt follows an authorising recheck, but not when the dimension is `not_checked`. L02 and L07 differ only by a recorded refusing recheck. The rule appears only in the base report's finding ("no recheck or attempt is recorded"). A reading from the text chose "no attempt" and failed L07. Proposed: state in "The verifier and its report" that `authorisation_recheck` is `not_checked` when neither a recheck nor an attempt is recorded.
