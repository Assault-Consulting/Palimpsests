# F-05 — Action binding 0.3.0: W07 cannot be reproduced from the text

For: the Standard's repository. Not filed.

**Minimised:** W07, `vectors.json` `base_report`. With `findings` included, the first difference is at `/results/0/time_assurance/findings`: present in the base report, absent from this reading's report. With `findings` excluded, there is no difference.

**At fault:** the case, relative to the text.

**Draft:**
W07 requires the reference report of A0 and A1 "byte for byte". That includes the wording of every finding, which the text does not fix. A check written from the text can match the statuses and values, which this reading does with `findings` excluded, but not the bytes. Proposed: compare W07 with `findings` excluded, or fix the wording of the findings in the text.
