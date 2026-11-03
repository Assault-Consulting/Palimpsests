# F-06 — Action binding 0.3.0: a referenced policy, a specification's own expiry, an approval's age

For: the Standard's repository, as a question. Not filed.

**Facts:**
- On Lemonnier's negatives N4, N5 and N6, every dimension the two extension texts define has the same status as on the base.
- No dimension reads:
  - the issuer's policy document that `policy_version` names;
  - a specification's own `valid_until`;
  - an approval's maximum age.
- His `summary.json` reports these under `policy_checks`, outside the extensions.
- In N6, a recheck recorded as `authorised` 28 minutes after the approval, past the specification's `valid_until`, gives `authorisation_recheck` verified under the text.

**At fault:** none established; this is a scope question.

**Draft:**
Is it intended that action binding leaves a specification's own expiry, a policy referenced by `policy_version`, and an approval's age to the executor's recheck? If so, could "What this shows, and what it does not" and the verifier's scope say that these are not checked?
