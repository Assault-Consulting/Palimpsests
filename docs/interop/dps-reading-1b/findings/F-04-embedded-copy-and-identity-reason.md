# F-04 — Signatures 0.2.0: `embedded_copy` with no copy; reasons for identity not checked

For: the Standard's repository. Not filed.

**Minimised:**
- O03 and O05, `embedded_copy`. Both expect `not_checked` for an attachment carrying no copy; the text describes the comparison only when a copy is present.
- N28 and the cases giving `identity_reason`: the values `not_held`, `not_read` and `none_read` are used by the cases but defined neither in the text nor in the report schema.

**At fault:** the text is silent.

**Draft:**
State `embedded_copy` for an action-binding attachment that carries no copy of its seal. Define the reasons identity is reported `not_checked` when no actor can be read, and their names.
