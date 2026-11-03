# F-02 — Action binding 0.3.0: the dimension of each binding check

For: the Standard's repository. Not filed.

**Minimised:**
- L23: the case expects `authorisation_recheck` failed and `action_binding` verified, for a `recheck_ref` naming a request.
- L42: the case expects `stage_order` failed, for a duplicate `stage_id`.
- L43: the case expects `observed_results` failed, for a result naming a request.

**At fault:** the text is silent.

**Draft:**
The third bullet of "The verifier and its report" lists every binding check in one sentence. The cases fix which dimension fails for a wrong-kind `recheck_ref` or `attempt_ref` and for a duplicate `stage_id`; the text does not. Proposed: name the dimension for each check, or add a table mapping check to dimension.
