# F01. `beside_results/st_a` names a key that did not sign `st_a`

For: the Standard's repository (extensions/anchoring/tests). Not filed.

**Minimised.** `vectors.json` `/beside_results/st_a/signature/key_ref` and `/beside_results/st_a/key_state/key_ref` are `witness-a-1`. The statement that result describes, `/scitt/statements/st_a`, is signed with `witness-a-scitt-1` (`signed_with`), its protected header's `kid` is `witness-a-scitt-1`, and its payload's `key_ref` field is `witness-a-scitt-1`. The trust policy lists `witness-a-scitt-1` (not `witness-a-1`) for `log-s`.

**Effect.** J45 ("st_a carried beside the export with its receipt, reported as a verifier reports it") expects consistent; this reading reports inconsistent, first difference `/checkpoints/3/signature/key_ref`. J46 and J47 expect inconsistent and get it, but for the same member, not for the receipt they describe. With only that value changed to `witness-a-scitt-1` (`out/counterfactual-J45-J47.json`), J45 is consistent, J46 differs first at `/receipt/tree_size` and J47 at `/receipt/status`.

**Where the fault is, as far as this reading can tell.** The vector. The text supports `witness-a-scitt-1`: "A witness MUST sign its statements with a key other than the one it signs checkpoints with under the shared rule" (#68), and the check builds the payload with `key_ref` "the key's reference", which must equal `kid`. The descriptions of K85, K127 and K128 also say "witness-a-1's statement" (or "signed by witness-a-1") for statements signed by `witness-a-scitt-1`; K115, K133 and K137 name `witness-a-1` for statements it does sign.

**Draft note.** "vectors.json `beside_results/st_a` reports the signature and key state of `witness-a-1`, but `scitt/statements/st_a` is signed by `witness-a-scitt-1` (kid and payload key_ref alike), as #68 requires. A reader that recomputes the result finds J45 inconsistent at `/checkpoints/3/signature/key_ref`, and J46 and J47 inconsistent at the same member before reaching the receipt. Suggest regenerating `beside_results/st_a` with `witness-a-scitt-1`, and updating the descriptions of K85, K127 and K128."
