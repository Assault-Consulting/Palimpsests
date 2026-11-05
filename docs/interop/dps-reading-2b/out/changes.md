# Changes after the first run

The first run of every group is kept as it ran in `first-run/` (13:26:12Z to 13:26:22Z). The results the README reports are in `final/` (13:26:53Z to 13:27:02Z). Each change says what changed, on which sentence it rests, and whether the fault was in the check (the code that implements the text) or in the harness (the code that runs the vectors and records them).

| # | What changed | Rests on | Fault in | Effect |
|---|---|---|---|---|
| C01 | `run_2b.py`, group A7 only: the first run stored, for every run that departed from D.6's expected step, the full outcome with its trace. In A7 every run departs (all 46,920 return invalid at step 3, where D.6 states step 2), so `first-run/a7_substitution_claimed_from_presented.json` holds 46,920 full traces (34.9 MB). Now each such run is listed as its row, and the full outcome is kept for the first run of each artifact. | none (recording only) | harness | No verdict or step changed. Every row and every count of A7 is the same in `first-run/` and `final/`; the other six result files are byte-identical between the two runs. |

No change was made to the check (`verify_anchor.py`, `chain.py`).

No change was made to reading 2's parser or replay. Reading 2's record was used as unzipped: after all runs, a fresh unzip of `dps-reading-2.zip` and the working copy were compared with `diff -r` (no difference), and reading 2's `ots_replay.py` was run again; its output was byte-identical to the published `out/ots-replay.json` (SHA-256 `4d530f93…6e27`).
