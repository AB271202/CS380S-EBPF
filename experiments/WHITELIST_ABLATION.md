# Minimal Whitelist Ablation

This note records the measured minimal-whitelist result used in the experiment context.

## Goal

We wanted a whitelist that was:

- small enough to explain entry by entry,
- strong enough to keep the benign suite quiet,
- and narrow enough that removing any one remaining entry would measurably change the results.

## Final Experimental Baseline

The final reduced whitelist was tested through a config-level trust policy, not by changing the detector's built-in defaults. The baseline kept exactly:

- `gpg`
- `gzip`
- `zstd`
- `ccencrypt`
- `openssl`

The same baseline used the detector's process-tree attribution policy, allowing delegated child writes to be attributed to an eligible suspicious parent.

## Baseline Result

With that five-entry policy, the tuned 3-repeat full run produced:

- Overall: `TP=30`, `FP=0`, `TN=36`, `FN=15`
- Legacy: `TP=6`, `FP=0`, `TN=12`, `FN=3`
- T1486: `TP=0`, `FP=0`, `TN=0`, `FN=12`
- Benign: `TP=0`, `FP=0`, `TN=24`, `FN=0`
- Behavioral: `TP=24`, `FP=0`, `TN=0`, `FN=0`

## Ablation

We then ran a full ablation over just that five-entry policy: baseline, then baseline-minus-one for each entry, across all four suites with three repeats.

| Variant | Legacy TP/FP/TN/FN | T1486 TP/FP/TN/FN | Benign TP/FP/TN/FN | Behavioral TP/FP/TN/FN |
|---|---:|---:|---:|---:|
| `baseline_config` | `6 / 0 / 12 / 3` | `0 / 0 / 0 / 12` | `0 / 0 / 24 / 0` | `24 / 0 / 0 / 0` |
| `remove:gpg` | `6 / 0 / 12 / 3` | `0 / 0 / 0 / 12` | `0 / 3 / 21 / 0` | `24 / 0 / 0 / 0` |
| `remove:gzip` | `6 / 0 / 12 / 3` | `0 / 0 / 0 / 12` | `0 / 3 / 21 / 0` | `24 / 0 / 0 / 0` |
| `remove:zstd` | `6 / 0 / 12 / 3` | `0 / 0 / 0 / 12` | `0 / 3 / 21 / 0` | `24 / 0 / 0 / 0` |
| `remove:ccencrypt` | `6 / 0 / 12 / 3` | `0 / 0 / 0 / 12` | `0 / 3 / 21 / 0` | `24 / 0 / 0 / 0` |
| `remove:openssl` | `6 / 0 / 12 / 3` | `0 / 0 / 0 / 12` | `0 / 3 / 21 / 0` | `24 / 0 / 0 / 0` |

## Interpretation

The pattern was unusually clean:

- every one of the five entries was indispensable,
- removing any one of them caused exactly one benign workload family to flip from `TN=3/3` to `FP=3/3`,
- and no legacy, Atomic, or behavioral count changed under any of those five removals.

The per-entry flips were one-to-one:

- removing `gpg` only broke `neg_gpg_encrypt_benign`
- removing `gzip` only broke `neg_gzip_compress`
- removing `zstd` only broke `neg_zstd_compress`
- removing `ccencrypt` only broke `neg_ccencrypt_encrypt_benign`
- removing `openssl` only broke `neg_openssl_encrypt_benign`

So, in the measured test context, this five-entry set was the minimal whitelist that preserved the final operating point.
