# P2 findings: Unicode look-alike evasion

Source: `homoglyph_evasion.py`, one run on 2026-10-17 against `char_ngram_logreg`
`a2-3fa96dd` (SHA-256 `66b9a09c…9b41`, threshold 0.5), seed 42. Raw numbers are in
`results/summary.json`; every case is in `results/cases.csv` and every benign URL in
`results/benign.csv`. All URLs were scored as text only and never opened.

## What was tested

- **Attack:** rewrite a brand name (`paypal`, `apple`, ...) with look-alike characters.
  Five strategies: one Cyrillic letter, every Cyrillic-replaceable letter, Greek letters,
  fullwidth Latin, and dot-below/above Latin letters (`pạypạl`). The defence does not
  cover the last one, on purpose.
- **Conditions:** `baseline` (the A2 pipeline as the API runs it); `naive_fold` (NFKC +
  confusable map, then the A2 pipeline); `defended` (the same folding, but the A2 brand
  mask is decided on the *original* host; `app/services/normalization.py`).
- **Cases (1,095 distinct variants):**
  - A: 16 synthetic phishing URLs × 5 strategies = 79 (one Greek rewrite left `dhl`
    unchanged and was dropped).
  - B: 8 official domains turned into IDN homographs × 2 Cyrillic strategies = 16.
  - C: 200 phishing URLs from the A2 domain-grouped test split, with a brand name in the
    host and detected by the baseline, × 5 strategies = 1,000.
- **Evasion rate:** variants scored below the threshold, counted only over variants of
  bases the baseline detects. All 16 A bases and all 200 C bases were detected, so no
  missed base had to be excluded.

## Results

| Set | n | baseline | naive_fold | defended |
|---|---:|---:|---:|---:|
| A evasion (synthetic) | 79 | 0 (0.0%) | 0 | 0 |
| C evasion (dataset) | 1,000 | 9 (0.9%) | 1 (0.1%) | 1 (0.1%) |
| B homographs detected | 16 | 16 (100%) | **10 (62.5%)** | 16 (100%) |

C evasion by strategy (out of 200 each), baseline → defended: Greek 5 → 0, fullwidth 2 → 0,
Cyrillic-all 1 → 0, Cyrillic-one 0 → 0, dot diacritics (not covered) 1 → 1.
Paired on the same 1,000 variants, 8 were missed by the baseline and caught by the
defence and none the other way round (exact McNemar p = 0.0078).

Benign URLs flagged as phishing (false positives); both defences changed no label:

| Benign set | n | changed by folding | baseline | naive_fold | defended |
|---|---:|---:|---:|---:|---:|
| Test-split legitimate sample | 5,000 | 0 | 384 (7.68%) | 384 | 384 |
| Test-split legitimate, non-ASCII | 60 | 7 | 6 (10.0%) | 6 | 6 |
| `data/test_urls.csv` legitimate | 95 | 0 | 23 (24.2%) | 23 | 23 |

Latency per single-URL call over all 6,250 attack and benign URLs (ms):
baseline mean 1.627 / p95 2.879, naive_fold 1.663 / 2.985, defended 1.553 / 2.827.
These differences are within run-to-run noise on this Windows laptop; the defence adds no
measurable cost.

## What it means

1. **The A2 model is already hard to evade with look-alikes.** Look-alike characters
   produce n-grams the model never saw (weight about 0); TF-IDF normalisation then shrinks
   the remaining weights, and the intercept is positive (+2.63), so the score drifts
   toward phishing rather than away from it. Only the 9 C variants of borderline bases
   (baseline 0.56–0.76) crossed the threshold.
2. **The defence works where it applies.** It brought C evasion from 9/1,000 to 1/1,000.
   The one left is the dot-diacritic strategy it does not cover. For every caught case the
   defended score equals the ASCII base's score, because folding recovers the original text.
3. **Naive folding is harmful.** Folding `pаypal.com` to `paypal.com` lets the A2 brand mask
   treat the attacker's domain as the official one (`§.com`). That dropped homograph
   detection from 16/16 to 10/16. Any normalisation has to keep the mask decision on the
   original host.
4. **Caveat on B:** the baseline also flags 5 of the 8 real ASCII login URLs
   (`paypal.com/signin` 0.348 is one of the 3 it does not). So 100% homograph detection
   mostly reflects how the model scores login paths, not real homograph awareness.
5. **Limits:** NFKC does not fold cross-script letters. The table covers only the letters
   listed in `normalization.py`, not all of `confusables.txt`. Diacritic look-alikes
   (`ạ`, `ọ`) are untouched, because stripping accents would change legitimate
   Vietnamese, French or German domains. The benign non-ASCII set is small (60 URLs, 7
   changed by folding).

## Decision for v1

**The defence is not enabled in the v1 API.** The API keeps exact A2 parity, and it still
shows look-alikes to the user through the `rule-brand-lookalike` signal (which uses A2's
own homoglyph and leetspeak maps).

The reasons:

- the measured gain is small (8 of 1,000 variants);
- it changes the model input relative to A2, which breaks the parity tests by design;
- folded text can change length, so n-gram offsets would no longer map onto `analysed_url`.

If the team wants it on, use `defended_model_input()` (never `naive_fold`). Score with
`PreprocessedScorer`, keep `analysed_url` as the unfolded text, and return `ngram` signals
with null offsets for folded inputs. That is a small, separate PR.
