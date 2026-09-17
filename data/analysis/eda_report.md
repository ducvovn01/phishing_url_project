# EDA Report - Phishing URL Dataset

Combined dataset: `/home/lvsumi/Documents/Swinburne/Computing Technology Innovation Project/cos30049-phishing-url-detector/data/processed/combined_dataset.csv`

## Summary of findings

- Combined, deduplicated dataset holds 1607776 rows across 4 sources: 827502 phishing (51.47%) vs 780274 legitimate (48.53%) - roughly balanced overall, a ~1.5pp skew toward phishing.
- Class balance is NOT even per source: harisudhan411 skews phishing (33824 legitimate vs 158496 phishing); mitake skews legitimate (608350 legitimate vs 249303 phishing); phiusiil skews legitimate (134424 legitimate vs 79770 phishing); semihguner skews phishing (3676 legitimate vs 339933 phishing). mitake contributes the most rows post-dedup.
- Cross-source overlap: 978374 of 2586150 raw rows (~38%) were exact duplicates after canonicalizing URLs. Largest source-pairs: harisudhan411→mitake: 620307; semihguner→mitake: 293081; mitake→mitake: 28359 - sources are not independent samples, so per-source class balance and any train/test split should account for this shared content rather than treating sources as disjoint.
- Data quality: 0 null and 0 empty/whitespace-only `url` rows, 0 rows with a no-dot hostname (malformed/local-like) - these were already logged and dropped by normalize_datasets.py before dedup, so the checks above should read 0. No invalid label values found.
- Feature-relevant signals: mean dot count - legitimate 1.82, phishing 2.15; mean hyphen count - legitimate 1.10, phishing 0.58 (hyphen count alone is not a reliable phishing signal in this data, contrary to common assumption). IP-address hostnames are rare overall but far more common in phishing (2.312% vs 0.003% legitimate) - a strong candidate feature. TLD distribution is skewed (see table below) - TLD looks like a useful categorical feature.

Total rows: 1607776

## Missing values / malformed URLs

- Null `url`: 0
- Empty/whitespace-only `url`: 0
- Null `label`: 0
- `label` not in {0,1}: 0
- Hostname with no dot (malformed/local-like): 0

## Class balance (overall)

- legitimate (label=0): 780274 (48.53%)
- phishing (label=1): 827502 (51.47%)

## Class balance by source

| source        |   legitimate |   phishing |
|:--------------|-------------:|-----------:|
| harisudhan411 |        33824 |     158496 |
| mitake        |       608350 |     249303 |
| phiusiil      |       134424 |      79770 |
| semihguner    |         3676 |     339933 |

## URL length

| label      |   count |    mean |     std |   min |   25% |   50% |   75% |   max |
|:-----------|--------:|--------:|--------:|------:|------:|------:|------:|------:|
| legitimate |  780274 | 39.5949 | 29.3401 |     4 |    22 |    31 |    49 |  2073 |
| phishing   |  827502 | 40.8735 | 65.4442 |     3 |    19 |    27 |    43 | 25515 |

## Duplicate / overlap counts

Total duplicate rows removed: 978374

Dropped per source:

| dropped_source   |   count |
|:-----------------|--------:|
| harisudhan411    |  629555 |
| semihguner       |  298859 |
| mitake           |   28359 |
| phiusiil         |   21601 |

Dropped per source-pair (dropped_source -> kept_source):

|                                    |      0 |
|:-----------------------------------|-------:|
| ('harisudhan411', 'harisudhan411') |   8647 |
| ('harisudhan411', 'mitake')        | 620307 |
| ('harisudhan411', 'semihguner')    |    601 |
| ('mitake', 'mitake')               |  28359 |
| ('phiusiil', 'harisudhan411')      |   1043 |
| ('phiusiil', 'mitake')             |  16287 |
| ('phiusiil', 'phiusiil')           |   2124 |
| ('phiusiil', 'semihguner')         |   2147 |
| ('semihguner', 'mitake')           | 293081 |
| ('semihguner', 'semihguner')       |   5778 |

## Dot / hyphen counts and IP hostnames

- Mean dot count - legitimate: 1.82, phishing: 2.15
- Mean hyphen count - legitimate: 1.10, phishing: 0.58
- IP-address hostname - legitimate: 0.003%, phishing: 2.312%

## TLD frequency (top 15 overall)

|      |   legitimate |   phishing |
|:-----|-------------:|-----------:|
| au   |         6282 |       5448 |
| br   |         3034 |      10227 |
| ca   |        13636 |       2025 |
| cn   |          815 |      37755 |
| com  |       490728 |     340454 |
| de   |         8895 |       4278 |
| edu  |        18688 |         63 |
| info |         2884 |      10066 |
| net  |        36193 |      55364 |
| org  |        90303 |      33471 |
| ru   |         4068 |      14729 |
| tk   |           86 |      12502 |
| top  |           13 |      34568 |
| uk   |        18757 |       5272 |
| xyz  |          149 |      18882 |
