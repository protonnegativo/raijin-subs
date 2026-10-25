# Token benchmark: subfinder + dnsx vs raijin-subs

How many tokens does an AI agent spend reading the result of a subdomain enumeration, and does it lose anything? This benchmark enumerates three public root domains with subfinder, resolves every name with dnsx, counts the tokens in each output shape, and checks that every name and record is in the raijin-subs output.

Reproduce from the saved engine output: `bench/run.sh`. Re-enumerate and refresh the fixtures first: `LIVE=1 bench/run.sh` (needs network; the names and records will differ from the numbers below, since passive sources and DNS change).

## Setup

- **Targets:** three public root domains of companies with public bug bounty programs, which publish many subdomains and are common public examples: `hackerone.com`, `gitlab.com` and `shopify.com`. Enumeration was run on 2026-10-24.
- **Passive only.** subfinder asked public passive sources; with no API keys configured, the names came from subdomaincenter, crt.sh and HackerTarget. dnsx asked public DNS resolvers. Nothing was sent to the discovered hosts: no HTTP, no port probes. The wildcard check added one DNS query per crowded parent (3 in total).
- **subfinder:** v2.6.7, `-timeout 20 -max-time 3`. **dnsx:** v1.2.1, defaults.
- **Fixtures:** `bench/fixtures/<scenario>/raw.jsonl` is the `raw` file of the live raijin-subs run: subfinder's `-json -cs` lines, dnsx's `-json -omit-raw` lines and the wildcard probes. They were recorded when raijin-subs still passed `-cname` to dnsx (it no longer does, since that hides NXDOMAIN); the only names it could change are NOERROR with a CNAME and no address, and those are NODATA with or without `-cname`, so the fixtures stand. `dnsx.txt` is dnsx's text output (`-a -aaaa -cname -resp -silent`) on the same names, run right after. Every row below is computed from these files, so `bench/run.sh` gives the same numbers offline.
- **raijin-subs:** replays `raw.jsonl` with `--input`, so every row sees the same names and records. Defaults apply: no limit on findings, and `--max-bytes 64000`, which was not reached.
- **Baselines**, as an agent would read the engines:
  - JSON: the subfinder and dnsx lines of `raw.jsonl` (`subfinder -json -cs` plus `dnsx -json -omit-raw`), without the wildcard probes. This is the leanest JSON dnsx writes; without `-omit-raw` each line also carries the raw DNS message.
  - Text: `subfinder -silent` (one name per line; the same names as in `raw.jsonl`), then `dnsx.txt`. dnsx's text output has one line per record and no line for names that do not resolve.
- **Tokens:** counted with tiktoken (`o200k_base`). This is a **proxy**, because Claude's tokenizer is not public. `bench/count_tokens.py` also gives exact Claude counts if `ANTHROPIC_API_KEY` is set and the `anthropic` package is installed. `cl100k_base` gives the same ratios.

## Scenario 1: noisy (hackerone.com)

510 names. 498 come from a passive dataset and no longer exist: hackerone.com's DNS answers NOERROR with no record (`NODATA`) for them. 12 resolve. raijin-subs returned 4 findings (GitHub Pages for three `mta-sts` names, SendGrid twice, Freshdesk; all low) and 5 groups.

| Output | Bytes | Tokens | vs. engines JSON |
|---|---:|---:|---:|
| subfinder `-json -cs` + dnsx `-json -omit-raw` | 377,344 | 128,845 | 1× |
| subfinder text + dnsx text | 14,310 | 5,567 | 23× |
| **raijin-subs JSON (default)** | 13,892 | **4,810** | **27×** |
| raijin-subs `--pretty` | 19,648 | 6,166 | 21× |
| raijin-subs `--format table` | 725 | 264 | 488× |

## Scenario 2: findings (gitlab.com)

830 names. 130 resolve, 602 are NXDOMAIN (mostly old review apps under `design-staging.gitlab.com`), 98 are NODATA. raijin-subs returned 29 findings and 56 groups. The findings are CNAMEs to GitLab Pages, Zendesk, Marketo, Heroku and AWS, and names like `staging`, `grafana`, `prometheus`, `registry`, `internal` and `dev` that resolve. All 29 are low: no CNAME in this run was dangling and no record was private. The wildcard check found `*.community.gitlab.com` (6 names).

| Output | Bytes | Tokens | vs. engines JSON |
|---|---:|---:|---:|
| subfinder `-json -cs` + dnsx `-json -omit-raw` | 891,477 | 294,874 | 1× |
| subfinder text + dnsx text | 55,784 | 20,999 | 14× |
| **raijin-subs JSON (default)** | 49,713 | **17,063** | **17×** |
| raijin-subs `--pretty` | 66,801 | 21,445 | 14× |
| raijin-subs `--format table` | 6,611 | 2,435 | 121× |

## Scenario 3: wildcard (shopify.com)

549 names. 506 are answered by the wildcard `*.shopify.com` (CNAME `wc.shopify.com`): the random probe name got the same CNAME chain. raijin-subs returned 1 finding (a CNAME to Google, low) and 11 groups; the wildcard group lists all 506 names.

| Output | Bytes | Tokens | vs. engines JSON |
|---|---:|---:|---:|
| subfinder `-json -cs` + dnsx `-json -omit-raw` | 276,155 | 95,998 | 1× |
| subfinder text + dnsx text | 57,732 | 22,741 | 4.2× |
| **raijin-subs JSON (default)** | 14,398 | **4,500** | **21×** |
| raijin-subs `--pretty` | 20,323 | 5,892 | 16× |
| raijin-subs `--format table` | 655 | 241 | 398× |

In every scenario the raijin-subs JSON includes about 10 tokens for `target`, the path of the replayed fixture. A live run writes the domain there and adds about 18 tokens for `raw`.

**High and medium findings** (dangling CNAME, private IP, CNAME without an address on a claimable service) did not occur in these three public runs. They are covered by the synthetic fixture `testdata/sample.jsonl` and the unit tests, not by this benchmark.

## Nothing is lost

For each scenario, `bench/verify.py` checks the engines' output (`raw.jsonl`) against the raijin-subs output. A result is:

- each name subfinder found: it must be in the `locations` of a finding or group;
- each (name, record type, value) triple dnsx returned, for A, AAAA and CNAME, plus the name's DNS status: the name must be in the `locations` of a finding or group whose `status`, `cname`, `a` and `aaaa` equal the record's.

Results:

- Scenario 1: 510 names, 510 dnsx records (575 triples), **0 missing**.
- Scenario 2: 830 names, 830 dnsx records (1,263 triples), **0 missing**; 2 wildcard probes skipped.
- Scenario 3: 549 names, 549 dnsx records (1,587 triples), **0 missing**; 1 wildcard probe skipped.

What the JSON leaves out stays in `raw`, which raijin-subs saves to disk: the passive sources (or `--sources`), the root each name was found for, TTLs, resolvers, SOA records and timestamps.

## Reading the numbers

- **Against the engines' JSON**, the structured output an agent would parse, raijin-subs uses **17× to 27× fewer tokens** for the same names and records. Most of the JSON is dnsx repeating its resolvers, TTL, timestamp and the zone's SOA record on every line, and subfinder repeating the root and the sources.
- **Against the engines' text output**, the gap depends on the run:
  - noisy: **1.16× smaller** (5,567 → 4,810);
  - findings: **1.23× smaller** (20,999 → 17,063);
  - wildcard: **5.1× smaller** (22,741 → 4,500).

  When most names are different, the cost is the names themselves, and both outputs list every name once. raijin-subs writes each IP once per group instead of once per name and record type, which is where the wildcard run saves the most: dnsx's text has one line per record for each of the 506 wildcard names. In exchange the agent gets the status of the 498 or 700 names that do not resolve (dnsx's text has no line for them), the CNAME chain with its provider, the wildcard label, and the leads ranked first.
- **The output stays bounded.** On a run too big for `--max-bytes`, raijin-subs cuts the least important data first: names that do not resolve, then other group names, then groups, then extra names of low-ranked findings, then low-ranked findings. Every cut is counted in `omitted`, and `next` points to the raw file. The engines' output has no upper bound.

## How the default output got here

o200k tokens, on the same fixtures:

| Version | Scenario 1 | Scenario 2 | Scenario 3 | Lossless? |
|---|---:|---:|---:|---|
| `no-address` also on names behind a wildcard | 4,810 | 17,063 | 4,528 | yes |
| **no `no-address` behind a wildcard** (current) | **4,810** | **17,063** | **4,500** | **yes** |

Before the benchmark runs, two changes were made on a first live sample of the same domains: CNAMEs to CDNs and load balancers (CloudFront, Cloudflare, Akamai, Fastly, AWS ELB) stopped being `third-party` findings, since they front the owner's own origin (on gitlab.com this turned 13 low findings into groups), and the registered domain's own name stopped counting as an interesting word (`gitlab` under gitlab.com). In the first version 6 shopify.com names that answered with the wildcard CNAME but no address (a flaky query) were `no-address` findings; they are now part of the wildcard group.
