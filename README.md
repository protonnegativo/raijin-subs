# ⚡ Raijin Subs

[![CI](https://github.com/protonnegativo/raijin-subs/actions/workflows/ci.yml/badge.svg)](https://github.com/protonnegativo/raijin-subs/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/protonnegativo/raijin-subs)](https://github.com/protonnegativo/raijin-subs/releases/latest)
[![License: MIT](https://img.shields.io/github/license/protonnegativo/raijin-subs)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/protonnegativo/raijin-subs.svg)](https://pkg.go.dev/github.com/protonnegativo/raijin-subs)
[![Go Report Card](https://goreportcard.com/badge/github.com/protonnegativo/raijin-subs)](https://goreportcard.com/report/github.com/protonnegativo/raijin-subs)

**subfinder + dnsx for AI agents: every subdomain with its DNS answer, names that share an answer collapsed, dangling CNAMEs and internal IPs ranked first.**

`raijin-subs` is a tool of **Raijin**, an arsenal of offensive security tools built for AI agents. It runs [subfinder](https://github.com/projectdiscovery/subfinder) for passive enumeration and [dnsx](https://github.com/projectdiscovery/dnsx) to resolve every name, and returns the **Raijin Schema**: one compact JSON where names with the same answer share one entry, dangling CNAMEs, private IPs, third-party services and names like `staging` or `vpn` are ranked findings, wildcard DNS is detected and labelled, and anything it had to cut is counted.

## Why not just run subfinder and dnsx?

They are built for people and pipelines. An agent pays for every byte it reads. subfinder's JSON is one line per name with its sources. dnsx's JSON is one line per name, and every line repeats the resolvers, the TTL, the timestamp and the zone's SOA record, even for the hundreds of names that do not resolve. Their text output is shorter, but it is two lists the agent has to join, and dnsx's text leaves out every name that did not resolve.

Here are the same names, with the same records, read by an agent (tokens, `o200k_base`):

```
Noisy: hackerone.com, 510 names, 498 that do not resolve
  raijin-subs     ▊                       4,820 tokens
  engines text    ▉                       5,567 tokens
  engines JSON    ████████████████████  128,845 tokens

Findings: gitlab.com, 830 names, 29 findings, 602 NXDOMAIN
  raijin-subs     █▏                     17,073 tokens
  engines text    █▍                     20,999 tokens
  engines JSON    ████████████████████  294,874 tokens

Wildcard: shopify.com, 549 names, 506 behind *.shopify.com
  raijin-subs     █                       4,510 tokens
  engines text    ████▊                  22,741 tokens
  engines JSON    ████████████████████   95,998 tokens
```

raijin-subs reads **17× to 27×** fewer tokens than the engines' JSON (`subfinder -json -cs` plus `dnsx -json -omit-raw`). Each scenario's bars are drawn to scale against the JSON.

- **Nothing is lost.** Every name subfinder found is in the output, and every A, AAAA and CNAME record and DNS status dnsx returned is on it. `bench/verify.py` checked 1,889 names and 3,425 name/type/value triples in the three scenarios and none were missing.
- **The real leads come first.** A CNAME that ends in NXDOMAIN on a service where names can be claimed is high; a private IP in public DNS is medium. 500 names that do not resolve are one group that lists all 500.
- **Wildcards do not drown the run.** 506 names answered by `*.shopify.com` are one group, labelled with the wildcard, still listing every name.
- **Output is bounded.** On a huge run, `--max-bytes` cuts the least important data first (names that do not resolve) and counts every cut.
- **Details are one file away.** Both engines' full JSONL is saved to disk, and its path is in `raw`. It holds the sources, TTLs, resolvers and SOA records, costs no tokens until the agent opens it, and replays with `--input`.

Against the engines' text output (`subfinder -silent` and `dnsx -a -aaaa -cname -resp -silent`), the gap is small when most names are different: **1.2×** on the noisy and the findings runs. It is **5.0×** on the wildcard run. The text output also has no grouping, no ranking, no status for names that do not resolve, and no field names. Full method and numbers are in [BENCHMARK.md](BENCHMARK.md), and `bench/run.sh` reproduces them.

## Install

```bash
go install github.com/protonnegativo/raijin-subs/cmd/raijin-subs@latest
```

That installs the latest release.

You also need `subfinder` and `dnsx` on `PATH`, or pass `--subfinder <path>` and `--dnsx <path>`. Use dnsx 1.2.1 (`go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1`), not 1.3.x: see [Engine versions](#engine-versions).

**Versions.** Releases are tagged automatically on every change and every passing engine update. `raijin-subs --version` shows the release and the tested engine versions (`raijin-subs v0.1.3 (tested with dnsx 1.2.1, subfinder 2.6.7)`). `raijin-mcp update` updates every Raijin tool at once.

## Usage

```bash
raijin-subs --scope scope.txt                                        # enumerate every host the scope names
raijin-subs --scope scope.txt -d example.com
raijin-subs --scope scope.txt -l roots.txt --max-items 20
raijin-subs --scope scope.txt -d example.com --no-resolve --sources  # names and sources only, no DNS
raijin-subs --scope scope.txt --input raw.jsonl                      # replay a saved run, nothing is sent
raijin-subs --scope scope.txt --input subfinder.jsonl --input dnsx.jsonl
raijin-subs --scope scope.txt -d example.com --state run.json        # mark findings that are new since last run
raijin-subs ... -- -all -s crtsh,anubis                              # anything after -- goes to subfinder
```

`--scope` is required. One rule per line:

```
example.com
*.example.com
10.0.0.0/24
!admin.example.com
```

A root domain is enumerated when the scope allows it or its subdomains (`*.example.com` covers `example.com`). Roots outside the scope are dropped before subfinder runs, and names outside it are dropped before dnsx resolves them. Both are counted in `omitted.out_of_scope`.

With no `-d`, `-l` or `--input`, raijin-subs enumerates what the scope names: every domain, and the apex of every wildcard (`*.example.com` enumerates `example.com`), once, minus exclusions. IPs and ranges are not root domains, so they are skipped.

`--input` reads subfinder JSONL, subfinder's text output (one name per line), dnsx JSONL, or a file with all of them, like the `raw` file. A replay never runs an engine: names with no dnsx record are `NOANSWER` when the input has dnsx records, `UNCHECKED` when it has none.

**Passive only.** subfinder asks public passive sources (certificate logs, DNS datasets). dnsx asks the DNS resolvers. raijin-subs never sends HTTP requests or port probes to the names it finds. The wildcard check is one more DNS query per crowded parent, for a random name under it.

## Output

```json
{
  "schema_version": 1,
  "tool": "raijin-subs",
  "version": "0.1.0",
  "target": "bench/fixtures/noisy/raw.jsonl",
  "summary": "510 names, 12 resolve, 4 findings (4 low), 5 groups",
  "findings": [
    {
      "id": "third-party-b24431fc",
      "title": "CNAME to GitHub Pages",
      "severity": "low",
      "tags": ["third-party"],
      "cname": ["hacker0x01.github.io"],
      "a": ["185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153"],
      "aaaa": ["2606:50c0:8000::153", "2606:50c0:8001::153", "2606:50c0:8002::153", "2606:50c0:8003::153"],
      "provider": "GitHub Pages",
      "locations": ["mta-sts.forwarding.hackerone.com", "mta-sts.hackerone.com", "mta-sts.managed.hackerone.com"]
    },
    {
      "id": "no-address-247aba4c",
      "title": "CNAME to SendGrid without an address",
      "severity": "low",
      "tags": ["no-address", "third-party"],
      "cname": ["u18966564.wl065.sendgrid.net"],
      "provider": "SendGrid",
      "locations": ["gsemail.hackerone.com"]
    }
  ],
  "groups": [
    {
      "id": "a-fdedb065",
      "a": ["104.18.36.214", "172.64.151.42"],
      "aaaa": ["2a06:98c1:3109::ac40:972a", "2a06:98c1:310c::6812:24d6"],
      "locations": ["api.hackerone.com", "docs.hackerone.com", "www.hackerone.com"]
    },
    {
      "id": "nodata-029dc686",
      "status": "NODATA",
      "locations": ["0qh.hackerone.com", "1.229.hackerone.com", "1.hackerone.com", "... 495 more"]
    }
  ]
}
```

That is the real noisy run from the benchmark (`--input` on the saved subfinder and dnsx output for hackerone.com), pretty-printed here. Three things are shortened: 2 of the 4 findings and 3 of the 5 groups are left out, and the `NODATA` group lists all 498 names in the real output (495 are replaced by `"... 495 more"` here). The tool writes it as one line.

**Nothing the engines found is dropped silently.** Every name is in exactly one finding or group per answer it has. Only exact repeats collapse, and they are counted in `omitted.duplicates`.

What the reducer does:

- **One entry per distinct answer.** Two names have the same answer when the DNS status, the CNAME chain, the A records and the AAAA records are all equal (records sorted, so the order a resolver returns them in does not matter). Each entry lists every name that has it, so 50 names behind the same two load balancer IPs are one group.
- **The answer** is written once per entry:
  - `status` is left out for NOERROR with records. Otherwise it is dnsx's status (`NXDOMAIN`, `SERVFAIL`, `REFUSED`...), `NODATA` (NOERROR with no A, AAAA or CNAME), `NOANSWER` (dnsx returned nothing for the name) or `UNCHECKED` (dnsx did not run).
  - `cname` is the chain in the order the resolver returned it.
  - `provider` is the third-party service the chain points into, when it is a known one (about 70 suffixes: GitHub Pages, S3, Heroku, Azure, CloudFront, Fastly, Zendesk...).
- **Wildcard DNS.** When at least 5 names under one parent have the same answer, raijin-subs resolves one random name under that parent (`raijin-wc-<hex>.parent`). If it gets the same answer (the same CNAME chain, or the same IPs when there is no CNAME), the names with that answer are labelled `"wildcard": "*.parent"`. They stay listed, but the `no-address` and `name` rules are off for them. The probe answers are saved in `raw`, so a replay makes the same decision; they are not results.
- **Findings** are the answers that match a rule. A finding takes the highest severity of its tags:

  | Tag | Severity | Rule |
  |---|---|---|
  | `dangling` | high on a claimable service, medium otherwise | The name has a CNAME and the chain ends in NXDOMAIN. Claimable services (GitHub Pages, S3, Heroku, Azure App Service, Shopify, Statuspage and others from the public can-i-take-over-xyz list) let anyone register an unclaimed name. It is a takeover candidate, not a verified takeover. |
  | `no-address` | medium on a claimable service, low otherwise; `heuristic` | The name has a CNAME but no A or AAAA record, and is not behind a wildcard. Often a mail or DKIM record, sometimes a removed resource. |
  | `private-ip` | medium | An A or AAAA record is private (RFC 1918, RFC 4193), loopback, link-local, unspecified or CGNAT (100.64.0.0/10). |
  | `third-party` | low | The CNAME chain points into a known service that hosts content. CDNs and load balancers in front of the owner's origin (CloudFront, Cloudflare, Akamai, Fastly, AWS ELB...) set `provider` but are not a finding by themselves. |
  | `name` | low, `heuristic` | A label says dev, staging, test, uat, admin, internal, vpn, sso, jenkins, gitlab, grafana, registry, backup, db and similar, the name has an address, and it is not behind a wildcard. The name of the registered domain itself is never a hint (`gitlab` under gitlab.com). |

  A finding whose tags are all `no-address` or `name` has `confidence: heuristic`. Interesting names are split out of the group they would share with other names; the rest of the group stays complete.
- **Groups** are the answers that match no rule: names behind the same IPs or CDN, and names that do not resolve.
- **Ranking:** findings by severity, then confidence (matched before heuristic), then the number of names, then `id`. Groups that resolve come before groups that do not, then by the number of names, then `id`. The same input always gives the same order.
- **`id`** is the first tag (or the status, `wildcard`, `cname` or `a` for a group) and a short hash of the answer, so the same answer has the same `id` in the next run. A CDN that answers with other IPs next time gets a new `id`.
- **`raw`** is subfinder's and dnsx's full JSONL, saved to one file. It holds the passive sources, TTLs, resolvers, SOA records and timestamps, reading it costs no tokens until the agent opens it, and `--input` replays it. `--raw <file>` picks the path.
- **Sources** cost about one token per name per source, so they are off by default. `--sources` writes them in each location: `dev.example.com [crtsh, hackertarget]`.
- **Budget:** `--max-bytes` (64,000 by default, about 2,000 names; higher than the other Raijin tools because a subdomain list is long by nature) keeps the output bounded on huge runs. It cuts in this order until the JSON fits:
  1. group names, starting with the groups that do not resolve;
  2. groups;
  3. the names of the lowest-ranked findings, each keeping one name plus its `count`;
  4. the lowest-ranked findings.

  Every cut is counted in `omitted`, `budget.truncated` is set, and `next` points to the raw file. `--max-items` caps the number of findings (0, the default, keeps all).
- **Errors** say what to try next. If subfinder is missing, nothing runs and the exit code is 2. If dnsx is missing, every name is still listed as `UNCHECKED`, with the hint in `errors`, and the exit code is 2.
- **`schema_version`** is the first field of the JSON (currently `1`). It changes only when a field is removed or changes meaning.
- **Invalid scope.** A scope file with a bad line (a port, a CIDR with host bits set, no include rules...) stops the run before any engine starts. `errors` has one entry per bad line with `kind: "scope"`, and its `hint` says the line number, the reason and the fix.
- **Exit codes.** `0` ok. `2` structured error with the JSON on stdout (`kind: "scope"`, `missing_engine`), so an agent can tell them apart by `kind`. `1` wrong usage (unknown flag, missing `--scope`, no root domain in scope).

Fields an agent can rebuild are left out to save tokens:

- `status` is left out for NOERROR with records; `cname`, `a`, `aaaa`, `provider` and `wildcard` when there are none.
- `count` appears only when the budget cut `locations`.
- `confidence` appears only when it is not `matched`.
- `omitted`, `errors` and `next` appear only when they are not empty.
- `budget` appears only when something was cut.

The JSON is compact (one line) by default because indentation costs 26% to 31% more tokens in the benchmark; `--pretty` indents it (the example above is pretty-printed, with short arrays kept on one line). `--format table` prints a short human view of the same result; it lists finding names but only counts group names.

The Raijin banner is **off by default**, so normal runs stay small. `--banner` prints it to **stderr** (never stdout, so the JSON is untouched), with the version taken from the binary. Colors are disabled when `NO_COLOR` is set or stderr is not a terminal.

## Flags

| Flag | Default | |
|---|---|---|
| `--scope` | (required) | scope file |
| `-d` / `-l` / `--input` | every host the scope names | one root domain (repeatable) / root domain file / existing subfinder and dnsx output (repeatable) |
| `--no-resolve` | false | only enumerate; do not run dnsx |
| `--sources` | false | write each name's passive sources in its location |
| `--timeout`, `--max-time` | | subfinder `-timeout` (seconds per source) / `-max-time` (minutes) |
| `--rate`, `--threads`, `--resolvers` | | dnsx `-rl` / `-t` / `-r` |
| `--max-items` | 0 | max findings (0 keeps all) |
| `--max-bytes` | 64000 | max JSON size; cuts are counted in `omitted` |
| `--raw` | temp file | where to save the engines' full JSONL |
| `--state` | | state file for new-since-last-run |
| `--format` | json | `json` or `table` |
| `--pretty` | false | indent the JSON |
| `--subfinder`, `--dnsx` | subfinder, dnsx | paths to the binaries |
| `--banner` | false | print the banner to stderr |

## Engine versions

The tested subfinder and dnsx versions are in [`engines.json`](engines.json), built into the binary. When the installed engine is another major version or older than the tested one, raijin-subs adds an `engine_version` error with the install command; when an engine's output lines lack the fields it reads (subfinder `host`, dnsx `host` and `status_code`), it adds an `engine_format` error and counts the lines in `omitted.unparsed`. Neither stops the run. A weekly GitHub Actions job runs the benchmark with the latest engines and commits the bump to `engines.json` and tags a release when it passes, or an issue when it breaks. Before the benchmark it resolves a name that cannot exist (`raijin-drift-<random>.example`) with the same dnsx arguments and requires an `NXDOMAIN` line.

**dnsx 1.3.x drops NXDOMAIN names from its JSON.** Since dnsx v1.3.0 (projectdiscovery/dnsx#988), `-json` writes no line for a name without a record of the requested type, even with `-rcode`, so names that no longer exist lose their status (fix proposed in [projectdiscovery/dnsx#1091](https://github.com/projectdiscovery/dnsx/pull/1091)). raijin-subs pins dnsx 1.2.1 in `engines.json` and warns: dnsx versions in the known-bad range (`KnownBad` in [`engines.go`](engines.go), `>=1.3.0` until a fixed release exists) get an `engine_version` error even though they are newer, and when dnsx writes no line for some of the names it was given (wildcard probes included), those names are still listed (`NOANSWER`) and an `engine_format` error says how many. Install the tested version with `go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1` or `raijin-mcp update --pinned`.

## Development

```bash
go test ./...
go vet ./...
```

The only Go dependency is [raijin-core](https://github.com/protonnegativo/raijin-core) (scope, schema envelope, state), shared by the Raijin tools. subfinder runs as a subprocess with `-json -cs -silent -nc -duc`, and dnsx with `-a -aaaa -resp -json -silent -nc -duc -omit-raw -rcode noerror,formerr,servfail,nxdomain,notimp,refused`, so the binary stays small and the engines can be updated on their own. `-rcode` with every status makes dnsx write a line for the names that do not resolve too. There is no `-cname`, on purpose: the A and AAAA answers already carry the chain, which dnsx writes in `cname`, and with `-cname` dnsx v1.2.1 also sends a CNAME query whose NOERROR replaces the A query's NXDOMAIN, so a dangling CNAME would never be reported as `dangling`. The CLI tests run the live path offline with small fake engines; `testdata/sample.jsonl` is a synthetic run that hits every rule.

## Responsible use

Only enumerate domains you are authorized to test. raijin-subs is passive, but the scope still applies.
