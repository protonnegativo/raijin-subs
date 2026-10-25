#!/usr/bin/env bash
# Reproducible token benchmark: subfinder + dnsx output vs raijin-subs output on the same names.
#
# usage: bench/run.sh [workdir]
#        LIVE=1 bench/run.sh [workdir]   re-enumerate the domains and refresh bench/fixtures first
# needs: go, python3 with tiktoken (pip install tiktoken); LIVE=1 also needs subfinder, dnsx and network
# optional: ANTHROPIC_API_KEY + pip install anthropic for exact Claude token counts
# env: PY=<python with tiktoken>, SUBFINDER=<path>, DNSX=<path>
#
# Safety: passive only. subfinder asks public passive sources (certificate logs, DNS datasets) and dnsx
# asks public DNS resolvers. Nothing is sent to the discovered hosts: no HTTP, no port probes.
set -euo pipefail

W=${1:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
PY=${PY:-python3}
SUBFINDER=${SUBFINDER:-subfinder}
DNSX=${DNSX:-dnsx}
mkdir -p "$W"
echo "workdir: $W"

# Scenarios: public root domains of companies with public bug bounty programs, which publish many
# subdomains and are common public examples.
#   noisy:    hackerone.com, mostly names from a passive dataset that no longer resolve
#   findings: gitlab.com, CNAMEs to third-party services and names like staging, grafana, registry
#   wildcard: shopify.com, hundreds of names answered by one wildcard CNAME
scenarios=(noisy=hackerone.com findings=gitlab.com wildcard=shopify.com)

(cd "$ROOT" && go build -o "$W/raijin-subs" ./cmd/raijin-subs)

for s in "${scenarios[@]}"; do
  name=${s%%=*}; domain=${s#*=}
  f=$HERE/fixtures/$name
  printf '%s\n*.%s\n' "$domain" "$domain" > "$W/$name.scope"
  if [ "${LIVE:-}" = 1 ]; then
    mkdir -p "$f"
    # raijin-subs runs subfinder (-json -cs) and dnsx (-json -omit-raw), plus one wildcard probe per
    # crowded parent, and saves all their JSONL as raw: that file is the fixture.
    "$W/raijin-subs" --subfinder "$SUBFINDER" --dnsx "$DNSX" --scope "$W/$name.scope" -d "$domain" \
      --timeout 20 --max-time 3 --raw "$f/raw.jsonl" > "$W/$name.live.json"
    # dnsx as an agent would run it, in text, on the same names.
    python3 -c 'import json,sys
for l in open(sys.argv[1]):
    l=l.strip()
    if l.startswith("{"):
        try: e=json.loads(l)
        except ValueError: continue
        if "host" in e and "status_code" not in e and "resolver" not in e: print(e["host"])' "$f/raw.jsonl" | sort -u > "$W/$name.names"
    "$DNSX" -l "$W/$name.names" -a -aaaa -cname -resp -silent -nc -duc < /dev/null > "$f/dnsx.txt"
  fi
done

scenario() {
  local name=$1
  local f=$HERE/fixtures/$name o=$W/$name
  mkdir -p "$o"
  # Engine JSON: the subfinder and dnsx lines of raw, without the wildcard probes (they are raijin-subs's).
  grep -v '"host":"raijin-wc-' "$f/raw.jsonl" > "$o/engines.jsonl" || true
  # Engine text: subfinder -silent prints one name per line (the same names as in raw), then dnsx text.
  python3 -c 'import json,sys
for l in open(sys.argv[1]):
    l=l.strip()
    if l.startswith("{"):
        try: e=json.loads(l)
        except ValueError: continue
        if "host" in e and "status_code" not in e and "resolver" not in e: print(e["host"])' "$f/raw.jsonl" > "$o/subfinder.txt"
  # raijin-subs replays raw with --input, so every row sees the same names and records.
  (cd "$ROOT" && "$W/raijin-subs" --scope "$W/$name.scope" --input "bench/fixtures/$name/raw.jsonl") > "$o/raijin.json"
  (cd "$ROOT" && "$W/raijin-subs" --scope "$W/$name.scope" --input "bench/fixtures/$name/raw.jsonl" --pretty) > "$o/raijin_pretty.json"
  (cd "$ROOT" && "$W/raijin-subs" --scope "$W/$name.scope" --input "bench/fixtures/$name/raw.jsonl" --format table) > "$o/raijin_table.txt"
  echo; echo "## $name: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["summary"])' "$o/raijin.json")"; echo
  # Verify the unbounded output: a run that outgrows --max-bytes cuts on purpose (and counts it in
  # omitted), and passive sources can return far more names than when the fixtures were recorded.
  (cd "$ROOT" && "$W/raijin-subs" --scope "$W/$name.scope" --input "bench/fixtures/$name/raw.jsonl" --max-bytes 0) > "$o/raijin_full.json"
  python3 "$HERE/verify.py" "$f/raw.jsonl" "$o/raijin_full.json"
  "$PY" "$HERE/count_tokens.py" \
    "subfinder -json -cs + dnsx -json -omit-raw=$o/engines.jsonl" \
    "subfinder text + dnsx text=$o/subfinder.txt+$f/dnsx.txt" \
    "raijin-subs JSON (default)=$o/raijin.json" \
    "raijin-subs --pretty=$o/raijin_pretty.json" \
    "raijin-subs --format table=$o/raijin_table.txt"
}

for s in "${scenarios[@]}"; do scenario "${s%%=*}"; done
