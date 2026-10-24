"""Checks that every subfinder and dnsx result is in a raijin-subs result.

The engine output is a JSONL file with subfinder lines, dnsx lines or both (the `raw` file raijin-subs
saves, or the two engines' outputs concatenated). Results are:

- each subfinder name: it must be in the locations of a finding or group;
- each (name, record type, value) triple from dnsx, for A, AAAA and CNAME, plus the name's DNS status:
  the name must be in the locations of a finding or group whose status, cname, a and aaaa equal the
  record's (NOERROR with no record is NODATA; no dnsx line for a name is NOANSWER, or UNCHECKED when the
  file has no dnsx line at all).

Wildcard probe names (raijin-wc-*) are not results and are skipped. Names outside the root domain
subfinder searched (its "input") count as out of scope, not missing.

usage: python verify.py <engine.jsonl> <raijin.json>
"""
import json, sys

raw, out = sys.argv[1], sys.argv[2]
o = json.load(open(out))


def norm(s):
    s = s.strip().lower().rstrip(".")
    return s[2:] if s.startswith("*.") else s


entries = {}
for kind in ("findings", "groups"):
    for x in o[kind]:
        answer = (x.get("status", ""), tuple(x.get("cname", [])), tuple(x.get("a", [])), tuple(x.get("aaaa", [])))
        for loc in x.get("locations", []):
            entries.setdefault(loc.split(" [", 1)[0], set()).add(answer)

names, roots, records = {}, set(), []
probes = 0
for line in open(raw, encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    if not line.startswith("{"):
        if "." in line and not any(c in line for c in ' \t[]{}"'):
            names.setdefault(norm(line), None)
        continue
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if not isinstance(e, dict) or not e.get("host"):
        continue
    if "status_code" in e:
        if norm(e["host"]).startswith("raijin-wc-"):
            probes += 1
            continue
        records.append(e)
    elif "resolver" not in e:
        names.setdefault(norm(e["host"]), e.get("input"))
        if e.get("input"):
            roots.add(norm(e["input"]))


def in_roots(n):
    return not roots or any(n == r or n.endswith("." + r) for r in roots)


def chain(cn):
    out = []
    for c in cn or []:
        c = norm(c)
        if c and (not out or out[-1] != c):
            out.append(c)
    return tuple(out)


miss, triples, oos = [], 0, 0
resolved_names = set()
for e in records:
    n = norm(e["host"])
    if not in_roots(n):
        oos += 1
        continue
    resolved_names.add(n)
    status = e["status_code"].upper()
    a, aaaa, cn = tuple(sorted(set(e.get("a") or []))), tuple(sorted(set(e.get("aaaa") or []))), chain(e.get("cname"))
    if status == "NOERROR":
        status = "" if (a or aaaa or cn) else "NODATA"
    want = (status, cn, a, aaaa)
    got = entries.get(n, set())
    ts = [("status", status or "NOERROR")] + [("a", v) for v in a] + [("aaaa", v) for v in aaaa] + [("cname", v) for v in cn]
    triples += len(ts)
    if want not in got:
        for t in ts:
            ok = any((t[0] == "status" and (s or "NOERROR") == t[1]) or (t[0] == "a" and t[1] in ga) or (t[0] == "aaaa" and t[1] in g6) or (t[0] == "cname" and t[1] in gc) for s, gc, ga, g6 in got)
            if not ok:
                miss.append((n,) + t)
        if not any(m[0] == n for m in miss):
            miss.append((n, "answer", want))

missing_names = 0
unresolved = "NOANSWER" if records else "UNCHECKED"
for n in names:
    if not in_roots(n):
        oos += 1
        continue
    if n not in entries:
        missing_names += 1
        miss.append((n, "name"))
    elif n not in resolved_names and (unresolved, (), (), ()) not in entries[n]:
        miss.append((n, "status", unresolved))

print(f"{len(names)} subfinder names, {len(records)} dnsx records ({triples} name/type/value triples), "
      f"{len(miss)} missing from output", f"({probes} wildcard probes skipped, {oos} out of scope)",
      "truncated" if o.get("budget") else "")
for m in miss[:5]:
    print("  MISSING", m)
sys.exit(1 if miss else 0)
