#!/usr/bin/env python3
"""Aggregate data/rows.csv into headline rates + a methodology-aware data/summary.md.

The authoritative narrative (the precision-hardening story, 19.3% -> 8.1%) lives in README.md;
this regenerates a transient, data-derived summary under data/ (gitignored) on each run.
"""
import csv
from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
rows = list(csv.DictReader(open(DATA / "rows.csv")))


def i(r, k):
    try:
        return int(r[k])
    except (ValueError, KeyError):
        return 0


# The code-search candidate pool (discover.sh -> repos.txt) is a wider funnel than
# the repos we actually scanned (rows.csv); report both so the headline funnel
# (candidates -> scanned -> ship-RLS) is unambiguous and matches the write-up.
repos_txt = DATA / "repos.txt"
candidates = (
    sum(1 for line in repos_txt.read_text().splitlines() if line.strip())
    if repos_txt.exists()
    else None
)
scanned_attempted = len(rows)
status = {}
for r in rows:
    status[r["status"]] = status.get(r["status"], 0) + 1

# CSV column names come from `ruleId.split("/")[1]` in run.py, so they are hyphenated.
NOT_OWNER, TABLE_NO_RLS, ANON_WRITABLE = (
    "policy-not-owner-scoped", "table-without-rls", "anon-writable",
)
scanned = [r for r in rows if r["status"] == "ok"]
# "Has RLS" = ships at least one CREATE POLICY in the authoritative schema dir.
with_rls = [r for r in scanned if i(r, "create_policy") > 0]
not_owner_repos = [r for r in with_rls if i(r, NOT_OWNER) > 0]
table_no_rls_repos = [r for r in scanned if i(r, TABLE_NO_RLS) > 0]
anon_writable_repos = [r for r in scanned if i(r, ANON_WRITABLE) > 0]

total_policies = sum(i(r, "create_policy") for r in with_rls)
total_not_owner = sum(i(r, NOT_OWNER) for r in with_rls)


def pct(n, d):
    return f"{(100*n/d):.1f}%" if d else "n/a"


L = []
L.append("# Supabase RLS owner-scope study — results\n")
L.append("> Static analysis of public GitHub repositories with the Aegis scanner. "
         "Public source only; no live probing of any deployed app.\n")
L.append("## Headline\n")
if candidates is not None:
    L.append(f"- Code-search candidates (unique public repos): **{candidates}**")
L.append(f"- Repos scanned (attempted): **{scanned_attempted}**")
L.append(f"- Successfully scanned: **{len(scanned)}**  (" +
         ", ".join(f"{k}={v}" for k, v in sorted(status.items())) + ")")
L.append(f"- Of those, ship RLS (>=1 CREATE POLICY): **{len(with_rls)}**")
L.append("")
L.append(f"### Repos with RLS that have >=1 policy NOT scoped to the row owner: "
         f"**{len(not_owner_repos)} / {len(with_rls)} = {pct(len(not_owner_repos), len(with_rls))}**")
L.append("")
L.append(f"- Per-policy: **{total_not_owner} / {total_policies} = "
         f"{pct(total_not_owner, total_policies)}** of all RLS policies authenticate "
         f"but do not authorize per-row.")
L.append("")
L.append("### Secondary findings (full picture)\n")
L.append(f"- Repos with a table that has RLS disabled entirely "
         f"(`rls/table-without-rls`): **{len(table_no_rls_repos)} / {len(scanned)} = "
         f"{pct(len(table_no_rls_repos), len(scanned))}**")
L.append(f"- Repos with anon-writable exposure (`rls/anon-writable`): "
         f"**{len(anon_writable_repos)} / {len(scanned)} = "
         f"{pct(len(anon_writable_repos), len(scanned))}**")
L.append("")
L.append("See README.md for the full precision-hardening methodology and honest caveats.")

(DATA / "summary.md").write_text("\n".join(L) + "\n")
print("\n".join(L))
