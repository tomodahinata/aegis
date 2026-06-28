#!/usr/bin/env python3
"""Clone (shallow, sparse: supabase schema only) + Aegis-scan each discovered repo,
then record per-repo RLS metrics to data/rows.csv.

Denominator (ground truth, grep on the checked-out SQL): repos that actually ship
RLS (>=1 CREATE POLICY). Numerator (scanner): repos with >=1
`rls/policy-not-owner-scoped` finding — a policy that proves a session exists but
does NOT scope rows to their owner. Static, public-source only; no live probing.

Usage:  python3 run.py [LIMIT]
The Aegis CLI is resolved repo-relative; override with AEGIS_CLI=/path/to/main.js.
Build it first:  pnpm --filter @aegiskit/cli build
"""
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
# repo root is two levels up: <root>/research/rls-precision-study/run.py
CLI = os.environ.get("AEGIS_CLI", str(BASE.parents[1] / "packages/cli/dist/main.js"))
DATA = BASE / "data"
CLONES = DATA / "clones"
RESULTS = DATA / "results"
CLONES.mkdir(parents=True, exist_ok=True)
RESULTS.mkdir(parents=True, exist_ok=True)

LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else 10**9
RULE_KEYS = [
    "rls/policy-not-owner-scoped",
    "rls/table-without-rls",
    "rls/anon-writable",
    "rls/anon-table-grant",
    "rls/write-policy-without-check",
    "rls/permissive-write-policy",
]
SQL_AUTHORITY = re.compile(r"/supabase/(migrations|schemas)/")


def run(cmd, timeout):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


repos = [l.strip() for l in (DATA / "repos.txt").read_text().splitlines() if l.strip()]
rows_path = DATA / "rows.csv"
total = min(LIMIT, len(repos))

with open(rows_path, "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(
        ["repo", "sql_files", "create_policy", "enable_rls"]
        + [k.split("/")[1] for k in RULE_KEYS]
        + ["status"]
    )
    for i, repo in enumerate(repos):
        if i >= LIMIT:
            break
        key = repo.replace("/", "__")
        d = CLONES / key
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)

        r = run(
            ["git", "clone", "--depth", "1", "--filter=blob:none", "--no-checkout",
             f"https://github.com/{repo}.git", str(d)],
            90,
        )
        if r is None or r.returncode != 0:
            w.writerow([repo, 0, 0, 0] + [0] * len(RULE_KEYS) + ["clone_fail"]); fh.flush()
            print(f"[{i+1}/{total}] {repo} clone_fail", flush=True)
            continue

        run(["git", "-C", str(d), "sparse-checkout", "set", "--no-cone",
             "**/supabase/migrations/**", "**/supabase/schemas/**"], 30)
        run(["git", "-C", str(d), "checkout"], 60)

        sqls = [p for p in d.rglob("*.sql") if SQL_AUTHORITY.search(str(p).replace("\\", "/"))]
        if not sqls:
            w.writerow([repo, 0, 0, 0] + [0] * len(RULE_KEYS) + ["no_sql"]); fh.flush()
            shutil.rmtree(d, ignore_errors=True)
            print(f"[{i+1}/{total}] {repo} no_sql", flush=True)
            continue

        text = "\n".join(p.read_text(errors="ignore") for p in sqls)
        cp = len(re.findall(r"create\s+policy", text, re.I))
        er = len(re.findall(r"enable\s+row\s+level\s+security", text, re.I))

        # Write scanner stdout as raw bytes to disk (mirrors a shell redirect). An earlier in-memory
        # text=True capture corrupted large UTF-8 JSON and silently dropped the biggest, most-finding-rich
        # repos — a serious upward-survivorship bias. Reading back from the file is the proven-correct path.
        rjson = RESULTS / f"{key}.json"
        counts = {k: 0 for k in RULE_KEYS}
        status = "ok"
        try:
            with open(rjson, "wb") as out:
                subprocess.run(
                    ["node", CLI, "scan", str(d), "--format", "json"],
                    stdout=out, stderr=subprocess.DEVNULL, timeout=150,
                )
            raw = rjson.read_text(encoding="utf-8", errors="ignore")
            if not raw.strip():
                status = "scan_err"
            else:
                data = json.loads(raw)
                for f in data.get("findings", []):
                    if f["ruleId"] in counts:
                        counts[f["ruleId"]] += 1
        except subprocess.TimeoutExpired:
            status = "scan_timeout"
        except Exception:
            status = "scan_err"

        w.writerow([repo, len(sqls), cp, er] + [counts[k] for k in RULE_KEYS] + [status])
        fh.flush()
        shutil.rmtree(d, ignore_errors=True)
        print(
            f"[{i+1}/{total}] {repo} sql={len(sqls)} pol={cp} "
            f"not_owner={counts['rls/policy-not-owner-scoped']} {status}",
            flush=True,
        )

print("done", flush=True)
