#!/usr/bin/env bash
# Discover public GitHub repos that ship Supabase RLS policies in the authoritative
# schema dir (supabase/migrations | supabase/schemas) — the only place the Aegis
# scanner treats SQL as source-of-truth. Static, public-source discovery only.
# Requires an authenticated `gh` CLI (code search). See README.md.
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p data
: > data/repos.raw.txt
: > data/discover.err

# Diversified queries so we collect many UNIQUE repos (code search caps at 1000
# results/query; many files map to one repo, so we vary the predicate keywords).
queries=(
  '"create policy" path:supabase/migrations'
  '"enable row level security" path:supabase/migrations'
  '"auth.uid()" path:supabase/migrations'
  '"for select using" path:supabase/migrations'
  '"to authenticated" path:supabase/migrations'
  '"using (true)" path:supabase/migrations'
  '"create policy" path:supabase/schemas'
)
PAGES="${PAGES:-5}"   # 100/page * 5 = up to 500 results/query

for q in "${queries[@]}"; do
  for p in $(seq 1 "$PAGES"); do
    gh api -X GET search/code \
      -f q="$q" -f per_page=100 -f page="$p" \
      --jq '.items[].repository | select(.fork == false) | .full_name' >> data/repos.raw.txt 2>>data/discover.err || true
    sleep 7   # code_search budget is 10 req/min; stay under it
  done
done

sort -u data/repos.raw.txt > data/repos.txt
echo "discovered $(wc -l < data/repos.txt | tr -d ' ') unique repos"
