# PAUSE — dig-rpc CI failure (#200)

## What was paused
Finalizing #200 (dig-rpc rebuild). The crate is complete, tested, and pushed;
the blocker is CI, not the code.

## Failing run
- Repo: DIG-Network/dig-rpc
- Run: 28612036645 (CI) — both jobs failed at step "Checkout dig-rpc-types sibling".
- Error: `Not Found - https://docs.github.com/rest/repos/repos#get-a-repository`
  — the default `GITHUB_TOKEN` cannot check out the PRIVATE sibling repo
  `DIG-Network/dig-rpc-types` (dig-rpc path-depends on `../dig-rpc-types`, so CI
  must have it present).

## Fix applied
`.github/workflows/ci.yml` + `publish.yml`: the sibling checkout now uses
`token: ${{ secrets.GH_ACCESS_TOKEN || github.token }}` — the same org secret the
DIG publish workflows already use for cross-repo access.

## Resume condition
CI run on the fix commit is GREEN. If `GH_ACCESS_TOKEN` is NOT configured with
read access to dig-rpc-types, escalate to the orchestrator: either (a) grant the
token repo read, or (b) add dig-rpc-types as a git dependency with a deploy key,
or (c) the crates are consumed as submodules and CI should check out via the
superproject. Both crates' code is green locally regardless.
