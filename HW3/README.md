# sca — Software Supply Chain Security Analyzer

CE 879 — Homework 3. A Python tool that takes a **GitHub repository URL**,
evaluates the project's security posture, identifies supply-chain risks, and
produces actionable recommendations.

## What it does

| # | Stage | Details |
|---|-------|---------|
| 1 | **Dependency extraction** | Direct deps from manifests (`requirements*.txt`, `pyproject.toml`, `setup.py/cfg`, `Pipfile`, `package.json`, `pom.xml`, `build.gradle`, `go.mod`, `Cargo.toml`, `composer.json`); transitive deps from lockfiles (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `composer.lock`, `Gemfile.lock`), from `go.mod`'s `// indirect` module graph, or, when no lockfile exists, resolved online via the deps.dev API (PyPI fallback: recursive `requires_dist` resolution). |
| 2 | **SBOM generation** | CycloneDX 1.5 JSON with purl identifiers, license info, dependency graph, direct/transitive marking. |
| 3 | **Vulnerability analysis** | OSV.dev batch queries per resolved package version. For each vulnerability: package + vulnerable version, CVE id (when assigned) + OSV/GHSA id, severity (CVSS v3.1 base score computed from the vector, GHSA label fallback), description, fixed versions / mitigation. |
| 4 | **Dependency health** | Registry metadata per package (see *Health metrics* below). |
| 5 | **License analysis** | Project license (GitHub API → manifest declaration → LICENSE file content heuristics); dependency licenses from registry metadata; missing/unspecified licenses; restrictive (copyleft) and unusual licenses; incompatibility detection (strong copyleft vs permissive host, Apache-2.0 vs GPL-2.0-only, AGPL network clause). |
| 6 | **Secret detection** | Scans **every blob in the full git history** (`rev-list --objects --all` → `cat-file --batch` streaming) with ~20 token-format patterns (AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic, npm, PyPI, SendGrid, Telegram, Twilio, private keys, JWTs, credentials in URLs) plus keyword+entropy generics. Each finding reports: secret type, file location + line, introducing commit (author, date), and current status (ACTIVE in HEAD vs historical), with placeholder/test-value heuristics. |
| 7 | **Docker security** | All Dockerfiles: `latest`/untagged/undigested base images, missing `USER` / explicit root (multi-stage aware), `ADD` of URLs, hardcoded secrets in `ENV/ARG`, `curl \| sh`, disabled TLS verification, SSH exposure, missing `HEALTHCHECK`. |
| 8 | **CI/CD security** | GitHub Actions (+ basic GitLab CI): actions not pinned to a commit SHA (branch refs like `@main` worse than tags), `pull_request_target` (critical when combined with PR-head checkout), script injection via attacker-controlled `${{ github.event.* }}` expressions in `run:`/`github-script` bodies, missing GITHUB_TOKEN `permissions`, `curl \| bash`, hardcoded credentials, self-hosted runners, floating Docker images. |
| 9 | **Risk assessment & recommendations** | Weighted score → LOW/MEDIUM/HIGH/CRITICAL with per-category breakdown, written reasoning, and ≥1 tailored recommendation per discovered risk (exact upgrade versions, exact files/commits). |
| ★ | **Bonus: LLM executive report** | `--llm-summary` sends the condensed structured output to an LLM via OpenRouter (default `anthropic/claude-sonnet-4.5`; direct Anthropic API as fallback) and writes `executive_summary.md` (posture summary, top risks, prioritized actions). |

## Installation

```bash
# Python 3.11+ and git are required
cd supply-chain-analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# analyze a repository (clones with full history, runs all stages)
python3 -m sca https://github.com/OWNER/REPO

# useful options
python3 -m sca https://github.com/OWNER/REPO \
    -o results            # output directory (default ./output/<repo>)
    --skip-secrets        # skip the git-history secret scan
    --skip-health         # skip per-dependency health metadata
    --local-path DIR      # reuse an existing clone instead of cloning
    --keep-clone          # keep the temporary clone
    --llm-summary         # bonus LLM executive report (see below)
    -v                    # verbose logging
```

Optional environment variables:

- `GITHUB_TOKEN` — raises the GitHub API rate limit for repository metadata
  (the tool works without it).
- `OPENROUTER_API_KEY` — enables `--llm-summary` via OpenRouter (no extra
  package needed). `OPENROUTER_MODEL` overrides the default model
  (`anthropic/claude-sonnet-4.5`).
- `ANTHROPIC_API_KEY` + `pip install anthropic` — alternative provider for
  `--llm-summary` (used when no OpenRouter key is set).

### Outputs (`output/<repo>/`)

| File | Content |
|------|---------|
| `sbom.cyclonedx.json` | CycloneDX 1.5 SBOM |
| `report.json` | full machine-readable results of every stage |
| `report.md` | human-readable report (risk level, reasoning, all findings, recommendations) |
| `executive_summary.md` | (with `--llm-summary`) LLM-generated executive report |

A colored summary is also printed to the console.

## Documented criteria

### Health metrics (§3.4)

Per dependency, from its registry (PyPI / npm / crates.io / Packagist /
RubyGems / deps.dev):

- **M1** days since the latest release
- **M2** release cadence — releases in the last 365 days
- **M3** total release count (maturity)
- **M4** deprecation signals — npm `deprecated`, Packagist `abandoned`,
  PyPI *Development Status :: 7 – Inactive*, latest release yanked
- **M5** version lag of pinned direct dependencies vs the latest release

Classification: `DEPRECATED` (registry flag) → `ABANDONED` (M1 > 3 years) →
`STALE` (18–36 months) → `AGING` (6–18 months and M2 < 2) → `HEALTHY`;
`UNKNOWN` when no registry data exists (also flagged as a potential
dependency-confusion risk).

### Risk model (§5.1)

Severity weights: CRITICAL 10, HIGH 6, MEDIUM 3, LOW 1, INFO 0.
Category sub-scores (capped so one noisy category cannot saturate):

| Category | Scoring | Cap |
|---|---|---|
| Vulnerabilities | Σ severity weights | 40 |
| Secrets | active real 12 · historical real 6 · placeholder 0.1 (≤2 total) | 40 |
| CI/CD | Σ severity weights | 20 |
| Docker | Σ severity weights | 15 |
| Licenses | incompatibility 5 · strong copyleft 3 · weak copyleft 0.5 · missing 1 | 15 |
| Health | deprecated 4 · not-on-registry 3 · abandoned 1.5 · yanked 2 · stale 0.25 | 15 |

Repeated findings of the same rule count 100% once, then 50% (N instances of
one issue ≈ one process problem, not N independent risks).

**Bands:** `<10` LOW · `<25` MEDIUM · `<50` HIGH · `≥50` CRITICAL.
**Floors:** an ACTIVE secret, a CRITICAL vulnerability, or a CRITICAL CI/CD
finding each force at least HIGH.

## Architecture

```
sca/
├── cli.py           orchestration + argument parsing
├── repo.py          clone (full history) + GitHub metadata
├── dependencies.py  manifest & lockfile parsers (8 ecosystems)
├── registry.py      PyPI/npm/crates/Packagist/RubyGems/deps.dev clients,
│                    version resolution, online transitive resolution
├── sbom.py          CycloneDX 1.5 generator
├── vulns.py         OSV.dev scanner        ├── cvss.py  CVSS v3 calculator
├── health.py        health metrics         ├── licenses.py license analysis
├── secrets.py       git-history secret scanner
├── docker.py        Dockerfile checks      ├── cicd.py  workflow checks
├── risk.py          scoring + recommendation engine
├── report.py        console / Markdown / JSON output
└── llm.py           bonus LLM executive summary
```

External services: **OSV.dev** (vulnerabilities), **PyPI / npm / crates.io /
Packagist / RubyGems** registries (metadata), **deps.dev** (transitive
resolution, Maven/Go metadata), **GitHub API** (repo metadata; optional),
**OpenRouter / Anthropic API** (bonus only). All network access degrades gracefully —
offline the tool still performs extraction, SBOM, secrets, Docker and CI/CD
analysis and reports the reduced coverage as warnings.

## Robustness notes

- Not hardcoded to any project: ecosystems and files are auto-discovered.
- Every parser is wrapped; a malformed file becomes a warning, not a crash.
- Missing data (no manifests, no Dockerfile, no CI, no license) is reported
  explicitly and handled by every downstream stage.
- Secret scan caps blob size (400 KB) and findings (300) to stay usable on
  huge histories; binary blobs and asset extensions are skipped.
