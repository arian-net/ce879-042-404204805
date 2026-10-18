# Supply Chain Security Report — fastapi/fastapi

- **Repository:** https://github.com/fastapi/fastapi
- **Description:** FastAPI framework, high performance, easy to learn, fast to code, ready for production
- **Analyzed commit:** `7cb06f360dd4` on branch `master` (7473 commits in history)
- **GitHub:** 100354★, 9586 forks, 100 open issues
- **Generated:** 2026-07-11T14:11:52Z

## 1. Risk Assessment

### Overall risk level: 🟡 **MEDIUM** (score 18.5)

| Category | Score contribution |
|---|---|
| health | 9.5 |
| cicd | 4.0 |
| licenses | 3.0 |
| secrets | 2.0 |
| vulnerabilities | 0.0 |
| docker | 0.0 |

**Reasoning:**

- No known vulnerabilities were found in resolved dependencies.
- Secret scan over 7473 commits found 0 active, 0 historical and 56 likely-placeholder matches — contributes 2.0 points.
- CI/CD review raised 7 findings (0 high/critical), mostly cicd_pull_request_target ×7 — contributes 4.0 points.
- No Dockerfile exists in the repository, so no container risks apply.
- Licensing: 4 restrictive and 2 missing dependency licenses — contributes 3.0 points.
- Dependency health: 11 deprecated/abandoned/unresolvable packages — contributes 9.5 points.

*Scoring criteria: severity-weighted findings per category (CRITICAL=10, HIGH=6, MEDIUM=3, LOW=1; active secrets 12, historical 6, placeholders ≤2 total), each category capped (vulns/secrets 40, CI/CD 20, Docker/licenses/health 15); repeated findings of the same rule count 50% after the first. Bands: <10 LOW, <25 MEDIUM, <50 HIGH, ≥50 CRITICAL. Floors: an active secret, a CRITICAL vulnerability or a CRITICAL CI/CD finding each force at least HIGH.*

## 2. Component & Dependency Analysis

- **Total components:** 205 (56 direct, 149 transitive)
- **Ecosystems:** PyPI (205)
- **Transitive resolution:** lockfile
- **SBOM:** CycloneDX 1.5 → `sbom.cyclonedx.json`

### Direct dependencies

| Package | Ecosystem | Declared | Resolved | Scope | License | Health |
|---|---|---|---|---|---|---|
| a2wsgi | PyPI | `<=2.0.0,>=1.9.0` | 1.10.10 | dev | Apache-2.0 | AGING |
| annotated-doc | PyPI | `>=0.0.2` | 0.0.4 | runtime | MIT | HEALTHY |
| anyio | PyPI | `<5.0.0,>=3.2.1` | 4.12.1 | dev | MIT | HEALTHY |
| black | PyPI | `>=25.1.0` | 26.5.1 | dev | MIT | HEALTHY |
| cairosvg | PyPI | `>=2.8.2` | 2.9.0 | dev | LGPL-3.0-or-later | HEALTHY |
| coverage | PyPI | `<8.0,>=7.13` | 7.13.3 | dev | Apache-2.0 | HEALTHY |
| dirty-equals | PyPI | `>=0.9.0` | 0.11 | dev | MIT | HEALTHY |
| email-validator | PyPI | `>=2.0.0` | 2.3.0 | optional | Unlicense | AGING |
| fastapi-cli | PyPI | `>=0.0.8` | 0.0.20 | optional | MIT | HEALTHY |
| fastar | PyPI | `>=0.9.0` | 0.11.0 | optional | MIT | HEALTHY |
| flask | PyPI | `<4.0.0,>=3.0.0` | 3.1.3 | dev | BSD-3-Clause | HEALTHY |
| gitpython | PyPI | `>=3.1.46` | 3.1.50 | dev | BSD-3-Clause | HEALTHY |
| griffe-typingdoc | PyPI | `>=0.3.0` | 0.3.1 | dev | ISC | HEALTHY |
| griffe-warnings-deprecated | PyPI | `>=1.1.0` | 1.1.1 | dev | ISC | HEALTHY |
| httpx | PyPI | `<1.0.0,>=0.23.0` | 0.28.1 | optional | BSD-3-Clause | HEALTHY |
| httpx2 | PyPI | `>=2.0.0` | 2.5.0 | dev | BSD-3-Clause | HEALTHY |
| inline-snapshot | PyPI | `>=0.21.1` | 0.34.2 | dev | MIT | HEALTHY |
| itsdangerous | PyPI | `>=1.1.0` | 2.2.0 | optional | BSD-3-Clause | STALE |
| jieba | PyPI | `>=0.42.1` | 0.42.1 | dev | MIT | ABANDONED |
| jinja2 | PyPI | `>=3.1.5` | 3.1.6 | optional | BSD-3-Clause | AGING |
| markdown-include-variants | PyPI | `>=0.0.8` | 0.0.8 | dev | MIT | HEALTHY |
| mdx-include | PyPI | `<2.0.0,>=1.4.1` | 1.4.2 | dev | BSD-3-Clause | ABANDONED |
| mkdocstrings | PyPI | `>=1.0.3` | 1.0.4 | dev | ISC | HEALTHY |
| mypy | PyPI | `>=1.14.1` | 2.1.0 | dev | MIT | HEALTHY |
| pdm-backend | PyPI | `*` | 2.4.9 | build | MIT | HEALTHY |
| pillow | PyPI | `>=11.3.0` | 12.2.0 | dev | MIT-CMU | HEALTHY |
| playwright | PyPI | `>=1.57.0` | 1.61.0 | dev | Apache-2.0 | HEALTHY |
| prek | PyPI | `>=0.2.22` | 0.4.5 | dev | MIT | HEALTHY |
| pwdlib | PyPI | `>=0.2.1` | 0.3.0 | dev | MIT | AGING |
| pydantic | PyPI | `>=2.9.0` | 2.13.4 | runtime | MIT | HEALTHY |
| pydantic-ai | PyPI | `>=0.4.10` | 2.1.0 | dev | MIT | HEALTHY |
| pydantic-extra-types | PyPI | `>=2.0.0` | 2.11.0 | optional | MIT | HEALTHY |
| pydantic-settings | PyPI | `>=2.0.0` | 2.14.2 | optional | MIT | HEALTHY |
| pygithub | PyPI | `<3.0.0,>=2.3.0` | 2.9.1 | dev | GNU Library or Lesser General Public License (LGPL) | HEALTHY |
| pyjwt | PyPI | `>=2.9.0` | 2.13.0 | dev | MIT | HEALTHY |
| pytest | PyPI | `>=9.0.0` | 9.1.1 | dev | MIT | HEALTHY |
| pytest-codspeed | PyPI | `>=4.2.0` | 5.0.3 | dev | MIT | HEALTHY |
| pytest-cov | PyPI | `>=4.0.0` | 7.1.0 | dev | MIT | HEALTHY |
| pytest-sugar | PyPI | `>=1.0.0` | 1.1.1 | dev | BSD-3-Clause | HEALTHY |
| pytest-timeout | PyPI | `>=2.4.0` | 2.4.0 | dev | DFSG approved OR MIT | AGING |
| pytest-xdist | PyPI | `>=2.5.0` | 3.8.0 | dev | MIT | AGING |
| python-multipart | PyPI | `>=0.0.18` | 0.0.32 | optional | Apache-2.0 | HEALTHY |
| python-slugify | PyPI | `>=8.0.4` | 8.0.4 | dev | MIT | STALE |
| pyyaml | PyPI | `>=5.3.1` | 6.0.3 | optional | MIT | AGING |
| ruff | PyPI | `>=0.14.14` | 0.15.20 | dev | MIT | HEALTHY |
| smokeshow | PyPI | `>=0.5.0` | 0.5.0 | dev | MIT | STALE |
| sqlmodel | PyPI | `>=0.0.31` | 0.0.39 | dev | MIT | HEALTHY |
| starlette | PyPI | `>=0.46.0` | 1.3.1 | runtime | BSD-3-Clause | HEALTHY |
| strawberry-graphql | PyPI | `<1.0.0,>=0.200.0` | 0.320.0 | dev | MIT | HEALTHY |
| ty | PyPI | `>=0.0.25` | 0.0.55 | dev | MIT | HEALTHY |
| typer | PyPI | `>=0.21.1` | 0.26.8 | dev | MIT | HEALTHY |
| typing-extensions | PyPI | `>=4.8.0` | 4.15.0 | runtime | PSF-2.0 | HEALTHY |
| typing-inspection | PyPI | `>=0.4.2` | 0.4.2 | runtime | MIT | AGING |
| uvicorn | PyPI | `>=0.12.0` | 0.40.0 | optional | BSD-3-Clause | HEALTHY |
| zensical | PyPI | `>=0.0.42` | 0.0.46 | dev | MIT | HEALTHY |
| zizmor | PyPI | `>=1.23.1` | 1.26.1 | dev | MIT | HEALTHY |

## 3. Vulnerability Analysis

No known vulnerabilities were found in the resolved dependency set (source: OSV.dev).

## 4. Dependency Health Analysis

| Status | Count |
|---|---|
| HEALTHY | 148 |
| AGING | 27 |
| STALE | 19 |
| ABANDONED | 11 |

*Metrics: days since last release, releases in the last 365 days, total releases, registry deprecation/yanked flags, version lag. Classification: DEPRECATED (registry flag), ABANDONED (>3y since last release), STALE (18–36 months), AGING (6–18 months with <2 releases/yr), otherwise HEALTHY.*

### Health findings

- **[MEDIUM] jieba: appears abandoned (no release in 2363 days)** — The last release of 'jieba' was on 2020-01-20, more than 3 years ago. Vulnerabilities found in it are unlikely to be fixed upstream.
- **[MEDIUM] mdx-include: appears abandoned (no release in 1446 days)** — The last release of 'mdx-include' was on 2022-07-26, more than 3 years ago. Vulnerabilities found in it are unlikely to be fixed upstream.
- **[MEDIUM] colorama: appears abandoned (no release in 1355 days)** — The last release of 'colorama' was on 2022-10-25, more than 3 years ago. Vulnerabilities found in it are unlikely to be fixed upstream.
- **[MEDIUM] cyclic: appears abandoned (no release in 2844 days)** — The last release of 'cyclic' was on 2018-09-26, more than 3 years ago. Vulnerabilities found in it are unlikely to be fixed upstream.
- **[MEDIUM] ghp-import: appears abandoned (no release in 1530 days)** — The last release of 'ghp-import' was on 2022-05-02, more than 3 years ago. Vulnerabilities found in it are unlikely to be fixed upstream.
- **[MEDIUM] mdurl: appears abandoned (no release in 1427 days)** — The last release of 'mdurl' was on 2022-08-14, more than 3 years ago. Vulnerabilities found in it are unlikely to be fixed upstream.
- **[MEDIUM] mergedeep: appears abandoned (no release in 1981 days)** — The last release of 'mergedeep' was on 2021-02-05, more than 3 years ago. Vulnerabilities found in it are unlikely to be fixed upstream.
- **[MEDIUM] rcslice: appears abandoned (no release in 2844 days)** — The last release of 'rcslice' was on 2018-09-27, more than 3 years ago. Vulnerabilities found in it are unlikely to be fixed upstream.
- **[MEDIUM] sortedcontainers: appears abandoned (no release in 1881 days)** — The last release of 'sortedcontainers' was on 2021-05-16, more than 3 years ago. Vulnerabilities found in it are unlikely to be fixed upstream.
- **[MEDIUM] text-unidecode: appears abandoned (no release in 2506 days)** — The last release of 'text-unidecode' was on 2019-08-30, more than 3 years ago. Vulnerabilities found in it are unlikely to be fixed upstream.
- **[MEDIUM] webencodings: appears abandoned (no release in 3383 days)** — The last release of 'webencodings' was on 2017-04-05, more than 3 years ago. Vulnerabilities found in it are unlikely to be fixed upstream.
- **[LOW] itsdangerous: stale (no release in 815 days)** — 'itsdangerous' has had no release since 2024-04-16 and shows little maintenance activity.
- **[LOW] python-slugify: stale (no release in 883 days)** — 'python-slugify' has had no release since 2024-02-08 and shows little maintenance activity.
- **[LOW] smokeshow: stale (no release in 549 days)** — 'smokeshow' has had no release since 2025-01-07 and shows little maintenance activity.

## 5. License Analysis

- **Project license:** MIT (permissive; source: GitHub API)
- **Dependency licenses identified:** 203/205
- **Missing/unspecified:** 2 — mypy-extensions, tiktoken

| License | Packages |
|---|---|
| MIT | 99 |
| BSD-3-Clause | 39 |
| Apache-2.0 | 30 |
| ISC | 8 |
| PSF-2.0 | 3 |
| Apache-2.0 OR MIT | 3 |
| BSD-2-Clause | 3 |
| MPL-2.0 | 2 |
| Apache-2.0 OR BSD-3-Clause | 2 |
| UNKNOWN | 2 |
| LGPL-3.0-or-later | 1 |
| Unlicense | 1 |
| MIT-CMU | 1 |
| GNU Library or Lesser General Public License (LGPL) | 1 |
| DFSG approved OR MIT | 1 |

### Restrictive / copyleft licenses

- **cairosvg** 2.9.0: LGPL-3.0-or-later (weak-copyleft, direct)
- **certifi** 2026.1.4: MPL-2.0 (weak-copyleft, transitive)
- **pathspec** 1.0.4: MPL-2.0 (weak-copyleft, transitive)
- **tqdm** 4.67.3: MPL-2.0 AND MIT (weak-copyleft, transitive)

### Unusual / non-standard licenses

- **pygithub** 2.9.1: GNU Library or Lesser General Public License (LGPL)
- **protobuf** 6.33.5: 3-Clause BSD License
- **regex** 2026.1.15: Apache-2.0 AND CNRI-Python

No incompatibilities were detected between the project license and its dependencies.

## 6. Secret Detection (full git history)

**56 matches** — 0 likely real, 56 likely placeholders (test/docs/example values).

| Type | Location | Commit | Date | Status | Placeholder? |
|---|---|---|---|---|---|
| Generic Secret Assignment | `docs_src/security/tutorial004_an_py310.py:13` | `5fa8e38681` | 2024-05-20 | ACTIVE | likely |
| Generic Secret Assignment | `docs_src/security/tutorial004_py310.py:12` | `5fa8e38681` | 2024-05-20 | ACTIVE | likely |
| Generic Secret Assignment | `docs_src/security/tutorial005_an_py310.py:17` | `08b817a842` | 2025-02-15 | ACTIVE | likely |
| Generic Secret Assignment | `docs_src/security/tutorial005_py310.py:16` | `5fa8e38681` | 2024-05-20 | ACTIVE | likely |
| JWT | `docs/de/docs/tutorial/security/oauth2-jwt.md:16` | `c623291929` | 2025-10-01 | ACTIVE | likely |
| JWT | `docs/en/docs/tutorial/security/oauth2-jwt.md:16` | `d11f820ac3` | 2026-02-12 | ACTIVE | likely |
| JWT | `docs/es/docs/tutorial/security/oauth2-jwt.md:16` | `da83d79546` | 2025-12-16 | ACTIVE | likely |
| JWT | `docs/fr/docs/tutorial/security/oauth2-jwt.md:16` | `7dc1be8b88` | 2026-02-14 | ACTIVE | likely |
| JWT | `docs/ja/docs/tutorial/security/oauth2-jwt.md:16` | `b0e99d66e8` | 2026-02-04 | ACTIVE | likely |
| JWT | `docs/ko/docs/tutorial/security/oauth2-jwt.md:16` | `cf8dc98aad` | 2026-01-10 | ACTIVE | likely |
| JWT | `docs/pt/docs/tutorial/security/oauth2-jwt.md:16` | `540a83da65` | 2025-11-12 | ACTIVE | likely |
| JWT | `docs/ru/docs/tutorial/security/oauth2-jwt.md:16` | `55a9eee13a` | 2026-02-12 | ACTIVE | likely |
| JWT | `docs/tr/docs/tutorial/security/oauth2-jwt.md:16` | `b5d276bda8` | 2026-02-05 | ACTIVE | likely |
| JWT | `docs/uk/docs/tutorial/security/oauth2-jwt.md:16` | `ec35d6d380` | 2026-02-14 | ACTIVE | likely |
| JWT | `docs/zh-hant/docs/tutorial/security/oauth2-jwt.md:16` | `9a082312f3` | 2026-02-14 | ACTIVE | likely |
| JWT | `docs/zh/docs/tutorial/security/oauth2-jwt.md:16` | `376e108580` | 2026-02-08 | ACTIVE | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial004.py:121` | `3063ada72f` | 2025-12-26 | ACTIVE | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial004.py:135` | `3063ada72f` | 2025-12-26 | ACTIVE | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial004.py:149` | `3063ada72f` | 2025-12-26 | ACTIVE | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005.py:125` | `44c849c4fc` | 2025-12-27 | ACTIVE | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005.py:139` | `44c849c4fc` | 2025-12-27 | ACTIVE | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005.py:165` | `44c849c4fc` | 2025-12-27 | ACTIVE | likely |
| Generic Secret Assignment | `docs_src/security/tutorial004_an_py39.py:12` | `5ccc869fee` | 2024-03-26 | historical | likely |
| Generic Secret Assignment | `docs_src/security/tutorial004_py39.py:13` | `efdafa4361` | 2025-09-29 | historical | likely |
| Generic Secret Assignment | `docs_src/security/tutorial005_an_py39.py:17` | `5fa8e38681` | 2024-05-20 | historical | likely |
| Generic Secret Assignment | `docs_src/security/tutorial005_py39.py:16` | `5ccc869fee` | 2024-03-26 | historical | likely |
| Generic Secret Assignment | `tests/test_pydantic_v1_v2_mixed.py:64` | `d34918abf0` | 2025-10-11 | historical | likely |
| Generic Secret Assignment | `tests/test_pydantic_v1_v2_mixed.py:90` | `e2cd8a4201` | 2025-12-20 | historical | likely |
| Generic Secret Assignment | `tests/test_pydantic_v1_v2_noneable.py:68` | `d34918abf0` | 2025-10-11 | historical | likely |
| Generic Secret Assignment | `tests/test_pydantic_v1_v2_noneable.py:98` | `d34918abf0` | 2025-10-11 | historical | likely |
| Generic Secret Assignment | `docs_src/security/tutorial004_an.py:13` | `fd97e8efe4` | 2024-01-11 | historical | likely |
| Generic Secret Assignment | `docs_src/security/tutorial005.py:16` | `fd97e8efe4` | 2024-01-11 | historical | likely |
| Generic Secret Assignment | `docs_src/security/tutorial005_an.py:17` | `5ccc869fee` | 2024-03-26 | historical | likely |
| Generic Secret Assignment | `docs_src/security/tutorial004.py:12` | `07f8d31ec9` | 2024-01-10 | historical | likely |
| Generic Secret Assignment | `docs_src/sql_databases/sql_app/tests/test_sql_app.py:35` | `d96223460b` | 2020-04-05 | historical | likely |
| Generic Secret Assignment | `docs_src/sql_databases/sql_app_py310/tests/test_sql_app.py:35` | `e9b189e9f2` | 2020-04-08 | historical | likely |
| Generic Secret Assignment | `docs/src/security/tutorial004.py:13` | `8772e2f2ee` | 2019-02-16 | historical | likely |
| Generic Secret Assignment | `docs/src/security/tutorial005.py:18` | `7391056daf` | 2019-04-09 | historical | likely |
| Generic Secret Assignment | `docs/tutorial/src/security/tutorial004.py:16` | `00e2e544c7` | 2018-12-18 | historical | likely |
| JWT | `docs/em/docs/tutorial/security/oauth2-jwt.md:16` | `d4e85da18b` | 2023-04-01 | historical | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005_an.py:101` | `bd32fecaf6` | 2023-06-16 | historical | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005_an.py:113` | `bd32fecaf6` | 2023-06-16 | historical | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005_an.py:135` | `bd32fecaf6` | 2023-06-16 | historical | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005_an_py310.py:121` | `bd32fecaf6` | 2023-06-16 | historical | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005_an_py310.py:134` | `bd32fecaf6` | 2023-06-16 | historical | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005_an_py310.py:158` | `bd32fecaf6` | 2023-06-16 | historical | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005_an_py39.py:121` | `bd32fecaf6` | 2023-06-16 | historical | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005_an_py39.py:134` | `bd32fecaf6` | 2023-06-16 | historical | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005_an_py39.py:158` | `bd32fecaf6` | 2023-06-16 | historical | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005_py310.py:121` | `bd32fecaf6` | 2023-06-16 | historical | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005_py310.py:134` | `bd32fecaf6` | 2023-06-16 | historical | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005_py310.py:158` | `bd32fecaf6` | 2023-06-16 | historical | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005_py39.py:121` | `bd32fecaf6` | 2023-06-16 | historical | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005_py39.py:134` | `bd32fecaf6` | 2023-06-16 | historical | likely |
| JWT | `tests/test_tutorial/test_security/test_tutorial005_py39.py:158` | `bd32fecaf6` | 2023-06-16 | historical | likely |
| JWT | `docs/tutorial/security/oauth2-jwt.md:14` | `1ed5aa23e6` | 2019-08-30 | historical | likely |

## 7. Docker Security Analysis

No Dockerfile was found in the repository — container checks were skipped.

## 8. CI/CD Security Analysis

Analyzed 23 pipeline files.

| Severity | Rule | Finding | Location |
|---|---|---|---|
| LOW | `CICD_PULL_REQUEST_TARGET` | pull_request_target trigger in add-to-project.yml | `.github/workflows/add-to-project.yml` |
| LOW | `CICD_PULL_REQUEST_TARGET` | pull_request_target trigger in detect-conflicts.yml | `.github/workflows/detect-conflicts.yml` |
| LOW | `CICD_PULL_REQUEST_TARGET` | pull_request_target trigger in guard-dependencies.yml | `.github/workflows/guard-dependencies.yml` |
| LOW | `CICD_PULL_REQUEST_TARGET` | pull_request_target trigger in issue-manager.yml | `.github/workflows/issue-manager.yml` |
| LOW | `CICD_PULL_REQUEST_TARGET` | pull_request_target trigger in labeler.yml | `.github/workflows/labeler.yml` |
| LOW | `CICD_PULL_REQUEST_TARGET` | pull_request_target trigger in latest-changes.yml | `.github/workflows/latest-changes.yml` |
| LOW | `CICD_PULL_REQUEST_TARGET` | pull_request_target trigger in notify-translations.yml | `.github/workflows/notify-translations.yml` |

## 9. Recommendations

| Priority | Category | Issue | Recommendation |
|---|---|---|---|
| MEDIUM | health | jieba: appears abandoned (no release in 2363 days) [pyproject.toml, uv.lock] | Evaluate whether 'jieba' is still needed; prefer an actively maintained alternative, or accept and document the risk. |
| MEDIUM | health | mdx-include: appears abandoned (no release in 1446 days) [pyproject.toml, uv.lock] | Evaluate whether 'mdx-include' is still needed; prefer an actively maintained alternative, or accept and document the risk. |
| MEDIUM | health | colorama: appears abandoned (no release in 1355 days) [uv.lock] | Evaluate whether 'colorama' is still needed; prefer an actively maintained alternative, or accept and document the risk. |
| MEDIUM | health | cyclic: appears abandoned (no release in 2844 days) [uv.lock] | Evaluate whether 'cyclic' is still needed; prefer an actively maintained alternative, or accept and document the risk. |
| MEDIUM | health | ghp-import: appears abandoned (no release in 1530 days) [uv.lock] | Evaluate whether 'ghp-import' is still needed; prefer an actively maintained alternative, or accept and document the risk. |
| MEDIUM | health | mdurl: appears abandoned (no release in 1427 days) [uv.lock] | Evaluate whether 'mdurl' is still needed; prefer an actively maintained alternative, or accept and document the risk. |
| MEDIUM | health | mergedeep: appears abandoned (no release in 1981 days) [uv.lock] | Evaluate whether 'mergedeep' is still needed; prefer an actively maintained alternative, or accept and document the risk. |
| MEDIUM | health | rcslice: appears abandoned (no release in 2844 days) [uv.lock] | Evaluate whether 'rcslice' is still needed; prefer an actively maintained alternative, or accept and document the risk. |
| MEDIUM | health | sortedcontainers: appears abandoned (no release in 1881 days) [uv.lock] | Evaluate whether 'sortedcontainers' is still needed; prefer an actively maintained alternative, or accept and document the risk. |
| MEDIUM | health | text-unidecode: appears abandoned (no release in 2506 days) [uv.lock] | Evaluate whether 'text-unidecode' is still needed; prefer an actively maintained alternative, or accept and document the risk. |
| MEDIUM | health | webencodings: appears abandoned (no release in 3383 days) [uv.lock] | Evaluate whether 'webencodings' is still needed; prefer an actively maintained alternative, or accept and document the risk. |
| LOW | secret | 56 likely-placeholder secret matches in tests/docs/examples | Review the flagged matches once to confirm they are dummy values; keep obviously fake values clearly labelled (e.g. 'example-key') so scanners and reviewers can dismiss them quickly. |
| LOW | cicd | pull_request_target trigger in add-to-project.yml [.github/workflows/add-to-project.yml] | Prefer the 'pull_request' trigger. If write access is required, never check out or execute PR-controlled code in the same job, and gate execution on a maintainer label. |
| LOW | cicd | pull_request_target trigger in detect-conflicts.yml [.github/workflows/detect-conflicts.yml] | Prefer the 'pull_request' trigger. If write access is required, never check out or execute PR-controlled code in the same job, and gate execution on a maintainer label. |
| LOW | cicd | pull_request_target trigger in guard-dependencies.yml [.github/workflows/guard-dependencies.yml] | Prefer the 'pull_request' trigger. If write access is required, never check out or execute PR-controlled code in the same job, and gate execution on a maintainer label. |
| LOW | cicd | pull_request_target trigger in issue-manager.yml [.github/workflows/issue-manager.yml] | Prefer the 'pull_request' trigger. If write access is required, never check out or execute PR-controlled code in the same job, and gate execution on a maintainer label. |
| LOW | cicd | pull_request_target trigger in labeler.yml [.github/workflows/labeler.yml] | Prefer the 'pull_request' trigger. If write access is required, never check out or execute PR-controlled code in the same job, and gate execution on a maintainer label. |
| LOW | cicd | pull_request_target trigger in latest-changes.yml [.github/workflows/latest-changes.yml] | Prefer the 'pull_request' trigger. If write access is required, never check out or execute PR-controlled code in the same job, and gate execution on a maintainer label. |
| LOW | cicd | pull_request_target trigger in notify-translations.yml [.github/workflows/notify-translations.yml] | Prefer the 'pull_request' trigger. If write access is required, never check out or execute PR-controlled code in the same job, and gate execution on a maintainer label. |
| LOW | license | 2 dependencies without a declared license | Inspect these packages' repositories manually and record their actual licenses; replace packages that truly have none. |
| LOW | license | Restrictive license: cairosvg is LGPL-3.0-or-later | Confirm the usage of 'cairosvg' complies with LGPL-3.0-or-later (dynamic linking / unmodified use is usually fine for weak copyleft); document the obligation in your compliance records. |
| LOW | license | Restrictive license: certifi is MPL-2.0 | Confirm the usage of 'certifi' complies with MPL-2.0 (dynamic linking / unmodified use is usually fine for weak copyleft); document the obligation in your compliance records. |
| LOW | license | Restrictive license: pathspec is MPL-2.0 | Confirm the usage of 'pathspec' complies with MPL-2.0 (dynamic linking / unmodified use is usually fine for weak copyleft); document the obligation in your compliance records. |
| LOW | license | Restrictive license: tqdm is MPL-2.0 AND MIT | Confirm the usage of 'tqdm' complies with MPL-2.0 AND MIT (dynamic linking / unmodified use is usually fine for weak copyleft); document the obligation in your compliance records. |
| LOW | health | itsdangerous: stale (no release in 815 days) [pyproject.toml, uv.lock] | Monitor 'itsdangerous' for abandonment and plan an exit strategy. |
| LOW | health | python-slugify: stale (no release in 883 days) [pyproject.toml, uv.lock] | Monitor 'python-slugify' for abandonment and plan an exit strategy. |
| LOW | health | smokeshow: stale (no release in 549 days) [pyproject.toml, uv.lock] | Monitor 'smokeshow' for abandonment and plan an exit strategy. |
