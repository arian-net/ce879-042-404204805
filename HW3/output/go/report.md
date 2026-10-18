# Supply Chain Security Report — golang/go

- **Repository:** https://github.com/golang/go.git
- **Description:** The Go programming language
- **Analyzed commit:** `30719fe26f57` on branch `master` (66853 commits in history)
- **GitHub:** 135303★, 19275 forks, 10186 open issues
- **Generated:** 2026-07-10T18:55:18Z

## 1. Risk Assessment

### Overall risk level: 🟠 **HIGH** (score 35.5)

| Category | Score contribution |
|---|---|
| secrets | 32.0 |
| vulnerabilities | 3.0 |
| licenses | 0.5 |
| cicd | 0.0 |
| docker | 0.0 |
| health | 0.0 |

**Reasoning:**

- 1 known vulnerabilities (1 MEDIUM) affect 1 package(s): golang.org/x/crypto — contributes 3.0 points.
- Secret scan over 66853 commits found 1 active, 3 historical and 35 likely-placeholder matches — contributes 32.0 points.
- No Dockerfile exists in the repository, so no container risks apply.
- Licensing: 1 restrictive and 0 missing dependency licenses — contributes 0.5 points.

*Scoring criteria: severity-weighted findings per category (CRITICAL=10, HIGH=6, MEDIUM=3, LOW=1; active secrets 12, historical 6, placeholders ≤2 total), each category capped (vulns/secrets 40, CI/CD 20, Docker/licenses/health 15); repeated findings of the same rule count 50% after the first. Bands: <10 LOW, <25 MEDIUM, <50 HIGH, ≥50 CRITICAL. Floors: an active secret, a CRITICAL vulnerability or a CRITICAL CI/CD finding each force at least HIGH.*

## 2. Component & Dependency Analysis

- **Total components:** 16 (13 direct, 3 transitive)
- **Ecosystems:** Go (16)
- **Transitive resolution:** go.mod
- **SBOM:** CycloneDX 1.5 → `sbom.cyclonedx.json`

### Direct dependencies

| Package | Ecosystem | Declared | Resolved | Scope | License | Health |
|---|---|---|---|---|---|---|
| github.com/google/pprof | Go | `*` | 0.0.0-20260507013755-92041b743c96 | runtime | Apache-2.0 AND BSD-3-Clause | HEALTHY |
| github.com/mmcloughlin/avo | Go | `*` | 0.6.0 | runtime | BSD-3-Clause AND LGPL-3.0 AND BSD-2-Clause | HEALTHY |
| golang.org/x/arch | Go | `*` | 0.27.1-0.20260521044007-9c1a596a2c97 | runtime | BSD-3-Clause | HEALTHY |
| golang.org/x/build | Go | `*` | 0.0.0-20260522210304-d55d0041b921 | runtime | BSD-3-Clause AND ISC | HEALTHY |
| golang.org/x/crypto | Go | `*` | 0.52.1-0.20260526024921-9beb694f9766 | runtime | BSD-3-Clause | HEALTHY |
| golang.org/x/mod | Go | `*` | 0.36.1-0.20260520130633-087f6515dd3b | runtime | BSD-3-Clause | HEALTHY |
| golang.org/x/net | Go | `*` | 0.55.1-0.20260526154343-657eb1317b5d | runtime | BSD-3-Clause | HEALTHY |
| golang.org/x/sync | Go | `*` | 0.20.0 | runtime | BSD-3-Clause | HEALTHY |
| golang.org/x/sys | Go | `*` | 0.45.0 | runtime | BSD-3-Clause | HEALTHY |
| golang.org/x/telemetry | Go | `*` | 0.0.0-20260519152614-eab6ae52b5e2 | runtime | BSD-3-Clause | HEALTHY |
| golang.org/x/term | Go | `*` | 0.43.0 | runtime | BSD-3-Clause | HEALTHY |
| golang.org/x/tools | Go | `*` | 0.45.1-0.20260708165844-7044391f8d9f | runtime | BSD-3-Clause | HEALTHY |
| gopkg.in/yaml.v3 | Go | `*` | 3.0.1 | runtime | MIT AND Apache-2.0 | AGING |

## 3. Vulnerability Analysis

**1 known vulnerabilities** — 1 MEDIUM

| Package | Version | ID (CVE) | Severity | CVSS | Fixed in | Summary |
|---|---|---|---|---|---|---|
| golang.org/x/crypto | 0.52.1-0.20260526024921-9beb694f9766 | GO-2026-5932 | MEDIUM | — | — | The golang.org/x/crypto/openpgp package is unmaintained, unsafe by design, and has known security issues |

## 4. Dependency Health Analysis

| Status | Count |
|---|---|
| HEALTHY | 14 |
| AGING | 1 |
| STALE | 1 |

*Metrics: days since last release, releases in the last 365 days, total releases, registry deprecation/yanked flags, version lag. Classification: DEPRECATED (registry flag), ABANDONED (>3y since last release), STALE (18–36 months), AGING (6–18 months with <2 releases/yr), otherwise HEALTHY.*


## 5. License Analysis

- **Project license:** BSD-3-Clause (permissive; source: GitHub API)
- **Dependency licenses identified:** 16/16
- **Missing/unspecified:** 0

| License | Packages |
|---|---|
| BSD-3-Clause | 12 |
| Apache-2.0 AND BSD-3-Clause | 1 |
| BSD-3-Clause AND LGPL-3.0 AND BSD-2-Clause | 1 |
| BSD-3-Clause AND ISC | 1 |
| MIT AND Apache-2.0 | 1 |

### Restrictive / copyleft licenses

- **github.com/mmcloughlin/avo** 0.6.0: BSD-3-Clause AND LGPL-3.0 AND BSD-2-Clause (weak-copyleft, direct)

No incompatibilities were detected between the project license and its dependencies.

## 6. Secret Detection (full git history)

**39 matches** — 4 likely real, 35 likely placeholders (test/docs/example values).

| Type | Location | Commit | Date | Status | Placeholder? |
|---|---|---|---|---|---|
| Private Key (PEM) | `src/crypto/x509/platform_root_key.pem:1` | `3aea422e2c` | 2023-04-25 | ACTIVE | no |
| Generic Secret Assignment | `misc/makerelease/makerelease.go:769` | `031850b689` | 2014-12-10 | historical | no |
| Generic Secret Assignment | `misc/makerelease/makerelease.go:681` | `0627fa84b7` | 2014-05-29 | historical | no |
| Private Key (PEM) | `src/crypto/x509/x509_test_import.go:44` | `9144ef3321` | 2013-12-19 | historical | no |
| Credential in URL | `src/net/url/url_test.go:284` | `07d86b1f2d` | 2014-08-30 | ACTIVE | likely |
| Private Key (PEM) | `src/crypto/tls/example_test.go:139` | `7eb5941b95` | 2020-06-23 | ACTIVE | likely |
| Private Key (PEM) | `src/crypto/tls/testdata/example-key.pem:1` | `4154727e1b` | 2017-10-20 | ACTIVE | likely |
| Private Key (PEM) | `src/crypto/rsa/pkcs1v15_test.go:251` | `372f399e00` | 2014-07-02 | historical | likely |
| Private Key (PEM) | `src/crypto/tls/handshake_server_test.go:748` | `e5624edc7e` | 2014-10-15 | historical | likely |
| Private Key (PEM) | `src/crypto/tls/handshake_server_test.go:783` | `e5624edc7e` | 2014-10-15 | historical | likely |
| Private Key (PEM) | `src/crypto/tls/tls_test.go:31` | `fce63888ce` | 2014-08-11 | historical | likely |
| Private Key (PEM) | `src/crypto/tls/tls_test.go:44` | `fce63888ce` | 2014-08-11 | historical | likely |
| Private Key (PEM) | `src/crypto/tls/tls_test.go:73` | `fce63888ce` | 2014-08-11 | historical | likely |
| Private Key (PEM) | `src/crypto/x509/pem_decrypt_test.go:83` | `2ec3a0a72f` | 2014-07-03 | historical | likely |
| Private Key (PEM) | `src/crypto/x509/x509_test.go:80` | `64bed3f55f` | 2014-10-13 | historical | likely |
| Private Key (PEM) | `src/encoding/pem/pem_test.go:155` | `1e1733a9ac` | 2012-11-12 | historical | likely |
| Private Key (PEM) | `src/net/http/httptest/server.go:220` | `220a6de47e` | 2014-09-08 | historical | likely |
| Private Key (PEM) | `src/net/smtp/smtp_test.go:686` | `220a6de47e` | 2014-09-08 | historical | likely |
| Private Key (PEM) | `src/crypto/tls/boring_test.go:598` | `083811d079` | 2021-08-26 | historical | likely |
| Private Key (PEM) | `src/crypto/x509/x509_test.go:1244` | `ad7ce3911f` | 2019-10-30 | historical | likely |
| Private Key (PEM) | `src/crypto/tls/handshake_client_test.go:892` | `320da8d149` | 2019-02-19 | historical | likely |
| Private Key (PEM) | `src/net/http/internal/testcert.go:27` | `e50a4c6987` | 2015-11-03 | historical | likely |
| Private Key (PEM) | `src/crypto/tls/handshake_server_test.go:1410` | `f35338582d` | 2019-05-16 | historical | likely |
| Private Key (PEM) | `src/pkg/net/http/httptest/server.go:198` | `42c8904fe1` | 2012-11-22 | historical | likely |
| Private Key (PEM) | `src/pkg/net/smtp/smtp_test.go:686` | `a18bfb8c67` | 2014-03-04 | historical | likely |
| Private Key (PEM) | `src/pkg/crypto/tls/handshake_server_test.go:3154` | `f752484c74` | 2013-09-26 | historical | likely |
| Private Key (PEM) | `src/pkg/crypto/tls/handshake_server_test.go:3191` | `f752484c74` | 2013-09-26 | historical | likely |
| Private Key (PEM) | `src/pkg/crypto/tls/tls_test.go:25` | `aaf3b71288` | 2012-11-16 | historical | likely |
| Private Key (PEM) | `src/pkg/crypto/tls/tls_test.go:38` | `444b7b53e0` | 2012-12-01 | historical | likely |
| Private Key (PEM) | `src/pkg/crypto/tls/tls_test.go:54` | `aaf3b71288` | 2012-11-16 | historical | likely |
| Private Key (PEM) | `src/pkg/crypto/x509/pem_decrypt_test.go:83` | `791fb978dd` | 2012-11-12 | historical | likely |
| Private Key (PEM) | `src/pkg/crypto/x509/x509_test.go:78` | `87404c9887` | 2013-08-30 | historical | likely |
| Private Key (PEM) | `src/pkg/crypto/rsa/pkcs1v15_test.go:201` | `30aa701fec` | 2011-11-08 | historical | likely |
| Private Key (PEM) | `src/pkg/crypto/tls/handshake_client_test.go:88` | `1de4d313dd` | 2012-11-26 | historical | likely |
| Private Key (PEM) | `src/pkg/crypto/tls/handshake_client_test.go:2297` | `7b7dac5e23` | 2013-07-17 | historical | likely |
| Private Key (PEM) | `src/pkg/encoding/pem/pem_test.go:155` | `3478891d12` | 2010-10-22 | historical | likely |
| Private Key (PEM) | `src/pkg/crypto/openpgp/read_test.go:329` | `acc284d847` | 2011-07-01 | historical | likely |
| Private Key (PEM) | `src/pkg/exp/ssh/client_auth_test.go:20` | `bac7bc55a6` | 2011-12-01 | historical | likely |
| Private Key (PEM) | `src/pkg/http/httptest/server.go:125` | `cc40870f4b` | 2011-04-04 | historical | likely |

## 7. Docker Security Analysis

No Dockerfile was found in the repository — container checks were skipped.

## 8. CI/CD Security Analysis

No CI/CD pipeline definitions were found.

## 9. Recommendations

| Priority | Category | Issue | Recommendation |
|---|---|---|---|
| CRITICAL | secret | Private Key (PEM) in src/crypto/x509/platform_root_key.pem (commit 3aea422e2c, ACTIVE (present in current tree)) | Revoke and rotate this credential immediately — git history is public even after deletion. Then purge it from history (git filter-repo / BFG) and add pre-commit secret scanning (e.g. gitleaks) to prevent recurrence. |
| HIGH | secret | Generic Secret Assignment in misc/makerelease/makerelease.go (commit 031850b689, HISTORICAL (removed from current tree, still in git history)) | Revoke and rotate this credential immediately — git history is public even after deletion. Then purge it from history (git filter-repo / BFG) and add pre-commit secret scanning (e.g. gitleaks) to prevent recurrence. |
| HIGH | secret | Generic Secret Assignment in misc/makerelease/makerelease.go (commit 0627fa84b7, HISTORICAL (removed from current tree, still in git history)) | Revoke and rotate this credential immediately — git history is public even after deletion. Then purge it from history (git filter-repo / BFG) and add pre-commit secret scanning (e.g. gitleaks) to prevent recurrence. |
| HIGH | secret | Private Key (PEM) in src/crypto/x509/x509_test_import.go (commit 9144ef3321, HISTORICAL (removed from current tree, still in git history)) | Revoke and rotate this credential immediately — git history is public even after deletion. Then purge it from history (git filter-repo / BFG) and add pre-commit secret scanning (e.g. gitleaks) to prevent recurrence. |
| MEDIUM | vulnerability | golang.org/x/crypto@0.52.1-0.20260526024921-9beb694f9766 has 1 known vulnerability (GO-2026-5932) | No fixed release is published for GO-2026-5932; apply vendor mitigations or replace the package. |
| LOW | secret | 35 likely-placeholder secret matches in tests/docs/examples | Review the flagged matches once to confirm they are dummy values; keep obviously fake values clearly labelled (e.g. 'example-key') so scanners and reviewers can dismiss them quickly. |
| LOW | license | Restrictive license: github.com/mmcloughlin/avo is BSD-3-Clause AND LGPL-3.0 AND BSD-2-Clause | Confirm the usage of 'github.com/mmcloughlin/avo' complies with BSD-3-Clause AND LGPL-3.0 AND BSD-2-Clause (dynamic linking / unmodified use is usually fine for weak copyleft); document the obligation in your compliance records. |
