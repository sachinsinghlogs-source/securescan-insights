

# Advanced Cloud VAPT Upgrade Plan

## Current State
The pipeline has 10 scan modules with basic checks per module. Each module does surface-level probing (header checks, single-path probes, basic pattern matching). The upgrade deepens every module and adds new capabilities.

## What Changes

### 1. Edge Function — Deeper Scan Logic Per Module (6 key upgrades)

**DNS Recon** — Add: CAA record check, MX open-relay fingerprint, NS delegation consistency, AXFR attempt detection (via EDNS probing), wildcard DNS detection (`*.domain`), check for known dangling CNAME targets (GitHub Pages, Heroku, S3, Azure, etc. via a signature list).

**SSL/TLS Deep** — Add: check multiple ports (443, 8443), test TLS 1.0/1.1 by attempting downgraded fetch, OCSP stapling check via response headers, certificate key size analysis from CT logs, SAN (Subject Alternative Names) enumeration, mixed content detection (HTTP resources on HTTPS page).

**Auth & Session** — Add: test for username enumeration (different response on valid vs invalid login), check for CAPTCHA on login forms, test session cookie rotation after login, check for `__Host-` / `__Secure-` cookie prefixes, detect exposed API keys (AWS, Google, Stripe patterns in source), check for 2FA/MFA indicators.

**Info Disclosure / OSINT** — Add: check `.well-known/security.txt`, check for source maps (`.js.map`), detect debug mode indicators (`DEBUG=true`, stack traces), check `/.well-known/openid-configuration`, detect technology versions from `generator` meta tag, check for exposed Swagger/OpenAPI endpoints (`/swagger.json`, `/api-docs`), check `X-Debug-Token` header.

**WAF Detection** — Add: test multiple evasion techniques (encoding bypass, case variation, null bytes), check if WAF is in detection-only vs blocking mode (by analyzing response codes vs body), test SSRF payloads, test XXE patterns, detect ModSecurity, Azure Front Door, AWS Shield.

**Injection Surface** — Add: blind XSS polyglot testing, CRLF injection check (`%0d%0a`), host header injection, HTTP parameter pollution, LDAP injection indicators, XML injection probing, NoSQL injection patterns (`{"$gt": ""}`), prototype pollution patterns.

### 2. Enhanced Risk Scoring

- Add temporal scoring factor (newly discovered vulns weighted higher)
- Add exploitability score per finding (network-accessible vs local-only)
- Add environmental modifiers (public-facing = higher weight)
- Add CVSS v3.1 base score estimate per finding
- Cross-finding correlation: chained vulnerability detection (e.g., open redirect + no CSP = phishing chain)

### 3. New Scan Modules (expand from 10 to 14)

- **HTTP Method Testing** — Check for unsafe methods (PUT, DELETE, TRACE, CONNECT) enabled, test TRACE for XST attacks
- **Client-Side Security** — Scan HTML for inline scripts without nonces, check for Subresource Integrity (SRI) on external scripts, detect postMessage misuse patterns, check for DOM-XSS sinks
- **API Specification Discovery** — Probe for GraphQL (`/graphql`, introspection query), REST API docs (`/swagger`, `/openapi.json`, `/api-docs`), WSDL endpoints
- **Cloud Metadata & SSRF** — Test for cloud metadata access patterns, check for internal IP exposure, test common SSRF bypass patterns in URL parameters

### 4. Updated Pipeline UI

- Show 14 scan stages with categorized grouping (Network, Application, API, Infrastructure)
- Add per-finding CVSS score display
- Add vulnerability chain visualization (linked findings)
- Add "Export as JSON" alongside PDF
- Add scan comparison modal (diff two pipeline runs)
- Add dark/light severity timeline chart

### 5. Database Changes

- Add `cvss_vector` and `cvss_score` fields to finding JSONB structure
- Update `total_stages` default to 14
- Add `finding_chains` JSONB column to `vapt_reports` for correlated vulnerabilities

## Technical Details

**Edge Function** (`cloud-security-pipeline/index.ts`):
- Add 4 new scan functions: `scanHttpMethods`, `scanClientSideSecurity`, `scanApiDiscovery`, `scanCloudMetadata`
- Expand all 10 existing scan functions with deeper checks as described above
- Add CVSS v3.1 base score calculator
- Add finding chain correlator
- Update `SCAN_STAGES` to 14 entries

**Database Migration**:
- `ALTER TABLE cloud_scan_pipelines ALTER COLUMN total_stages SET DEFAULT 14`
- `ALTER TABLE vapt_reports ADD COLUMN finding_chains jsonb DEFAULT '[]'`

**Modified Frontend Files**:
- `CloudPipelineRunner.tsx` — Add 4 new stage labels, grouped stage display, CVSS badges per finding, chain indicators
- `VAPTReport.tsx` — Add CVSS display, finding chains section
- `OWASPHeatmap.tsx` — Add finding count per cell, clickable drill-down
- `AttackSurfaceRadar.tsx` — Expand to 14 categories

