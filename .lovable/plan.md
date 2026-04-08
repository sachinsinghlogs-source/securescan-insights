

# Advanced Cloud VAPT Tool - Full Upgrade Plan

## Current State
The existing cloud security pipeline has 4 basic scan modules (Deployment, API, Storage, Infrastructure) that perform surface-level checks like header presence, CORS, and admin panel probing. This plan upgrades it to an advanced-level VAPT (Vulnerability Assessment and Penetration Testing) tool.

## What We Will Build

### 1. Expand Edge Function with 6 New Advanced Scan Modules

Add these modules to the `cloud-security-pipeline` edge function alongside the existing 4:

- **DNS & Subdomain Reconnaissance**: Check DNS records (MX, TXT, SPF, DMARC, DNSKEY), detect zone transfer misconfigs, identify dangling CNAMEs (subdomain takeover risk)
- **SSL/TLS Deep Analysis**: Certificate chain validation, expiry checks, weak cipher detection, protocol version testing (TLS 1.0/1.1 deprecated), certificate transparency log checks, OCSP stapling
- **Authentication & Session Testing**: Test for default credentials on common paths, session fixation checks, JWT validation (algorithm confusion, expiry, weak secrets via known patterns), OAuth misconfiguration detection
- **Information Disclosure & OSINT**: robots.txt/sitemap.xml analysis, .git/.svn/.env exposure, backup file detection (.bak, .old, .sql), metadata leak detection, email harvesting from page source
- **WAF & Firewall Detection**: Identify WAF providers (Cloudflare, AWS WAF, Akamai), test WAF bypass patterns, detect rate-limit bypass opportunities
- **Injection Surface Mapping**: SQL injection pattern probing (error-based detection via `'`, `1 OR 1=1`), command injection signature testing, path traversal detection (`../../etc/passwd`), open redirect testing

All scans remain **passive/non-destructive** (no exploitation) per security policy.

### 2. Enhanced Risk Scoring Engine

Replace the simple additive scoring with a weighted CVSS-inspired model:
- Weight by category (Auth vulns > Info Disclosure)
- Factor in finding combinations (e.g., no WAF + XSS = elevated score)
- Generate a confidence score per finding
- Add OWASP Top 10 category mapping to each finding

### 3. New Database Table: `vapt_reports`

Store comprehensive report data:
- `pipeline_id`, `user_id`, `target_url`
- `executive_summary` (auto-generated text)
- `owasp_mapping` (JSONB - findings mapped to OWASP categories)
- `attack_surface_score` (0-100)
- `compliance_flags` (JSONB - PCI-DSS, SOC2, ISO27001 relevance)
- `remediation_priority` (JSONB - ordered fix list)

### 4. Updated Pipeline UI (`CloudPipelineRunner.tsx`)

- Show all 10 scan stages with progress indicators
- Add **OWASP Top 10 heatmap** showing which categories have findings
- Add **Attack Surface Visualization** - radar chart showing exposure across categories
- Add **Remediation Priority List** - ordered by impact with effort estimates
- Add **Compliance Quick-Check** badges (PCI-DSS, SOC2, ISO27001)
- Add **PDF Export** button for the full VAPT report

### 5. New Component: `VAPTReport.tsx`

A detailed report view with:
- Executive summary with risk posture overview
- Finding details grouped by OWASP category
- Remediation roadmap with priority ordering
- Comparison with previous scans (delta view)
- Compliance checklist

### 6. Update Dashboard Cloud Tab

Add a new sub-tab "VAPT Reports" to the Cloud section showing historical reports with trend comparison.

## Technical Details

**Edge Function Changes** (`cloud-security-pipeline/index.ts`):
- Add 6 new async scan functions
- Update `SCAN_STAGES` to include all 10 modules
- Add OWASP mapping helper
- Add weighted risk calculation
- Add executive summary auto-generation

**Database Migration**:
- Create `vapt_reports` table with RLS (user owns, owner sees all)
- Add `owasp_category` column to findings JSONB structure
- Update `cloud_scan_pipelines` to support 10 stages (`total_stages` default to 10)

**New Files**:
- `src/components/VAPTReport.tsx` - Full report component
- `src/components/OWASPHeatmap.tsx` - OWASP Top 10 visual mapping
- `src/components/AttackSurfaceRadar.tsx` - Radar chart for attack surface

**Modified Files**:
- `supabase/functions/cloud-security-pipeline/index.ts` - Add 6 modules + scoring
- `src/components/CloudPipelineRunner.tsx` - Enhanced UI with new visualizations
- `src/pages/Dashboard.tsx` - Add VAPT Reports sub-tab

