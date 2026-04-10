import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface Finding {
  id: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  recommendation: string;
  owasp?: string;
  confidence?: number;
  cvss_score?: number;
  cvss_vector?: string;
}

interface FindingChain {
  chain_id: string;
  title: string;
  severity: "critical" | "high" | "medium";
  finding_ids: string[];
  description: string;
  combined_impact: string;
}

const SCAN_STAGES = [
  "deployment", "api", "storage", "infrastructure",
  "dns_recon", "ssl_deep", "auth_session", "info_disclosure", "waf_detection", "injection_surface",
  "http_methods", "client_side_security", "api_discovery", "cloud_metadata"
] as const;

const OWASP_CATEGORIES: Record<string, string> = {
  "A01": "Broken Access Control",
  "A02": "Cryptographic Failures",
  "A03": "Injection",
  "A04": "Insecure Design",
  "A05": "Security Misconfiguration",
  "A06": "Vulnerable Components",
  "A07": "Auth Failures",
  "A08": "Software & Data Integrity",
  "A09": "Logging & Monitoring",
  "A10": "SSRF",
};

const CATEGORY_WEIGHTS: Record<string, number> = {
  "Authentication": 1.5, "Injection": 1.5, "Access Control": 1.4,
  "Transport Security": 1.3, "Cookie Security": 1.2, "CORS": 1.2,
  "Cryptographic": 1.3, "Information Disclosure": 0.8, "Infrastructure": 0.7,
  "DNS Security": 1.0, "SSL/TLS": 1.2, "WAF": 0.9, "Session": 1.3,
  "Data Exposure": 1.4, "Encryption": 1.1, "Rate Limiting": 1.0,
  "Security Headers": 1.0, "Connectivity": 0.5, "Deployment": 0.5,
  "Storage": 0.8, "API Security": 1.1, "HTTP Methods": 1.0,
  "Client-Side": 1.1, "Cloud Security": 1.3, "SSRF": 1.4,
};

function getWeight(category: string): number {
  for (const [key, w] of Object.entries(CATEGORY_WEIGHTS)) {
    if (category.toLowerCase().includes(key.toLowerCase())) return w;
  }
  return 1.0;
}

// CVSS v3.1 base score estimator
function estimateCVSS(finding: Finding): { score: number; vector: string } {
  const sevScores: Record<string, number> = { critical: 9.5, high: 7.5, medium: 5.0, low: 3.0, info: 0.0 };
  let base = sevScores[finding.severity] || 0;
  const conf = (finding.confidence || 80) / 100;
  
  // Attack vector: Network for most web findings
  const av = "N"; // Network
  // Attack complexity
  const ac = finding.confidence && finding.confidence > 80 ? "L" : "H";
  // Privileges required
  const pr = finding.category.includes("Auth") ? "N" : "L";
  // User interaction
  const ui = finding.category.includes("XSS") || finding.category.includes("Client") ? "R" : "N";
  // Scope
  const s = finding.category.includes("Injection") || finding.category.includes("SSRF") ? "C" : "U";
  // CIA impact
  const ci = finding.severity === "critical" ? "H" : finding.severity === "high" ? "H" : "L";
  const ii = finding.severity === "critical" ? "H" : finding.severity === "high" ? "L" : "N";
  const ai = finding.severity === "critical" ? "H" : "N";

  const vector = `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${ci}/I:${ii}/A:${ai}`;
  const score = Math.round(base * conf * 10) / 10;
  
  return { score: Math.min(10, score), vector };
}

// Dangling CNAME targets for subdomain takeover detection
const DANGLING_SIGNATURES = [
  "github.io", "herokuapp.com", "s3.amazonaws.com", "cloudfront.net",
  "azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net",
  "blob.core.windows.net", "pantheonsite.io", "domains.tumblr.com",
  "desk.com", "zendesk.com", "ghost.io", "myshopify.com",
  "statuspage.io", "uservoice.com", "surge.sh", "bitbucket.io",
  "wordpress.com", "teamwork.com", "helpjuice.com", "helpscoutdocs.com",
  "feedpress.me", "freshdesk.com", "ghost.io", "cargocollective.com",
];

// ========== SCAN MODULES ==========

async function scanDeployment(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const res = await fetch(url, { redirect: "manual" });
    const headers = res.headers;

    if (url.startsWith("http://")) {
      findings.push({ id: "dep-https", category: "Transport Security", severity: "critical", title: "No HTTPS Encryption", description: "Deployment not using HTTPS.", recommendation: "Enable HTTPS/TLS.", owasp: "A02", confidence: 100 });
    }

    const secHeaders = [
      { name: "strict-transport-security", id: "dep-hsts", severity: "high" as const, title: "Missing HSTS", owasp: "A05" },
      { name: "content-security-policy", id: "dep-csp", severity: "high" as const, title: "Missing CSP", owasp: "A05" },
      { name: "x-frame-options", id: "dep-xfo", severity: "medium" as const, title: "Missing X-Frame-Options", owasp: "A05" },
      { name: "x-content-type-options", id: "dep-xcto", severity: "medium" as const, title: "Missing X-Content-Type-Options", owasp: "A05" },
      { name: "referrer-policy", id: "dep-ref", severity: "medium" as const, title: "Missing Referrer-Policy", owasp: "A05" },
      { name: "permissions-policy", id: "dep-perm", severity: "medium" as const, title: "Missing Permissions-Policy", owasp: "A05" },
      { name: "x-xss-protection", id: "dep-xxss", severity: "low" as const, title: "Missing X-XSS-Protection", owasp: "A05" },
      { name: "cross-origin-embedder-policy", id: "dep-coep", severity: "low" as const, title: "Missing COEP Header", owasp: "A05" },
      { name: "cross-origin-opener-policy", id: "dep-coop", severity: "low" as const, title: "Missing COOP Header", owasp: "A05" },
      { name: "cross-origin-resource-policy", id: "dep-corp", severity: "low" as const, title: "Missing CORP Header", owasp: "A05" },
    ];

    for (const h of secHeaders) {
      if (!headers.get(h.name)) {
        findings.push({ id: h.id, category: "Security Headers", severity: h.severity, title: h.title, description: `${h.name} header is missing.`, recommendation: `Add ${h.name} header.`, owasp: h.owasp, confidence: 95 });
      }
    }

    // Check CSP quality if present
    const csp = headers.get("content-security-policy");
    if (csp) {
      if (csp.includes("'unsafe-inline'")) {
        findings.push({ id: "dep-csp-inline", category: "Security Headers", severity: "medium", title: "CSP Allows unsafe-inline", description: "CSP permits inline scripts, weakening XSS protection.", recommendation: "Use nonces or hashes instead of unsafe-inline.", owasp: "A05", confidence: 90 });
      }
      if (csp.includes("'unsafe-eval'")) {
        findings.push({ id: "dep-csp-eval", category: "Security Headers", severity: "medium", title: "CSP Allows unsafe-eval", description: "CSP permits eval(), enabling code injection.", recommendation: "Remove unsafe-eval from CSP.", owasp: "A05", confidence: 90 });
      }
      if (csp.includes("*") && !csp.includes("*.")) {
        findings.push({ id: "dep-csp-wildcard", category: "Security Headers", severity: "high", title: "CSP Wildcard Source", description: "CSP uses wildcard (*) allowing any source.", recommendation: "Restrict CSP sources to specific domains.", owasp: "A05", confidence: 85 });
      }
    }

    const server = headers.get("server");
    if (server && (server.includes("/") || server.match(/\d+\.\d+/))) {
      findings.push({ id: "dep-server", category: "Information Disclosure", severity: "low", title: "Server Version Exposed", description: `Server: "${server}"`, recommendation: "Remove or obfuscate Server header.", owasp: "A05", confidence: 90 });
    }

    const cookies = res.headers.get("set-cookie");
    if (cookies) {
      if (!cookies.toLowerCase().includes("secure")) findings.push({ id: "dep-cookie-secure", category: "Cookie Security", severity: "high", title: "Cookie Missing Secure Flag", description: "Cookies sent over insecure connections.", recommendation: "Add Secure flag.", owasp: "A02", confidence: 95 });
      if (!cookies.toLowerCase().includes("httponly")) findings.push({ id: "dep-cookie-http", category: "Cookie Security", severity: "medium", title: "Cookie Missing HttpOnly", description: "Cookies accessible via JS.", recommendation: "Add HttpOnly flag.", owasp: "A05", confidence: 95 });
      if (!cookies.toLowerCase().includes("samesite")) findings.push({ id: "dep-cookie-same", category: "Cookie Security", severity: "medium", title: "Cookie Missing SameSite", description: "CSRF risk.", recommendation: "Add SameSite flag.", owasp: "A01", confidence: 90 });
      // Check for __Host- and __Secure- prefixes
      if (!cookies.includes("__Host-") && !cookies.includes("__Secure-")) {
        findings.push({ id: "dep-cookie-prefix", category: "Cookie Security", severity: "low", title: "No Cookie Prefix Protection", description: "Cookies don't use __Host- or __Secure- prefixes.", recommendation: "Use __Host- or __Secure- cookie prefixes for sensitive cookies.", owasp: "A05", confidence: 70 });
      }
    }

    if (findings.length === 0) findings.push({ id: "dep-ok", category: "Deployment", severity: "info", title: "Deployment Secure", description: "No issues found.", recommendation: "Continue monitoring.", confidence: 100 });
  } catch (err) {
    findings.push({ id: "dep-err", category: "Connectivity", severity: "high", title: "Could Not Reach Deployment", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Verify URL.", confidence: 100 });
  }
  return findings;
}

async function scanApi(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const unauthRes = await fetch(url);
    if (unauthRes.ok) findings.push({ id: "api-noauth", category: "Authentication", severity: "critical", title: "API Without Auth", description: "Returns 200 without authentication.", recommendation: "Require auth for all endpoints.", owasp: "A07", confidence: 80 });

    const corsRes = await fetch(url, { method: "OPTIONS", headers: { Origin: "https://evil.com", "Access-Control-Request-Method": "POST" } });
    const ao = corsRes.headers.get("access-control-allow-origin");
    if (ao === "*") findings.push({ id: "api-cors-wild", category: "CORS", severity: "high", title: "CORS Allows All Origins", description: "Access-Control-Allow-Origin: *", recommendation: "Restrict to trusted origins.", owasp: "A05", confidence: 95 });
    else if (ao === "https://evil.com") findings.push({ id: "api-cors-reflect", category: "CORS", severity: "critical", title: "CORS Origin Reflection", description: "Reflects any origin.", recommendation: "Validate against whitelist.", owasp: "A01", confidence: 95 });

    // Check CORS credentials
    const acCreds = corsRes.headers.get("access-control-allow-credentials");
    if (acCreds === "true" && (ao === "*" || ao === "https://evil.com")) {
      findings.push({ id: "api-cors-creds", category: "CORS", severity: "critical", title: "CORS Credentials with Wild Origin", description: "Allows credentials from any origin — full account takeover risk.", recommendation: "Never combine Access-Control-Allow-Credentials with wildcard origin.", owasp: "A01", confidence: 95 });
    }

    const rl = unauthRes.headers;
    if (!rl.get("x-ratelimit-limit") && !rl.get("ratelimit-limit") && !rl.get("retry-after")) {
      findings.push({ id: "api-norate", category: "Rate Limiting", severity: "high", title: "No Rate Limiting", description: "No rate limit headers.", recommendation: "Implement rate limiting.", owasp: "A04", confidence: 70 });
    }

    try {
      const errRes = await fetch(url + "/<script>alert(1)</script>");
      const errBody = await errRes.text();
      if (errBody.includes("<script>alert(1)</script>")) findings.push({ id: "api-xss", category: "Injection", severity: "critical", title: "XSS in Error Response", description: "Reflects input unsanitized.", recommendation: "Sanitize all output.", owasp: "A03", confidence: 90 });
      if (errBody.includes("stack") || errBody.includes("at /")) findings.push({ id: "api-stack", category: "Information Disclosure", severity: "high", title: "Stack Trace Exposed", description: "Leaks internals.", recommendation: "Use generic errors in production.", owasp: "A05", confidence: 85 });
    } catch {}

    // Check for API versioning
    const body = await (await fetch(url)).text();
    if (!url.includes("/v1") && !url.includes("/v2") && !body.includes('"version"')) {
      findings.push({ id: "api-noversion", category: "API Security", severity: "low", title: "No API Versioning Detected", description: "API does not appear to use versioning.", recommendation: "Implement API versioning for backward compatibility.", owasp: "A04", confidence: 50 });
    }

    if (findings.length === 0) findings.push({ id: "api-ok", category: "API Security", severity: "info", title: "API Secure", description: "No issues found.", recommendation: "Continue monitoring.", confidence: 100 });
  } catch (err) {
    findings.push({ id: "api-err", category: "Connectivity", severity: "high", title: "Could Not Reach API", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Verify URL.", confidence: 100 });
  }
  return findings;
}

async function scanStorage(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const res = await fetch(url);
    if (res.ok) findings.push({ id: "sto-public", category: "Access Control", severity: "critical", title: "Storage Publicly Accessible", description: "No auth required.", recommendation: "Restrict with IAM/signed URLs.", owasp: "A01", confidence: 75 });

    const body = await res.text();
    if (body.includes("<ListBucketResult") || body.includes("<Contents>")) findings.push({ id: "sto-listing", category: "Access Control", severity: "critical", title: "Bucket Listing Enabled", description: "All files exposed.", recommendation: "Disable listing.", owasp: "A01", confidence: 95 });

    const sensitive = [".env", "config.json", "credentials", ".pem", ".key", "secret", ".pfx", ".p12", "id_rsa"];
    const found = sensitive.filter(p => body.toLowerCase().includes(p));
    if (found.length > 0) findings.push({ id: "sto-sensitive", category: "Data Exposure", severity: "critical", title: "Sensitive Files Found", description: `Found: ${found.join(", ")}`, recommendation: "Remove and rotate credentials.", owasp: "A02", confidence: 85 });

    if (res.headers.get("access-control-allow-origin") === "*") findings.push({ id: "sto-cors", category: "CORS", severity: "medium", title: "Storage CORS Open", description: "Allows all origins.", recommendation: "Restrict CORS.", owasp: "A05", confidence: 90 });

    if (!res.headers.get("x-amz-server-side-encryption") && !res.headers.get("x-goog-encryption-algorithm") && res.ok) {
      findings.push({ id: "sto-encrypt", category: "Encryption", severity: "medium", title: "No Encryption Detected", description: "May not be encrypted at rest.", recommendation: "Enable SSE.", owasp: "A02", confidence: 60 });
    }

    if (findings.length === 0) findings.push({ id: "sto-ok", category: "Storage", severity: "info", title: "Storage Secure", description: "No issues.", recommendation: "Continue auditing.", confidence: 100 });
  } catch {
    findings.push({ id: "sto-ok", category: "Storage", severity: "info", title: "Storage Not Public", description: "Could not access publicly — good.", recommendation: "Verify authorized access.", confidence: 100 });
  }
  return findings;
}

async function scanInfrastructure(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const res = await fetch(url, { redirect: "manual" });
    const headers = res.headers;
    const allH = `${headers.get("server") || ""} ${headers.get("via") || ""} ${headers.get("x-powered-by") || ""}`.toLowerCase();

    const providers = [
      { p: /cloudflare/i, n: "Cloudflare" }, { p: /amazonaws|cloudfront/i, n: "AWS" },
      { p: /google|gws/i, n: "Google Cloud" }, { p: /azure/i, n: "Azure" },
      { p: /vercel/i, n: "Vercel" }, { p: /netlify/i, n: "Netlify" },
      { p: /digitalocean/i, n: "DigitalOcean" }, { p: /heroku/i, n: "Heroku" },
    ];
    const detected = providers.find(pr => pr.p.test(allH));
    if (detected) findings.push({ id: "inf-provider", category: "Infrastructure", severity: "info", title: `Provider: ${detected.n}`, description: `Hosted on ${detected.n}.`, recommendation: "Follow provider security best practices.", confidence: 85 });

    const xpb = headers.get("x-powered-by");
    if (xpb) findings.push({ id: "inf-xpowered", category: "Information Disclosure", severity: "medium", title: "X-Powered-By Exposed", description: `Reveals: ${xpb}`, recommendation: "Remove header.", owasp: "A05", confidence: 95 });

    // Check X-AspNet-Version
    const aspnet = headers.get("x-aspnet-version") || headers.get("x-aspnetmvc-version");
    if (aspnet) findings.push({ id: "inf-aspnet", category: "Information Disclosure", severity: "medium", title: "ASP.NET Version Exposed", description: `Reveals: ${aspnet}`, recommendation: "Remove X-AspNet-Version header.", owasp: "A05", confidence: 95 });

    if (url.startsWith("https://")) findings.push({ id: "inf-tls", category: "Transport", severity: "info", title: "TLS Enabled", description: "HTTPS active.", recommendation: "Ensure TLS 1.2+.", confidence: 100 });
    else findings.push({ id: "inf-notls", category: "Transport", severity: "critical", title: "No TLS/HTTPS", description: "Not using HTTPS.", recommendation: "Enable immediately.", owasp: "A02", confidence: 100 });

    if (res.status >= 300 && res.status < 400) {
      const loc = headers.get("location");
      if (loc?.startsWith("http://")) findings.push({ id: "inf-redirect", category: "Transport", severity: "high", title: "Redirect to HTTP", description: "Redirects insecurely.", recommendation: "Redirect to HTTPS only.", owasp: "A02", confidence: 95 });
    }

    const adminPaths = ["/admin", "/wp-admin", "/console", "/_admin", "/administrator", "/manage", "/cpanel", "/phpmyadmin"];
    for (const path of adminPaths) {
      try {
        const r = await fetch(`${url.replace(/\/$/, "")}${path}`, { redirect: "manual" });
        if (r.status === 200) { findings.push({ id: `inf-admin-${path.replace(/\//g, "")}`, category: "Access Control", severity: "high", title: `Admin Panel: ${path}`, description: "Publicly accessible.", recommendation: "Restrict access.", owasp: "A01", confidence: 80 }); break; }
      } catch {}
    }

    if (findings.length === 0) findings.push({ id: "inf-ok", category: "Infrastructure", severity: "info", title: "Infrastructure Secure", description: "No issues.", recommendation: "Continue monitoring.", confidence: 100 });
  } catch (err) {
    findings.push({ id: "inf-err", category: "Connectivity", severity: "high", title: "Unreachable", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Check DNS/connectivity.", confidence: 100 });
  }
  return findings;
}

// ========== ADVANCED SCAN MODULES (DEEPENED) ==========

async function scanDnsRecon(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const hostname = new URL(url).hostname;

    const dnsTypes = ["MX", "TXT", "NS", "AAAA", "CAA"];
    for (const type of dnsTypes) {
      try {
        const dnsRes = await fetch(`https://dns.google/resolve?name=${hostname}&type=${type}`);
        const dns = await dnsRes.json();
        if (dns.Answer) {
          if (type === "TXT") {
            const txtRecords = dns.Answer.map((a: any) => a.data).join(" ");
            if (!txtRecords.includes("v=spf1")) {
              findings.push({ id: "dns-nospf", category: "DNS Security", severity: "medium", title: "Missing SPF Record", description: "No SPF record found. Email spoofing possible.", recommendation: "Add SPF TXT record.", owasp: "A05", confidence: 90 });
            } else if (txtRecords.includes("v=spf1 +all")) {
              findings.push({ id: "dns-spf-permissive", category: "DNS Security", severity: "high", title: "SPF Too Permissive (+all)", description: "SPF record allows any server to send email.", recommendation: "Change +all to ~all or -all.", owasp: "A05", confidence: 95 });
            }
            if (!txtRecords.includes("v=DMARC1")) {
              try {
                const dmarcRes = await fetch(`https://dns.google/resolve?name=_dmarc.${hostname}&type=TXT`);
                const dmarc = await dmarcRes.json();
                const dmarcTxt = dmarc.Answer?.map((a: any) => a.data).join(" ") || "";
                if (!dmarcTxt.includes("v=DMARC1")) {
                  findings.push({ id: "dns-nodmarc", category: "DNS Security", severity: "medium", title: "Missing DMARC Record", description: "No DMARC policy. Email domain can be spoofed.", recommendation: "Add DMARC TXT record.", owasp: "A05", confidence: 90 });
                } else if (dmarcTxt.includes("p=none")) {
                  findings.push({ id: "dns-dmarc-none", category: "DNS Security", severity: "low", title: "DMARC Policy Set to None", description: "DMARC exists but only monitors, doesn't reject.", recommendation: "Upgrade DMARC policy to quarantine or reject.", owasp: "A05", confidence: 85 });
                }
              } catch {}
            }
          }

          if (type === "CAA") {
            // CAA records found — good
            findings.push({ id: "dns-caa", category: "DNS Security", severity: "info", title: "CAA Records Present", description: "Certificate Authority Authorization restricts who can issue certs.", recommendation: "Keep CAA records up to date.", confidence: 90 });
          }

          if (type === "MX") {
            const mxRecords = dns.Answer.map((a: any) => a.data?.toLowerCase() || "");
            // Check for open relay indicators
            if (mxRecords.some((mx: string) => mx.includes("localhost") || mx.includes("127.0.0.1"))) {
              findings.push({ id: "dns-mx-localhost", category: "DNS Security", severity: "high", title: "MX Points to Localhost", description: "MX record points to localhost — misconfiguration or open relay risk.", recommendation: "Fix MX record to point to a proper mail server.", owasp: "A05", confidence: 90 });
            }
          }

          if (type === "NS") {
            const nsRecords = dns.Answer.map((a: any) => a.data?.toLowerCase() || "");
            // Check NS delegation consistency
            if (nsRecords.length === 1) {
              findings.push({ id: "dns-single-ns", category: "DNS Security", severity: "medium", title: "Single NS Record", description: "Only one nameserver — no redundancy.", recommendation: "Add at least 2 nameservers for DNS resilience.", owasp: "A05", confidence: 85 });
            }
          }
        } else if (type === "CAA") {
          findings.push({ id: "dns-no-caa", category: "DNS Security", severity: "low", title: "No CAA Records", description: "No CAA records restrict certificate issuance.", recommendation: "Add CAA records to restrict certificate authorities.", owasp: "A05", confidence: 80 });
        }
      } catch {}
    }

    // DNSSEC check
    try {
      const dnssecRes = await fetch(`https://dns.google/resolve?name=${hostname}&type=DNSKEY`);
      const dnssec = await dnssecRes.json();
      if (!dnssec.Answer || dnssec.Answer.length === 0) {
        findings.push({ id: "dns-nodnssec", category: "DNS Security", severity: "low", title: "DNSSEC Not Enabled", description: "Domain does not use DNSSEC.", recommendation: "Enable DNSSEC with your registrar.", owasp: "A05", confidence: 85 });
      }
    } catch {}

    // Wildcard DNS check
    try {
      const wildcard = `random-${Date.now()}.${hostname}`;
      const wcRes = await fetch(`https://dns.google/resolve?name=${wildcard}&type=A`);
      const wc = await wcRes.json();
      if (wc.Answer && wc.Answer.length > 0) {
        findings.push({ id: "dns-wildcard", category: "DNS Security", severity: "medium", title: "Wildcard DNS Detected", description: "*.domain resolves — may allow subdomain takeover or phishing.", recommendation: "Remove wildcard DNS unless intentional.", owasp: "A05", confidence: 75 });
      }
    } catch {}

    // Dangling CNAME / subdomain takeover check
    const subdomains = ["www", "mail", "staging", "dev", "api", "cdn", "app", "test", "beta", "admin"];
    for (const sub of subdomains.slice(0, 5)) {
      try {
        const cnameRes = await fetch(`https://dns.google/resolve?name=${sub}.${hostname}&type=CNAME`);
        const cname = await cnameRes.json();
        if (cname.Answer) {
          const target = cname.Answer[0]?.data?.replace(/\.$/, "");
          if (target) {
            // Check against known dangling signatures
            const isDanglingTarget = DANGLING_SIGNATURES.some(sig => target.includes(sig));
            if (isDanglingTarget) {
              try {
                const checkRes = await fetch(`https://${target}`, { redirect: "manual", signal: AbortSignal.timeout(5000) });
                if (checkRes.status === 404 || checkRes.status === 0) {
                  findings.push({ id: `dns-takeover-${sub}`, category: "DNS Security", severity: "critical", title: `Subdomain Takeover: ${sub}.${hostname}`, description: `CNAME to ${target} appears unclaimed. Attacker can claim this service.`, recommendation: "Remove dangling CNAME or claim the resource immediately.", owasp: "A05", confidence: 75 });
                }
              } catch {
                findings.push({ id: `dns-dangling-${sub}`, category: "DNS Security", severity: "high", title: `Potential Subdomain Takeover: ${sub}`, description: `${sub}.${hostname} has CNAME to ${target} which may be unclaimed.`, recommendation: "Remove dangling CNAME or claim the resource.", owasp: "A05", confidence: 60 });
              }
            }
          }
        }
      } catch {}
    }

    if (findings.length === 0) findings.push({ id: "dns-ok", category: "DNS Security", severity: "info", title: "DNS Configuration Secure", description: "DNS records properly configured.", recommendation: "Continue monitoring DNS.", confidence: 100 });
  } catch (err) {
    findings.push({ id: "dns-err", category: "DNS Security", severity: "info", title: "DNS Scan Limited", description: `Could not fully analyze DNS: ${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Manual DNS review recommended.", confidence: 50 });
  }
  return findings;
}

async function scanSslDeep(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const hostname = new URL(url).hostname;

    if (!url.startsWith("https://")) {
      findings.push({ id: "ssl-nossl", category: "SSL/TLS", severity: "critical", title: "No SSL/TLS", description: "Site does not use HTTPS.", recommendation: "Enable HTTPS immediately.", owasp: "A02", confidence: 100 });
      return findings;
    }

    const res = await fetch(url);
    const headers = res.headers;
    const body = await res.text();

    // HSTS deep analysis
    const hsts = headers.get("strict-transport-security");
    if (hsts) {
      const maxAge = hsts.match(/max-age=(\d+)/);
      if (maxAge && parseInt(maxAge[1]) < 31536000) {
        findings.push({ id: "ssl-hsts-short", category: "SSL/TLS", severity: "medium", title: "HSTS Max-Age Too Short", description: `HSTS max-age is ${maxAge[1]}s (< 1 year).`, recommendation: "Set max-age to at least 31536000 (1 year).", owasp: "A02", confidence: 90 });
      }
      if (!hsts.includes("includeSubDomains")) {
        findings.push({ id: "ssl-hsts-nosub", category: "SSL/TLS", severity: "low", title: "HSTS Missing includeSubDomains", description: "Subdomains not covered by HSTS.", recommendation: "Add includeSubDomains directive.", owasp: "A02", confidence: 85 });
      }
      if (!hsts.includes("preload")) {
        findings.push({ id: "ssl-hsts-nopreload", category: "SSL/TLS", severity: "info", title: "HSTS Not Preloaded", description: "Not in browser HSTS preload list.", recommendation: "Consider adding preload directive.", owasp: "A02", confidence: 80 });
      }
    }

    // Mixed content detection
    const httpResources = body.match(/src=["']http:\/\//gi) || [];
    const httpLinks = body.match(/href=["']http:\/\/[^"']*\.(js|css)/gi) || [];
    if (httpResources.length > 0 || httpLinks.length > 0) {
      findings.push({ id: "ssl-mixed", category: "SSL/TLS", severity: "high", title: "Mixed Content Detected", description: `${httpResources.length + httpLinks.length} HTTP resources loaded on HTTPS page.`, recommendation: "Ensure all resources use HTTPS.", owasp: "A02", confidence: 90 });
    }

    // CT log and cert analysis
    try {
      const ctRes = await fetch(`https://crt.sh/?q=${hostname}&output=json`, { signal: AbortSignal.timeout(5000) });
      if (ctRes.ok) {
        const certs = await ctRes.json();
        if (Array.isArray(certs) && certs.length > 0) {
          const now = new Date();
          const expiredActive = certs.filter((c: any) => new Date(c.not_after) < now).slice(0, 5);
          if (expiredActive.length > 3) {
            findings.push({ id: "ssl-expired-certs", category: "SSL/TLS", severity: "info", title: "Multiple Expired Certificates", description: `${expiredActive.length} expired certificates in CT logs.`, recommendation: "Clean up old certificates.", confidence: 70 });
          }

          const wildcards = certs.filter((c: any) => c.common_name?.startsWith("*."));
          if (wildcards.length > 0) {
            findings.push({ id: "ssl-wildcard", category: "SSL/TLS", severity: "info", title: "Wildcard Certificate in Use", description: `Wildcard cert found for *.${hostname}.`, recommendation: "Consider individual certs for better security isolation.", confidence: 75 });
          }

          // SAN enumeration
          const recentCert = certs[0];
          if (recentCert?.name_value) {
            const sans = recentCert.name_value.split("\n").filter((s: string) => s && s !== hostname);
            if (sans.length > 5) {
              findings.push({ id: "ssl-many-sans", category: "SSL/TLS", severity: "info", title: `${sans.length} SANs on Certificate`, description: `Certificate covers multiple domains: ${sans.slice(0, 5).join(", ")}...`, recommendation: "Review if all SANs are still needed.", confidence: 70 });
            }
          }
        }
      }
    } catch {}

    // TLS downgrade test - attempt HTTP to see if it redirects
    try {
      const httpRes = await fetch(`http://${hostname}`, { redirect: "manual", signal: AbortSignal.timeout(5000) });
      if (httpRes.status === 200) {
        findings.push({ id: "ssl-no-redirect", category: "SSL/TLS", severity: "high", title: "HTTP Not Redirected to HTTPS", description: "HTTP version serves content without redirecting to HTTPS.", recommendation: "Configure HTTP to HTTPS redirect.", owasp: "A02", confidence: 90 });
      }
    } catch {}

    // Check alternate ports
    try {
      const alt = await fetch(`https://${hostname}:8443`, { signal: AbortSignal.timeout(3000) });
      if (alt.ok) {
        findings.push({ id: "ssl-alt-port", category: "SSL/TLS", severity: "info", title: "Service on Port 8443", description: "HTTPS service found on alternate port 8443.", recommendation: "Ensure alternate port services are equally secured.", confidence: 70 });
      }
    } catch {}

    if (findings.length === 0) findings.push({ id: "ssl-ok", category: "SSL/TLS", severity: "info", title: "SSL/TLS Configuration Strong", description: "No SSL/TLS issues detected.", recommendation: "Continue monitoring certificate expiry.", confidence: 100 });
  } catch (err) {
    findings.push({ id: "ssl-err", category: "SSL/TLS", severity: "medium", title: "SSL Analysis Limited", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Manual SSL review recommended.", confidence: 50 });
  }
  return findings;
}

async function scanAuthSession(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const baseUrl = url.replace(/\/$/, "");
  try {
    // Test common login/auth endpoints
    const authPaths = ["/login", "/api/auth", "/auth/login", "/api/login", "/signin", "/api/signin"];
    for (const path of authPaths) {
      try {
        const res = await fetch(`${baseUrl}${path}`, { redirect: "manual" });
        if (res.status === 200 || res.status === 301 || res.status === 302) {
          findings.push({ id: `auth-endpoint-${path.replace(/\//g, "")}`, category: "Authentication", severity: "info", title: `Auth Endpoint Found: ${path}`, description: `Login endpoint discovered at ${path}.`, recommendation: "Ensure strong authentication and brute-force protection.", owasp: "A07", confidence: 70 });

          // Check for CAPTCHA
          if (res.status === 200) {
            const body = await res.text();
            if (!body.includes("captcha") && !body.includes("recaptcha") && !body.includes("hcaptcha") && !body.includes("turnstile")) {
              findings.push({ id: "auth-no-captcha", category: "Authentication", severity: "medium", title: "No CAPTCHA on Login", description: "Login form lacks CAPTCHA protection.", recommendation: "Add CAPTCHA to prevent automated attacks.", owasp: "A07", confidence: 65 });
            }
            // Check for 2FA/MFA indicators
            if (!body.includes("two-factor") && !body.includes("2fa") && !body.includes("mfa") && !body.includes("authenticator") && !body.includes("otp")) {
              findings.push({ id: "auth-no-mfa", category: "Authentication", severity: "medium", title: "No MFA/2FA Indicators", description: "Login page shows no multi-factor authentication options.", recommendation: "Implement MFA/2FA for enhanced account security.", owasp: "A07", confidence: 50 });
            }
          }
          break;
        }
      } catch {}
    }

    // Check for username enumeration
    try {
      const validRes = await fetch(`${baseUrl}/api/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "admin@test.com", password: "wrong" }),
        redirect: "manual",
      });
      const invalidRes = await fetch(`${baseUrl}/api/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "nonexistent-user-xyz@test.com", password: "wrong" }),
        redirect: "manual",
      });
      if (validRes.status !== invalidRes.status) {
        findings.push({ id: "auth-enum", category: "Authentication", severity: "medium", title: "Username Enumeration Possible", description: "Different responses for valid vs invalid usernames.", recommendation: "Return identical responses for both cases.", owasp: "A07", confidence: 60 });
      }
    } catch {}

    // Check for JWT and API key exposure in page source
    try {
      const mainRes = await fetch(url);
      const body = await mainRes.text();

      const jwtPattern = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/;
      if (jwtPattern.test(body)) {
        findings.push({ id: "auth-jwt-exposed", category: "Session", severity: "high", title: "JWT Token Exposed in Page Source", description: "A JWT token was found in the HTML source.", recommendation: "Never embed tokens in HTML. Use HttpOnly cookies.", owasp: "A07", confidence: 85 });
      }

      if (body.match(/[?&](session|sid|token|auth)=[a-zA-Z0-9]{10,}/i)) {
        findings.push({ id: "auth-session-url", category: "Session", severity: "high", title: "Session Token in URL Parameters", description: "Session identifiers found in URL query parameters.", recommendation: "Use cookies or headers for session management.", owasp: "A07", confidence: 80 });
      }

      if (body.includes("client_secret") || body.includes("client_id")) {
        findings.push({ id: "auth-oauth-leak", category: "Authentication", severity: "critical", title: "OAuth Credentials in Source", description: "OAuth client_id or client_secret found in page source.", recommendation: "Move OAuth secrets to server-side.", owasp: "A07", confidence: 85 });
      }

      // Detect exposed API keys
      const apiKeyPatterns = [
        { pattern: /AKIA[0-9A-Z]{16}/g, name: "AWS Access Key", severity: "critical" as const },
        { pattern: /AIza[0-9A-Za-z_-]{35}/g, name: "Google API Key", severity: "high" as const },
        { pattern: /sk_live_[0-9a-zA-Z]{24,}/g, name: "Stripe Secret Key", severity: "critical" as const },
        { pattern: /pk_live_[0-9a-zA-Z]{24,}/g, name: "Stripe Publishable Key", severity: "low" as const },
        { pattern: /ghp_[0-9a-zA-Z]{36}/g, name: "GitHub Personal Access Token", severity: "critical" as const },
        { pattern: /sk-[a-zA-Z0-9]{48}/g, name: "OpenAI API Key", severity: "high" as const },
      ];
      for (const { pattern, name, severity } of apiKeyPatterns) {
        if (pattern.test(body)) {
          findings.push({ id: `auth-apikey-${name.toLowerCase().replace(/\s/g, "")}`, category: "Data Exposure", severity, title: `${name} Exposed in Source`, description: `A ${name} was found in the page source.`, recommendation: "Remove API key from client-side code immediately.", owasp: "A02", confidence: 85 });
        }
      }
    } catch {}

    // Check password reset endpoints
    const resetPaths = ["/reset-password", "/forgot-password", "/api/reset", "/api/forgot-password"];
    for (const path of resetPaths) {
      try {
        const res = await fetch(`${baseUrl}${path}`, { redirect: "manual" });
        if (res.status === 200) {
          if (!res.headers.get("x-ratelimit-limit") && !res.headers.get("retry-after")) {
            findings.push({ id: "auth-reset-norate", category: "Authentication", severity: "medium", title: "Password Reset Without Rate Limit", description: `${path} has no visible rate limiting.`, recommendation: "Add rate limiting to password reset.", owasp: "A07", confidence: 65 });
          }
          break;
        }
      } catch {}
    }

    if (findings.length === 0) findings.push({ id: "auth-ok", category: "Authentication", severity: "info", title: "Auth Configuration Adequate", description: "No obvious authentication issues.", recommendation: "Conduct manual auth testing.", confidence: 100 });
  } catch (err) {
    findings.push({ id: "auth-err", category: "Authentication", severity: "info", title: "Auth Scan Limited", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Manual auth review recommended.", confidence: 50 });
  }
  return findings;
}

async function scanInfoDisclosure(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const baseUrl = url.replace(/\/$/, "");
  try {
    // robots.txt
    try {
      const robotsRes = await fetch(`${baseUrl}/robots.txt`);
      if (robotsRes.ok) {
        const robots = await robotsRes.text();
        const disallowed = robots.match(/Disallow:\s*(.+)/gi) || [];
        const sensitive = disallowed.filter(d => /admin|backup|config|secret|internal|private|api|debug/i.test(d));
        if (sensitive.length > 0) {
          findings.push({ id: "info-robots", category: "Information Disclosure", severity: "low", title: "Sensitive Paths in robots.txt", description: `robots.txt reveals: ${sensitive.slice(0, 5).join(", ")}`, recommendation: "Review if these paths need to be in robots.txt.", owasp: "A05", confidence: 80 });
        }
      }
    } catch {}

    // Exposed config/source files
    const exposedFiles = [
      { path: "/.git/HEAD", id: "info-git", title: "Git Repository Exposed", severity: "critical" as const },
      { path: "/.env", id: "info-env", title: ".env File Exposed", severity: "critical" as const },
      { path: "/.svn/entries", id: "info-svn", title: "SVN Repository Exposed", severity: "critical" as const },
      { path: "/wp-config.php.bak", id: "info-wpbak", title: "WordPress Config Backup", severity: "critical" as const },
      { path: "/config.json", id: "info-config", title: "Config File Exposed", severity: "high" as const },
      { path: "/package.json", id: "info-package", title: "package.json Exposed", severity: "low" as const },
      { path: "/composer.json", id: "info-composer", title: "composer.json Exposed", severity: "low" as const },
      { path: "/.DS_Store", id: "info-dsstore", title: ".DS_Store File Exposed", severity: "low" as const },
      { path: "/backup.sql", id: "info-sqlbak", title: "SQL Backup Exposed", severity: "critical" as const },
      { path: "/database.sql", id: "info-dbsql", title: "Database Dump Exposed", severity: "critical" as const },
      { path: "/.htaccess", id: "info-htaccess", title: ".htaccess Exposed", severity: "medium" as const },
      { path: "/web.config", id: "info-webconfig", title: "web.config Exposed", severity: "medium" as const },
      { path: "/Dockerfile", id: "info-dockerfile", title: "Dockerfile Exposed", severity: "medium" as const },
      { path: "/docker-compose.yml", id: "info-docker", title: "docker-compose.yml Exposed", severity: "high" as const },
    ];

    for (const file of exposedFiles) {
      try {
        const res = await fetch(`${baseUrl}${file.path}`, { redirect: "manual" });
        if (res.status === 200) {
          const body = await res.text();
          if (body.length > 5 && !body.toLowerCase().includes("not found") && !body.toLowerCase().includes("404")) {
            findings.push({ id: file.id, category: "Information Disclosure", severity: file.severity, title: file.title, description: `${file.path} is accessible.`, recommendation: "Block access to this file.", owasp: "A05", confidence: 85 });
          }
        }
      } catch {}
    }

    // security.txt
    try {
      const secRes = await fetch(`${baseUrl}/.well-known/security.txt`);
      if (!secRes.ok) {
        findings.push({ id: "info-no-security-txt", category: "Information Disclosure", severity: "info", title: "No security.txt Found", description: "No /.well-known/security.txt file for responsible disclosure.", recommendation: "Add a security.txt with contact information.", owasp: "A09", confidence: 80 });
      }
    } catch {}

    // Source maps
    try {
      const mainRes = await fetch(url);
      const html = await mainRes.text();
      const jsFiles = html.match(/src=["'][^"']*\.js["']/gi) || [];
      for (const jsMatch of jsFiles.slice(0, 3)) {
        const jsSrc = jsMatch.match(/src=["']([^"']+)["']/)?.[1];
        if (jsSrc) {
          const jsUrl = jsSrc.startsWith("http") ? jsSrc : `${baseUrl}${jsSrc.startsWith("/") ? "" : "/"}${jsSrc}`;
          try {
            const mapRes = await fetch(`${jsUrl}.map`, { redirect: "manual" });
            if (mapRes.ok) {
              const mapBody = await mapRes.text();
              if (mapBody.includes('"sources"') || mapBody.includes('"mappings"')) {
                findings.push({ id: "info-sourcemap", category: "Information Disclosure", severity: "medium", title: "Source Maps Exposed", description: "JavaScript source maps are publicly accessible, revealing original source code.", recommendation: "Remove source maps from production.", owasp: "A05", confidence: 90 });
                break;
              }
            }
          } catch {}
        }
      }

      // Debug mode indicators
      if (html.includes("DEBUG=true") || html.includes("debug=true") || html.includes("__REDUX_DEVTOOLS_EXTENSION__")) {
        findings.push({ id: "info-debug", category: "Information Disclosure", severity: "medium", title: "Debug Mode Indicators", description: "Debug mode or dev tools detected in page source.", recommendation: "Disable debug mode in production.", owasp: "A05", confidence: 70 });
      }

      // Generator meta tag
      const generatorMatch = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
      if (generatorMatch) {
        findings.push({ id: "info-generator", category: "Information Disclosure", severity: "low", title: `Technology Revealed: ${generatorMatch[1]}`, description: `Generator meta tag reveals: ${generatorMatch[1]}`, recommendation: "Remove generator meta tag.", owasp: "A05", confidence: 90 });
      }

      // Email harvesting
      const emails = html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
      if (emails && emails.length > 3) {
        const unique = [...new Set(emails)];
        findings.push({ id: "info-emails", category: "Information Disclosure", severity: "low", title: "Email Addresses Exposed", description: `${unique.length} unique email(s) found in page source.`, recommendation: "Obfuscate email addresses to prevent scraping.", owasp: "A05", confidence: 75 });
      }
    } catch {}

    // Check X-Debug-Token header
    try {
      const res = await fetch(url);
      if (res.headers.get("x-debug-token") || res.headers.get("x-debug-token-link")) {
        findings.push({ id: "info-debug-token", category: "Information Disclosure", severity: "high", title: "Debug Token Header Exposed", description: "X-Debug-Token header reveals debug profiler access.", recommendation: "Disable debug toolbar in production.", owasp: "A05", confidence: 90 });
      }
    } catch {}

    // OpenID configuration
    try {
      const oidcRes = await fetch(`${baseUrl}/.well-known/openid-configuration`);
      if (oidcRes.ok) {
        findings.push({ id: "info-oidc", category: "Information Disclosure", severity: "info", title: "OpenID Configuration Exposed", description: "OpenID Connect configuration is publicly accessible.", recommendation: "Review if all exposed endpoints are intended to be public.", owasp: "A05", confidence: 85 });
      }
    } catch {}

    // Sitemap analysis
    try {
      const sitemapRes = await fetch(`${baseUrl}/sitemap.xml`);
      if (sitemapRes.ok) {
        const sitemap = await sitemapRes.text();
        if (sitemap.includes("<url>")) {
          const adminUrls = sitemap.match(/<loc>[^<]*(admin|internal|dashboard|manage)[^<]*<\/loc>/gi);
          if (adminUrls && adminUrls.length > 0) {
            findings.push({ id: "info-sitemap", category: "Information Disclosure", severity: "low", title: "Admin URLs in Sitemap", description: `Sitemap exposes admin-like URLs.`, recommendation: "Exclude admin paths from sitemap.xml.", owasp: "A05", confidence: 70 });
          }
        }
      }
    } catch {}

    if (findings.length === 0) findings.push({ id: "info-ok", category: "Information Disclosure", severity: "info", title: "No Info Leaks Detected", description: "No sensitive files or data exposed.", recommendation: "Continue monitoring.", confidence: 100 });
  } catch (err) {
    findings.push({ id: "info-err", category: "Information Disclosure", severity: "info", title: "Info Disclosure Scan Limited", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Manual review recommended.", confidence: 50 });
  }
  return findings;
}

async function scanWafDetection(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const res = await fetch(url, { redirect: "manual" });
    const headers = res.headers;
    const allHeaders = [...headers.entries()].map(([k, v]) => `${k}: ${v}`).join("\n").toLowerCase();

    const wafSignatures = [
      { pattern: /cloudflare/i, name: "Cloudflare", header: "cf-ray" },
      { pattern: /aws/i, name: "AWS WAF", header: "x-amzn-waf" },
      { pattern: /akamai/i, name: "Akamai", header: "x-akamai" },
      { pattern: /sucuri/i, name: "Sucuri", header: "x-sucuri" },
      { pattern: /imperva|incapsula/i, name: "Imperva/Incapsula", header: "x-iinfo" },
      { pattern: /f5|big-?ip/i, name: "F5 BIG-IP", header: "x-cnection" },
      { pattern: /barracuda/i, name: "Barracuda", header: "barra_counter" },
      { pattern: /fortinet|fortigate/i, name: "Fortinet", header: "fortigate" },
      { pattern: /modsecurity/i, name: "ModSecurity", header: "x-modsecurity" },
      { pattern: /azure.*front.*door/i, name: "Azure Front Door", header: "x-azure-ref" },
      { pattern: /aws.*shield/i, name: "AWS Shield", header: "x-amz-cf-pop" },
    ];

    let wafDetected = false;
    for (const waf of wafSignatures) {
      if (waf.pattern.test(allHeaders) || headers.get(waf.header)) {
        findings.push({ id: `waf-${waf.name.toLowerCase().replace(/[\s/]/g, "")}`, category: "WAF", severity: "info", title: `WAF Detected: ${waf.name}`, description: `${waf.name} WAF/CDN is protecting this application.`, recommendation: "Ensure WAF rules are up to date.", confidence: 85 });
        wafDetected = true;
        break;
      }
    }

    if (headers.get("cf-ray") && !wafDetected) {
      findings.push({ id: "waf-cloudflare", category: "WAF", severity: "info", title: "WAF Detected: Cloudflare", description: "Cloudflare is active.", recommendation: "Review Cloudflare security settings.", confidence: 95 });
      wafDetected = true;
    }

    if (!wafDetected) {
      findings.push({ id: "waf-none", category: "WAF", severity: "high", title: "No WAF Detected", description: "No Web Application Firewall detected. Application is directly exposed.", recommendation: "Deploy a WAF (e.g., Cloudflare, AWS WAF) to protect against common attacks.", owasp: "A05", confidence: 70 });
    }

    // WAF bypass/evasion tests
    if (wafDetected) {
      // Standard SQLi
      try {
        const sqliRes = await fetch(`${url}?id=1%20OR%201%3D1`, { redirect: "manual" });
        if (sqliRes.status !== 403 && sqliRes.status !== 406 && sqliRes.status !== 429) {
          findings.push({ id: "waf-bypass-sqli", category: "WAF", severity: "medium", title: "WAF May Not Block SQLi Patterns", description: "Basic SQL injection pattern was not blocked.", recommendation: "Review and tighten WAF rules.", owasp: "A03", confidence: 55 });
        }
      } catch {}

      // Encoded bypass
      try {
        const encodedRes = await fetch(`${url}?id=1%252f%252a%252a%252fOR%252f%252a%252a%252f1%3D1`, { redirect: "manual" });
        if (encodedRes.status !== 403 && encodedRes.status !== 406) {
          findings.push({ id: "waf-bypass-encode", category: "WAF", severity: "medium", title: "WAF Bypass via Double Encoding", description: "Double-encoded payload was not blocked.", recommendation: "Enable double-decoding in WAF rules.", owasp: "A03", confidence: 50 });
        }
      } catch {}

      // Case variation
      try {
        const caseRes = await fetch(`${url}?q=<ScRiPt>alert(1)</ScRiPt>`, { redirect: "manual" });
        if (caseRes.status !== 403) {
          const body = await caseRes.text();
          if (body.includes("<ScRiPt>")) {
            findings.push({ id: "waf-bypass-case", category: "WAF", severity: "medium", title: "WAF Bypass via Case Variation", description: "Mixed-case XSS payload passed through WAF.", recommendation: "Enable case-insensitive WAF rules.", owasp: "A03", confidence: 65 });
          }
        }
      } catch {}

      // Check detection vs blocking mode
      try {
        const testRes = await fetch(`${url}?test=<script>alert('xss')</script>`, { redirect: "manual" });
        if (testRes.status === 200) {
          const wafModeHeader = testRes.headers.get("x-waf-mode") || testRes.headers.get("x-cdn-mode");
          if (wafModeHeader?.includes("detect") || wafModeHeader?.includes("monitor")) {
            findings.push({ id: "waf-detect-only", category: "WAF", severity: "high", title: "WAF in Detection-Only Mode", description: "WAF is monitoring but not actively blocking attacks.", recommendation: "Switch WAF to blocking mode.", owasp: "A05", confidence: 60 });
          }
        }
      } catch {}
    }

    // XSS filter test
    try {
      const xssRes = await fetch(`${url}?q=<script>alert(1)</script>`, { redirect: "manual" });
      if (xssRes.status !== 403 && xssRes.status !== 406) {
        const body = await xssRes.text();
        if (body.includes("<script>alert(1)</script>")) {
          findings.push({ id: "waf-xss-pass", category: "WAF", severity: "high", title: "XSS Pattern Not Filtered", description: "XSS payload passed through without filtering.", recommendation: "Enable XSS protection in WAF rules.", owasp: "A03", confidence: 80 });
        }
      }
    } catch {}

  } catch (err) {
    findings.push({ id: "waf-err", category: "WAF", severity: "info", title: "WAF Detection Limited", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Manual WAF review recommended.", confidence: 50 });
  }
  return findings;
}

async function scanInjectionSurface(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const baseUrl = url.replace(/\/$/, "");
  try {
    // SQL injection error detection
    const sqliPayloads = [
      { param: "id=1'", pattern: /(sql|syntax|mysql|postgresql|sqlite|oracle|mariadb|mssql|unterminated|unexpected)/i, id: "inj-sqli-error" },
      { param: "id=1%20AND%201=1", pattern: /(error|exception|warning)/i, id: "inj-sqli-bool" },
    ];

    for (const test of sqliPayloads) {
      try {
        const res = await fetch(`${baseUrl}?${test.param}`, { redirect: "manual" });
        const body = await res.text();
        if (test.pattern.test(body) && body.length < 50000) {
          findings.push({ id: test.id, category: "Injection", severity: "critical", title: "SQL Injection Indicators", description: "Database error messages triggered by injection patterns.", recommendation: "Use parameterized queries. Never expose DB errors.", owasp: "A03", confidence: 70 });
          break;
        }
      } catch {}
    }

    // NoSQL injection
    try {
      const nosqlRes = await fetch(`${baseUrl}?username[$gt]=&password[$gt]=`, { redirect: "manual" });
      if (nosqlRes.ok && nosqlRes.status === 200) {
        const body = await nosqlRes.text();
        if (body.includes("token") || body.includes("session") || body.includes("user")) {
          findings.push({ id: "inj-nosql", category: "Injection", severity: "critical", title: "NoSQL Injection Indicators", description: "NoSQL operator injection may be possible.", recommendation: "Sanitize inputs and validate query operators.", owasp: "A03", confidence: 60 });
        }
      }
    } catch {}

    // Path traversal
    try {
      const travRes = await fetch(`${baseUrl}?file=../../etc/passwd`, { redirect: "manual" });
      const body = await travRes.text();
      if (body.includes("root:") && body.includes("/bin/")) {
        findings.push({ id: "inj-traversal", category: "Injection", severity: "critical", title: "Path Traversal Vulnerability", description: "Server responded with /etc/passwd content.", recommendation: "Sanitize file path inputs. Use allowlists.", owasp: "A03", confidence: 90 });
      }
    } catch {}

    // CRLF injection
    try {
      const crlfRes = await fetch(`${baseUrl}/%0d%0aSet-Cookie:crlf=injected`, { redirect: "manual" });
      const setCookie = crlfRes.headers.get("set-cookie");
      if (setCookie?.includes("crlf=injected")) {
        findings.push({ id: "inj-crlf", category: "Injection", severity: "high", title: "CRLF Injection Detected", description: "HTTP response splitting via CRLF injection is possible.", recommendation: "Sanitize CR/LF characters in all user inputs.", owasp: "A03", confidence: 85 });
      }
    } catch {}

    // Host header injection
    try {
      const hostRes = await fetch(url, { headers: { Host: "evil.com" }, redirect: "manual" });
      const hostBody = await hostRes.text();
      if (hostBody.includes("evil.com")) {
        findings.push({ id: "inj-host", category: "Injection", severity: "high", title: "Host Header Injection", description: "Application reflects Host header value in response.", recommendation: "Validate Host header against whitelist.", owasp: "A03", confidence: 75 });
      }
    } catch {}

    // Open redirect
    const redirectPayloads = [
      `${baseUrl}/redirect?url=https://evil.com`,
      `${baseUrl}/login?next=https://evil.com`,
      `${baseUrl}?redirect=https://evil.com`,
      `${baseUrl}?return_to=https://evil.com`,
    ];

    for (const payload of redirectPayloads) {
      try {
        const res = await fetch(payload, { redirect: "manual" });
        const location = res.headers.get("location");
        if (location && location.includes("evil.com")) {
          findings.push({ id: "inj-openredirect", category: "Injection", severity: "medium", title: "Open Redirect Detected", description: "Application redirects to arbitrary external URLs.", recommendation: "Validate redirect URLs against an allowlist.", owasp: "A01", confidence: 80 });
          break;
        }
      } catch {}
    }

    // SSTI
    try {
      const sstiRes = await fetch(`${baseUrl}?name={{7*7}}`, { redirect: "manual" });
      const body = await sstiRes.text();
      if (body.includes("49") && !body.includes("{{7*7}}")) {
        findings.push({ id: "inj-ssti", category: "Injection", severity: "critical", title: "Server-Side Template Injection", description: "Template expression was evaluated on the server.", recommendation: "Sanitize all user inputs in templates.", owasp: "A03", confidence: 75 });
      }
    } catch {}

    // Command injection
    try {
      const cmdRes = await fetch(`${baseUrl}?cmd=;id`, { redirect: "manual" });
      const body = await cmdRes.text();
      if (body.match(/uid=\d+\(/) || body.match(/gid=\d+/)) {
        findings.push({ id: "inj-cmdi", category: "Injection", severity: "critical", title: "Command Injection Detected", description: "System command output detected in response.", recommendation: "Never pass user input to system commands.", owasp: "A03", confidence: 85 });
      }
    } catch {}

    // HTTP Parameter Pollution
    try {
      const hppRes = await fetch(`${baseUrl}?id=1&id=2`, { redirect: "manual" });
      if (hppRes.ok) {
        findings.push({ id: "inj-hpp", category: "Injection", severity: "low", title: "HTTP Parameter Pollution Possible", description: "Server accepts duplicate parameters.", recommendation: "Handle duplicate parameters explicitly.", owasp: "A03", confidence: 40 });
      }
    } catch {}

    // Prototype pollution patterns (check if reflected)
    try {
      const protoRes = await fetch(`${baseUrl}?__proto__[test]=polluted`, { redirect: "manual" });
      const body = await protoRes.text();
      if (body.includes("polluted")) {
        findings.push({ id: "inj-prototype", category: "Injection", severity: "high", title: "Prototype Pollution Indicators", description: "Server may be vulnerable to prototype pollution.", recommendation: "Sanitize object property access from user input.", owasp: "A03", confidence: 55 });
      }
    } catch {}

    if (findings.length === 0) findings.push({ id: "inj-ok", category: "Injection", severity: "info", title: "No Injection Surfaces Found", description: "No obvious injection vulnerabilities detected.", recommendation: "Conduct manual penetration testing.", confidence: 100 });
  } catch (err) {
    findings.push({ id: "inj-err", category: "Injection", severity: "info", title: "Injection Scan Limited", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Manual injection testing recommended.", confidence: 50 });
  }
  return findings;
}

// ========== 4 NEW SCAN MODULES ==========

async function scanHttpMethods(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const baseUrl = url.replace(/\/$/, "");
  try {
    const unsafeMethods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"];
    for (const method of unsafeMethods) {
      try {
        const res = await fetch(baseUrl, { method, redirect: "manual" });
        if (res.status !== 405 && res.status !== 501 && res.status !== 400) {
          if (method === "TRACE") {
            const body = await res.text();
            if (body.includes("TRACE") || res.status === 200) {
              findings.push({ id: "http-trace", category: "HTTP Methods", severity: "high", title: "TRACE Method Enabled (XST Risk)", description: "TRACE method is enabled — Cross-Site Tracing (XST) attacks possible.", recommendation: "Disable TRACE method on the server.", owasp: "A05", confidence: 85 });
            }
          } else {
            findings.push({ id: `http-${method.toLowerCase()}`, category: "HTTP Methods", severity: method === "CONNECT" ? "high" : "medium", title: `${method} Method Enabled`, description: `HTTP ${method} method is accepted by the server.`, recommendation: `Disable ${method} method if not required.`, owasp: "A05", confidence: 70 });
          }
        }
      } catch {}
    }

    // Check OPTIONS response for allowed methods
    try {
      const optRes = await fetch(baseUrl, { method: "OPTIONS" });
      const allow = optRes.headers.get("allow") || optRes.headers.get("access-control-allow-methods") || "";
      if (allow) {
        const methods = allow.toUpperCase().split(",").map(m => m.trim());
        const dangerous = methods.filter(m => ["PUT", "DELETE", "TRACE", "CONNECT"].includes(m));
        if (dangerous.length > 0) {
          findings.push({ id: "http-allow-dangerous", category: "HTTP Methods", severity: "medium", title: `Dangerous Methods Advertised: ${dangerous.join(", ")}`, description: `OPTIONS response lists: ${allow}`, recommendation: "Remove unnecessary HTTP methods.", owasp: "A05", confidence: 80 });
        }
      }
    } catch {}

    if (findings.length === 0) findings.push({ id: "http-ok", category: "HTTP Methods", severity: "info", title: "HTTP Methods Properly Restricted", description: "No unsafe HTTP methods enabled.", recommendation: "Continue monitoring.", confidence: 100 });
  } catch (err) {
    findings.push({ id: "http-err", category: "HTTP Methods", severity: "info", title: "HTTP Methods Scan Limited", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Manual review recommended.", confidence: 50 });
  }
  return findings;
}

async function scanClientSideSecurity(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const res = await fetch(url);
    const html = await res.text();

    // Inline scripts without nonces
    const inlineScripts = html.match(/<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/gi) || [];
    const csp = res.headers.get("content-security-policy") || "";
    if (inlineScripts.length > 0 && !csp.includes("nonce-")) {
      findings.push({ id: "cs-inline-no-nonce", category: "Client-Side Security", severity: "medium", title: "Inline Scripts Without Nonces", description: `${inlineScripts.length} inline script(s) without CSP nonces.`, recommendation: "Add nonces to inline scripts or move to external files.", owasp: "A05", confidence: 80 });
    }

    // SRI on external scripts
    const extScripts = html.match(/<script[^>]*src=["'][^"']+["'][^>]*>/gi) || [];
    const noSRI = extScripts.filter(s => !s.includes("integrity="));
    const crossOriginScripts = noSRI.filter(s => {
      const src = s.match(/src=["']([^"']+)["']/)?.[1] || "";
      return src.startsWith("http") && !src.includes(new URL(url).hostname);
    });
    if (crossOriginScripts.length > 0) {
      findings.push({ id: "cs-no-sri", category: "Client-Side Security", severity: "medium", title: "External Scripts Missing SRI", description: `${crossOriginScripts.length} cross-origin script(s) without Subresource Integrity.`, recommendation: "Add integrity attributes to external script tags.", owasp: "A08", confidence: 85 });
    }

    // DOM XSS sinks
    const domXssSinks = ["document.write", "innerHTML", "outerHTML", "eval(", "setTimeout(", "setInterval(", "Function("];
    const scriptContent = inlineScripts.join(" ");
    const foundSinks = domXssSinks.filter(sink => scriptContent.includes(sink));
    if (foundSinks.length > 0) {
      findings.push({ id: "cs-dom-xss", category: "Client-Side Security", severity: "high", title: "DOM XSS Sinks Detected", description: `Found dangerous DOM methods: ${foundSinks.join(", ")}`, recommendation: "Replace with safe alternatives (textContent, createElement).", owasp: "A03", confidence: 60 });
    }

    // postMessage misuse
    if (scriptContent.includes("addEventListener") && scriptContent.includes("message") && !scriptContent.includes("origin")) {
      findings.push({ id: "cs-postmessage", category: "Client-Side Security", severity: "medium", title: "postMessage Without Origin Check", description: "Message event listener found without origin validation.", recommendation: "Always verify event.origin in message handlers.", owasp: "A01", confidence: 55 });
    }

    // Check for outdated jQuery
    const jqueryMatch = html.match(/jquery[.-](\d+\.\d+\.\d+)/i) || html.match(/jquery\/(\d+\.\d+\.\d+)/i);
    if (jqueryMatch) {
      const version = jqueryMatch[1];
      const [major, minor] = version.split(".").map(Number);
      if (major < 3 || (major === 3 && minor < 5)) {
        findings.push({ id: "cs-jquery-old", category: "Client-Side Security", severity: "medium", title: `Outdated jQuery (${version})`, description: "Known vulnerabilities in older jQuery versions.", recommendation: "Upgrade to jQuery 3.5+ or remove if unused.", owasp: "A06", confidence: 80 });
      }
    }

    if (findings.length === 0) findings.push({ id: "cs-ok", category: "Client-Side Security", severity: "info", title: "Client-Side Security Adequate", description: "No obvious client-side vulnerabilities.", recommendation: "Continue monitoring.", confidence: 100 });
  } catch (err) {
    findings.push({ id: "cs-err", category: "Client-Side Security", severity: "info", title: "Client-Side Scan Limited", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Manual review recommended.", confidence: 50 });
  }
  return findings;
}

async function scanApiDiscovery(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const baseUrl = url.replace(/\/$/, "");
  try {
    // GraphQL endpoints
    const gqlPaths = ["/graphql", "/api/graphql", "/v1/graphql", "/gql"];
    for (const path of gqlPaths) {
      try {
        const gqlRes = await fetch(`${baseUrl}${path}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query: "{ __schema { types { name } } }" }),
          redirect: "manual",
        });
        if (gqlRes.ok) {
          const body = await gqlRes.text();
          if (body.includes("__schema") || body.includes("types")) {
            findings.push({ id: "api-gql-introspection", category: "API Security", severity: "high", title: `GraphQL Introspection Enabled: ${path}`, description: "GraphQL introspection reveals entire schema.", recommendation: "Disable introspection in production.", owasp: "A05", confidence: 90 });
          } else if (body.includes("graphql") || body.includes("query")) {
            findings.push({ id: `api-gql-${path.replace(/\//g, "")}`, category: "API Security", severity: "info", title: `GraphQL Endpoint Found: ${path}`, description: "GraphQL endpoint discovered (introspection may be disabled).", recommendation: "Ensure proper authorization on all queries/mutations.", confidence: 75 });
          }
        }
      } catch {}
    }

    // REST API documentation
    const apiDocPaths = [
      { path: "/swagger.json", id: "api-swagger", title: "Swagger/OpenAPI Spec Exposed" },
      { path: "/openapi.json", id: "api-openapi", title: "OpenAPI Spec Exposed" },
      { path: "/api-docs", id: "api-docs", title: "API Documentation Exposed" },
      { path: "/swagger-ui", id: "api-swagger-ui", title: "Swagger UI Exposed" },
      { path: "/swagger", id: "api-swagger-page", title: "Swagger Page Exposed" },
      { path: "/redoc", id: "api-redoc", title: "ReDoc API Docs Exposed" },
      { path: "/api/docs", id: "api-apidocs", title: "API Docs Endpoint Exposed" },
    ];

    for (const doc of apiDocPaths) {
      try {
        const res = await fetch(`${baseUrl}${doc.path}`, { redirect: "manual" });
        if (res.ok) {
          const body = await res.text();
          if (body.includes("swagger") || body.includes("openapi") || body.includes("paths") || body.includes("API")) {
            findings.push({ id: doc.id, category: "API Security", severity: "medium", title: doc.title, description: `${doc.path} is publicly accessible.`, recommendation: "Restrict API documentation to authorized users.", owasp: "A05", confidence: 80 });
            break;
          }
        }
      } catch {}
    }

    // WSDL endpoints
    try {
      const wsdlRes = await fetch(`${baseUrl}?wsdl`, { redirect: "manual" });
      if (wsdlRes.ok) {
        const body = await wsdlRes.text();
        if (body.includes("wsdl") || body.includes("definitions")) {
          findings.push({ id: "api-wsdl", category: "API Security", severity: "medium", title: "WSDL Endpoint Exposed", description: "SOAP WSDL definition is publicly accessible.", recommendation: "Restrict WSDL access or migrate to REST.", owasp: "A05", confidence: 75 });
        }
      }
    } catch {}

    if (findings.length === 0) findings.push({ id: "api-disc-ok", category: "API Security", severity: "info", title: "No API Specifications Exposed", description: "No publicly accessible API documentation.", recommendation: "Continue monitoring.", confidence: 100 });
  } catch (err) {
    findings.push({ id: "api-disc-err", category: "API Security", severity: "info", title: "API Discovery Scan Limited", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Manual review recommended.", confidence: 50 });
  }
  return findings;
}

async function scanCloudMetadata(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const baseUrl = url.replace(/\/$/, "");
  try {
    // Check for internal IP exposure in page source
    try {
      const res = await fetch(url);
      const body = await res.text();
      const headers = res.headers;

      // Internal IP in headers
      const internalIpPattern = /(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/g;
      const allHeaderValues = [...headers.entries()].map(([, v]) => v).join(" ");
      const headerIps = allHeaderValues.match(internalIpPattern);
      if (headerIps) {
        findings.push({ id: "cloud-internal-ip-header", category: "Cloud Security", severity: "medium", title: "Internal IP in Response Headers", description: `Internal IP addresses found in headers: ${[...new Set(headerIps)].join(", ")}`, recommendation: "Remove internal IP addresses from response headers.", owasp: "A05", confidence: 85 });
      }

      // Internal IP in body
      const bodyIps = body.match(internalIpPattern);
      if (bodyIps && bodyIps.length > 0) {
        const uniqueIps = [...new Set(bodyIps)];
        findings.push({ id: "cloud-internal-ip-body", category: "Cloud Security", severity: "low", title: "Internal IP in Page Content", description: `Internal IPs found: ${uniqueIps.slice(0, 5).join(", ")}`, recommendation: "Remove internal network addresses from public content.", owasp: "A05", confidence: 60 });
      }
    } catch {}

    // SSRF bypass patterns check
    const ssrfPayloads = [
      { url: `${baseUrl}?url=http://169.254.169.254/latest/meta-data/`, name: "AWS Metadata" },
      { url: `${baseUrl}?url=http://metadata.google.internal/computeMetadata/v1/`, name: "GCP Metadata" },
      { url: `${baseUrl}?url=http://169.254.169.254/metadata/instance`, name: "Azure Metadata" },
    ];

    for (const payload of ssrfPayloads) {
      try {
        const res = await fetch(payload.url, { redirect: "manual" });
        const body = await res.text();
        if (body.includes("ami-id") || body.includes("instance-id") || body.includes("project-id") || body.includes("vmId")) {
          findings.push({ id: `cloud-ssrf-${payload.name.toLowerCase().replace(/\s/g, "")}`, category: "SSRF", severity: "critical", title: `SSRF to ${payload.name}`, description: `Server-side request to cloud metadata endpoint succeeded.`, recommendation: "Block metadata endpoint access and validate all user-supplied URLs.", owasp: "A10", confidence: 85 });
        }
      } catch {}
    }

    // Check for cloud storage misconfigs in page
    try {
      const res = await fetch(url);
      const body = await res.text();
      const cloudPatterns = [
        { pattern: /s3\.amazonaws\.com\/[a-z0-9.-]+/gi, name: "AWS S3 Bucket", severity: "low" as const },
        { pattern: /storage\.googleapis\.com\/[a-z0-9.-]+/gi, name: "GCS Bucket", severity: "low" as const },
        { pattern: /blob\.core\.windows\.net\/[a-z0-9.-]+/gi, name: "Azure Blob", severity: "low" as const },
      ];

      for (const { pattern, name, severity } of cloudPatterns) {
        const matches = body.match(pattern);
        if (matches) {
          findings.push({ id: `cloud-bucket-${name.toLowerCase().replace(/\s/g, "")}`, category: "Cloud Security", severity, title: `${name} Referenced`, description: `Found ${name} reference: ${matches[0]}`, recommendation: `Verify ${name} permissions are properly configured.`, owasp: "A05", confidence: 70 });
        }
      }
    } catch {}

    // Check for Kubernetes/Docker exposure
    const k8sPaths = ["/healthz", "/readyz", "/metrics", "/actuator/health", "/actuator/env"];
    for (const path of k8sPaths) {
      try {
        const res = await fetch(`${baseUrl}${path}`, { redirect: "manual" });
        if (res.ok) {
          const body = await res.text();
          if (body.includes("ok") || body.includes("UP") || body.includes("kubernetes") || body.includes("HELP")) {
            findings.push({ id: `cloud-k8s-${path.replace(/\//g, "")}`, category: "Cloud Security", severity: path.includes("env") || path.includes("metrics") ? "high" : "low", title: `Exposed: ${path}`, description: `${path} endpoint is publicly accessible.`, recommendation: "Restrict health/metrics endpoints to internal networks.", owasp: "A05", confidence: 75 });
          }
        }
      } catch {}
    }

    if (findings.length === 0) findings.push({ id: "cloud-ok", category: "Cloud Security", severity: "info", title: "Cloud Configuration Secure", description: "No cloud metadata or SSRF issues detected.", recommendation: "Continue monitoring.", confidence: 100 });
  } catch (err) {
    findings.push({ id: "cloud-err", category: "Cloud Security", severity: "info", title: "Cloud Metadata Scan Limited", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Manual review recommended.", confidence: 50 });
  }
  return findings;
}

// ========== ADVANCED RISK SCORING ==========

function calculateWeightedRisk(findings: Finding[]): { risk_level: string; risk_score: number } {
  let weightedScore = 0;
  const severityBase: Record<string, number> = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };

  for (const f of findings) {
    const base = severityBase[f.severity] || 0;
    const weight = getWeight(f.category);
    const confidence = (f.confidence || 80) / 100;
    // Exploitability factor: network-accessible vulns weighted higher
    const exploitability = f.category.includes("Injection") || f.category.includes("SSRF") || f.category.includes("Authentication") ? 1.3 : 1.0;
    weightedScore += base * weight * confidence * exploitability;
  }

  // Combination bonuses (synergistic risk / vulnerability chaining)
  const hasNoWaf = findings.some(f => f.id === "waf-none");
  const hasInjection = findings.some(f => f.category === "Injection" && f.severity !== "info");
  const hasNoAuth = findings.some(f => f.id === "api-noauth");
  const hasNoHTTPS = findings.some(f => f.id === "dep-https" || f.id === "inf-notls");
  const hasOpenRedirect = findings.some(f => f.id === "inj-openredirect");
  const hasNoCSP = findings.some(f => f.id === "dep-csp");
  const hasSSRF = findings.some(f => f.category === "SSRF" && f.severity !== "info");
  const hasXSS = findings.some(f => f.id === "api-xss" || f.id === "waf-xss-pass");

  if (hasNoWaf && hasInjection) weightedScore += 15;
  if (hasNoAuth && hasInjection) weightedScore += 20;
  if (hasNoHTTPS && hasNoAuth) weightedScore += 10;
  if (hasOpenRedirect && hasNoCSP) weightedScore += 12;
  if (hasSSRF && hasNoWaf) weightedScore += 18;
  if (hasXSS && hasNoCSP) weightedScore += 15;

  const score = Math.min(100, Math.round(weightedScore));
  const risk_level = score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : "low";
  return { risk_level, risk_score: score };
}

// ========== VULNERABILITY CHAIN DETECTION ==========

function detectFindingChains(findings: Finding[]): FindingChain[] {
  const chains: FindingChain[] = [];
  const findingMap = new Map(findings.map(f => [f.id, f]));

  // Chain: Open Redirect + No CSP = Phishing
  const openRedirect = findings.find(f => f.id === "inj-openredirect");
  const noCSP = findings.find(f => f.id === "dep-csp");
  if (openRedirect && noCSP) {
    chains.push({
      chain_id: "chain-phishing",
      title: "Phishing Attack Chain",
      severity: "high",
      finding_ids: [openRedirect.id, noCSP.id],
      description: "Open redirect combined with missing CSP enables sophisticated phishing attacks.",
      combined_impact: "Attacker can redirect users to a phishing page that loads malicious content without CSP restrictions.",
    });
  }

  // Chain: No WAF + XSS = Direct Exploitation
  const noWaf = findings.find(f => f.id === "waf-none");
  const xss = findings.find(f => f.id === "api-xss" || f.id === "waf-xss-pass");
  if (noWaf && xss) {
    chains.push({
      chain_id: "chain-xss-exploit",
      title: "Unprotected XSS Exploitation",
      severity: "critical",
      finding_ids: [noWaf.id, xss.id],
      description: "XSS vulnerability with no WAF protection allows direct exploitation.",
      combined_impact: "Attacker can inject scripts and steal session tokens without any defensive layer.",
    });
  }

  // Chain: SSRF + Cloud Metadata = Full Compromise
  const ssrf = findings.find(f => f.category === "SSRF" && f.severity === "critical");
  const cloudExposed = findings.find(f => f.category === "Cloud Security" && f.severity !== "info");
  if (ssrf && cloudExposed) {
    chains.push({
      chain_id: "chain-cloud-compromise",
      title: "Cloud Infrastructure Compromise",
      severity: "critical",
      finding_ids: [ssrf.id, cloudExposed.id],
      description: "SSRF combined with cloud exposure enables access to cloud metadata and credentials.",
      combined_impact: "Full cloud infrastructure compromise via SSRF to metadata endpoints.",
    });
  }

  // Chain: No Auth + SQLi = Data Breach
  const noAuth = findings.find(f => f.id === "api-noauth");
  const sqli = findings.find(f => f.id === "inj-sqli-error" || f.id === "inj-sqli-bool");
  if (noAuth && sqli) {
    chains.push({
      chain_id: "chain-data-breach",
      title: "Data Breach Chain",
      severity: "critical",
      finding_ids: [noAuth.id, sqli.id],
      description: "Unauthenticated API with SQL injection enables direct database access.",
      combined_impact: "Complete database extraction without requiring any credentials.",
    });
  }

  // Chain: JWT exposed + No HTTPS = Session Hijack
  const jwtExposed = findings.find(f => f.id === "auth-jwt-exposed");
  const noHttps = findings.find(f => f.id === "dep-https" || f.id === "inf-notls");
  if (jwtExposed && noHttps) {
    chains.push({
      chain_id: "chain-session-hijack",
      title: "Session Hijacking Chain",
      severity: "critical",
      finding_ids: [jwtExposed.id, noHttps.id],
      description: "Exposed JWT tokens transmitted over unencrypted HTTP enable session hijacking.",
      combined_impact: "Attacker can intercept and reuse authentication tokens.",
    });
  }

  // Chain: GraphQL introspection + No rate limit = Data Enumeration
  const gqlIntro = findings.find(f => f.id === "api-gql-introspection");
  const noRate = findings.find(f => f.id === "api-norate");
  if (gqlIntro && noRate) {
    chains.push({
      chain_id: "chain-gql-enum",
      title: "GraphQL Data Enumeration",
      severity: "high",
      finding_ids: [gqlIntro.id, noRate.id],
      description: "GraphQL introspection with no rate limiting enables complete data enumeration.",
      combined_impact: "Attacker can discover and extract all queryable data without throttling.",
    });
  }

  return chains;
}

// ========== MITRE ATT&CK MAPPING ==========

const MITRE_FINDING_MAP: Record<string, Array<{ tactic: string; technique: string }>> = {
  // Reconnaissance
  "dns-": [{ tactic: "TA0043", technique: "T1590" }],
  "inf-provider": [{ tactic: "TA0043", technique: "T1592" }],
  "inf-xpowered": [{ tactic: "TA0043", technique: "T1592" }],
  "inf-aspnet": [{ tactic: "TA0043", technique: "T1592" }],
  "dep-server": [{ tactic: "TA0043", technique: "T1592" }],
  "info-": [{ tactic: "TA0043", technique: "T1596" }],
  "api-gql": [{ tactic: "TA0043", technique: "T1596" }],
  "api-swagger": [{ tactic: "TA0043", technique: "T1596" }],
  // Initial Access
  "api-xss": [{ tactic: "TA0001", technique: "T1190" }, { tactic: "TA0002", technique: "T1203" }],
  "inj-": [{ tactic: "TA0001", technique: "T1190" }],
  "dep-https": [{ tactic: "TA0001", technique: "T1189" }],
  "auth-noauth": [{ tactic: "TA0001", technique: "T1078" }],
  "api-noauth": [{ tactic: "TA0001", technique: "T1078" }],
  "auth-jwt": [{ tactic: "TA0001", technique: "T1078" }],
  // Execution
  "client-dom-xss": [{ tactic: "TA0002", technique: "T1059" }],
  "client-inline-script": [{ tactic: "TA0002", technique: "T1059" }],
  "http-trace": [{ tactic: "TA0002", technique: "T1059" }],
  // Credential Access
  "dep-cookie-": [{ tactic: "TA0006", technique: "T1539" }],
  "auth-enum": [{ tactic: "TA0006", technique: "T1110" }],
  "auth-nocaptcha": [{ tactic: "TA0006", technique: "T1110" }],
  "auth-apikey": [{ tactic: "TA0006", technique: "T1552" }],
  "info-env": [{ tactic: "TA0006", technique: "T1552" }],
  "info-git": [{ tactic: "TA0006", technique: "T1552" }],
  "ssl-": [{ tactic: "TA0006", technique: "T1557" }],
  // Discovery
  "sto-listing": [{ tactic: "TA0007", technique: "T1580" }],
  "cloud-metadata": [{ tactic: "TA0007", technique: "T1580" }],
  "inf-admin": [{ tactic: "TA0007", technique: "T1046" }],
  "http-unsafe": [{ tactic: "TA0007", technique: "T1046" }],
  // Defense Evasion
  "waf-": [{ tactic: "TA0005", technique: "T1562" }],
  "dep-csp": [{ tactic: "TA0005", technique: "T1562" }],
  // Privilege Escalation
  "api-cors-creds": [{ tactic: "TA0004", technique: "T1134" }],
  "api-cors-reflect": [{ tactic: "TA0004", technique: "T1134" }],
  "auth-no2fa": [{ tactic: "TA0004", technique: "T1078.004" }],
  // Collection
  "sto-sensitive": [{ tactic: "TA0009", technique: "T1530" }],
  "sto-public": [{ tactic: "TA0009", technique: "T1530" }],
  "info-sourcemap": [{ tactic: "TA0009", technique: "T1213" }],
  // Lateral Movement
  "cloud-internal": [{ tactic: "TA0008", technique: "T1210" }],
  "cloud-ssrf": [{ tactic: "TA0008", technique: "T1210" }],
  // Impact
  "api-norate": [{ tactic: "TA0040", technique: "T1499" }],
  "inj-host": [{ tactic: "TA0040", technique: "T1491" }],
};

function buildMitreMapping(findings: Finding[]): Record<string, Record<string, { count: number; severity: string; findings: Array<{ id: string; title: string; severity: string; cvss_score?: number }> }>> {
  const mapping: Record<string, Record<string, { count: number; severity: string; findings: Array<{ id: string; title: string; severity: string; cvss_score?: number }> }>> = {};
  const sevRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  for (const f of findings) {
    if (f.severity === "info") continue;

    // Find matching MITRE mappings by prefix
    for (const [prefix, mappings] of Object.entries(MITRE_FINDING_MAP)) {
      if (f.id.startsWith(prefix) || f.id === prefix.replace(/-$/, "")) {
        for (const { tactic, technique } of mappings) {
          if (!mapping[tactic]) mapping[tactic] = {};
          if (!mapping[tactic][technique]) {
            mapping[tactic][technique] = { count: 0, severity: "low", findings: [] };
          }
          mapping[tactic][technique].count++;
          mapping[tactic][technique].findings.push({
            id: f.id,
            title: f.title,
            severity: f.severity,
            cvss_score: f.cvss_score,
          });
          if ((sevRank[f.severity] || 0) > (sevRank[mapping[tactic][technique].severity] || 0)) {
            mapping[tactic][technique].severity = f.severity;
          }
        }
      }
    }
  }

  return mapping;
}

// ========== BUSINESS RISK SCORING ==========

function calculateBusinessRisk(findings: Finding[], url: string): Record<string, any> {
  const sevWeights: Record<string, number> = { critical: 10, high: 7, medium: 4, low: 1, info: 0 };

  // Data sensitivity score
  const dataFindings = findings.filter(f =>
    f.category.includes("Data") || f.category.includes("Storage") ||
    f.category.includes("Credential") || f.id.includes("sensitive") || f.id.includes("env")
  );
  const dataSensitivity = Math.min(100, dataFindings.reduce((s, f) => s + (sevWeights[f.severity] || 0) * 3, 0));

  // Revenue impact (based on critical/high exploitable vulns)
  const exploitable = findings.filter(f => f.severity === "critical" || f.severity === "high");
  const revenueImpact = Math.min(100, exploitable.length * 12);

  // Asset criticality (production assumed high)
  const isProduction = !url.includes("staging") && !url.includes("dev") && !url.includes("test");
  const assetCriticality = isProduction ? 85 : 40;

  // Composite score
  const composite = Math.round((dataSensitivity * 0.35) + (revenueImpact * 0.35) + (assetCriticality * 0.3));

  return {
    composite_score: Math.min(100, composite),
    data_sensitivity: { score: dataSensitivity, finding_count: dataFindings.length },
    revenue_impact: { score: revenueImpact, exploitable_count: exploitable.length },
    asset_criticality: { score: assetCriticality, environment: isProduction ? "production" : "non-production" },
    risk_level: composite >= 75 ? "critical" : composite >= 50 ? "high" : composite >= 25 ? "medium" : "low",
  };
}

// ========== ATTACK PATH GENERATION ==========

function generateAttackPaths(findings: Finding[], chains: FindingChain[]): Array<Record<string, any>> {
  const paths: Array<Record<string, any>> = [];

  // Generate paths from chains
  for (const chain of chains) {
    const chainFindings = chain.finding_ids.map(id => findings.find(f => f.id === id)).filter(Boolean);
    if (chainFindings.length < 2) continue;

    paths.push({
      path_id: chain.chain_id,
      title: chain.title,
      severity: chain.severity,
      steps: chainFindings.map((f, i) => ({
        step: i + 1,
        phase: i === 0 ? "Entry Point" : i === chainFindings.length - 1 ? "Impact" : "Escalation",
        finding_id: f!.id,
        finding_title: f!.title,
        severity: f!.severity,
        cvss_score: f!.cvss_score,
      })),
      impact: chain.combined_impact,
    });
  }

  // Auto-generate path: Auth bypass → Data access
  const authIssues = findings.filter(f => f.category.includes("Authentication") && (f.severity === "critical" || f.severity === "high"));
  const dataIssues = findings.filter(f => (f.category.includes("Data") || f.category.includes("Storage")) && f.severity !== "info");
  if (authIssues.length > 0 && dataIssues.length > 0) {
    paths.push({
      path_id: "auto-auth-data",
      title: "Authentication Bypass → Data Access",
      severity: "critical",
      steps: [
        { step: 1, phase: "Entry Point", finding_id: authIssues[0].id, finding_title: authIssues[0].title, severity: authIssues[0].severity },
        { step: 2, phase: "Impact", finding_id: dataIssues[0].id, finding_title: dataIssues[0].title, severity: dataIssues[0].severity },
      ],
      impact: "Unauthenticated attacker gains access to sensitive data.",
    });
  }

  // Auto-generate path: Info Disclosure → Credential Access → Privilege Escalation
  const infoDisc = findings.filter(f => f.category.includes("Information Disclosure") && f.severity !== "info");
  const credIssues = findings.filter(f => f.id.includes("apikey") || f.id.includes("env") || f.id.includes("git"));
  if (infoDisc.length > 0 && credIssues.length > 0) {
    paths.push({
      path_id: "auto-info-cred",
      title: "Information Leak → Credential Harvesting",
      severity: "high",
      steps: [
        { step: 1, phase: "Reconnaissance", finding_id: infoDisc[0].id, finding_title: infoDisc[0].title, severity: infoDisc[0].severity },
        { step: 2, phase: "Credential Access", finding_id: credIssues[0].id, finding_title: credIssues[0].title, severity: credIssues[0].severity },
      ],
      impact: "Exposed information leads to credential compromise.",
    });
  }

  return paths;
}

// ========== OWASP MAPPING ==========

function buildOwaspMapping(findings: Finding[]): Record<string, { count: number; severity: string; findings: string[] }> {
  const mapping: Record<string, { count: number; severity: string; findings: string[] }> = {};
  for (const [code] of Object.entries(OWASP_CATEGORIES)) {
    mapping[code] = { count: 0, severity: "none", findings: [] };
  }

  for (const f of findings) {
    if (f.owasp && mapping[f.owasp]) {
      mapping[f.owasp].count++;
      mapping[f.owasp].findings.push(f.title);
      const sevRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0, none: -1 };
      if ((sevRank[f.severity] || 0) > (sevRank[mapping[f.owasp].severity] || -1)) {
        mapping[f.owasp].severity = f.severity;
      }
    }
  }
  return mapping;
}

// ========== COMPLIANCE FLAGS ==========

function checkCompliance(findings: Finding[]): Record<string, { status: string; issues: string[] }> {
  const compliance: Record<string, { status: string; issues: string[] }> = {
    "PCI-DSS": { status: "pass", issues: [] },
    "SOC2": { status: "pass", issues: [] },
    "ISO27001": { status: "pass", issues: [] },
  };

  for (const f of findings) {
    if (f.severity === "info") continue;

    if (f.category.includes("SSL") || f.category.includes("Transport") || f.category.includes("Encryption") || f.category.includes("Cryptographic")) {
      if (f.severity === "critical" || f.severity === "high") {
        compliance["PCI-DSS"].status = "fail";
        compliance["PCI-DSS"].issues.push(f.title);
      }
    }
    if (f.category.includes("Authentication") && (f.severity === "critical" || f.severity === "high")) {
      compliance["PCI-DSS"].status = "fail";
      compliance["PCI-DSS"].issues.push(f.title);
    }

    if (f.category.includes("Access Control") || f.category.includes("Authentication")) {
      if (f.severity === "critical" || f.severity === "high") {
        compliance["SOC2"].status = "fail";
        compliance["SOC2"].issues.push(f.title);
      }
    }
    if (f.category.includes("Information Disclosure") && f.severity === "critical") {
      compliance["SOC2"].status = "fail";
      compliance["SOC2"].issues.push(f.title);
    }

    if (f.severity === "critical") {
      compliance["ISO27001"].status = "fail";
      compliance["ISO27001"].issues.push(f.title);
    }
    if (f.category.includes("Security Headers") && f.severity === "high") {
      if (compliance["ISO27001"].status !== "fail") compliance["ISO27001"].status = "warning";
      compliance["ISO27001"].issues.push(f.title);
    }
  }

  return compliance;
}

// ========== EXECUTIVE SUMMARY ==========

function generateSummary(url: string, findings: Finding[], risk: { risk_level: string; risk_score: number }, compliance: Record<string, any>, chains: FindingChain[]): string {
  const hostname = (() => { try { return new URL(url).hostname; } catch { return url; } })();
  const critCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const failedCompliance = Object.entries(compliance).filter(([, v]) => v.status === "fail").map(([k]) => k);

  let summary = `VAPT Assessment for ${hostname} — Risk Level: ${risk.risk_level.toUpperCase()} (${risk.risk_score}/100). `;
  summary += `Identified ${findings.length} findings across 14 security modules. `;

  if (critCount > 0) summary += `⚠️ ${critCount} critical vulnerabilities require immediate attention. `;
  if (highCount > 0) summary += `${highCount} high-severity issues should be prioritized. `;
  if (chains.length > 0) summary += `🔗 ${chains.length} vulnerability chain(s) detected — correlated findings amplify risk. `;
  if (failedCompliance.length > 0) summary += `Compliance failures: ${failedCompliance.join(", ")}. `;
  if (critCount === 0 && highCount === 0) summary += `No critical or high-severity issues found. Security posture is strong. `;

  return summary;
}

// ========== REMEDIATION PRIORITY ==========

function buildRemediationPriority(findings: Finding[]): Array<{ title: string; severity: string; effort: string; impact: string; category: string; cvss_score?: number }> {
  const effortMap: Record<string, string> = {
    "Security Headers": "Low", "Cookie Security": "Low", "Information Disclosure": "Low",
    "CORS": "Medium", "Rate Limiting": "Medium", "WAF": "Medium", "DNS Security": "Medium",
    "SSL/TLS": "Medium", "Encryption": "Medium", "HTTP Methods": "Low", "Client-Side Security": "Medium",
    "Authentication": "High", "Injection": "High", "Access Control": "High", "Session": "High",
    "API Security": "Medium", "Cloud Security": "High", "SSRF": "High",
  };

  const actionable = findings.filter(f => f.severity !== "info");
  const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

  return actionable
    .sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4))
    .map(f => {
      const cvss = estimateCVSS(f);
      return {
        title: f.title,
        severity: f.severity,
        effort: effortMap[f.category] || "Medium",
        impact: f.severity === "critical" ? "Critical" : f.severity === "high" ? "High" : "Moderate",
        category: f.category,
        cvss_score: cvss.score,
      };
    });
}

// ========== MAIN HANDLER ==========

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  if (req.method !== "POST") return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return new Response(JSON.stringify({ error: "Authentication required" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    const supabase = createClient(supabaseUrl, supabaseAnonKey, { global: { headers: { Authorization: authHeader } } });

    const token = authHeader.replace("Bearer ", "");
    const { data: claimsData, error: claimsError } = await supabase.auth.getClaims(token);
    if (claimsError || !claimsData?.claims) {
      return new Response(JSON.stringify({ error: "Invalid token" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const userId = claimsData.claims.sub as string;

    let body: { url?: string; webhook?: boolean };
    try { body = await req.json(); } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { url: targetUrl, webhook = false } = body;
    if (!targetUrl) return new Response(JSON.stringify({ error: "url is required" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });

    const normalizedUrl = targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`;
    const startTime = Date.now();

    // Create pipeline record
    const { data: pipeline, error: pipeErr } = await supabase
      .from("cloud_scan_pipelines")
      .insert({ user_id: userId, target_url: normalizedUrl, status: "running", webhook_trigger: webhook, total_stages: 14 })
      .select("id")
      .single();

    if (pipeErr || !pipeline) {
      return new Response(JSON.stringify({ error: "Failed to create pipeline" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const allFindings: Finding[] = [];
    const stageResults: Record<string, { findings: Finding[]; risk_level: string; risk_score: number; duration_ms: number }> = {};
    const completedStages: string[] = [];

    // Run all 14 scan stages
    const scanFunctions: Record<string, (url: string) => Promise<Finding[]>> = {
      deployment: scanDeployment,
      api: scanApi,
      storage: scanStorage,
      infrastructure: scanInfrastructure,
      dns_recon: scanDnsRecon,
      ssl_deep: scanSslDeep,
      auth_session: scanAuthSession,
      info_disclosure: scanInfoDisclosure,
      waf_detection: scanWafDetection,
      injection_surface: scanInjectionSurface,
      http_methods: scanHttpMethods,
      client_side_security: scanClientSideSecurity,
      api_discovery: scanApiDiscovery,
      cloud_metadata: scanCloudMetadata,
    };

    for (const stage of SCAN_STAGES) {
      const stageStart = Date.now();
      const scanFn = scanFunctions[stage];
      const findings = await scanFn(normalizedUrl);

      // Add CVSS scores to each finding
      for (const f of findings) {
        const cvss = estimateCVSS(f);
        f.cvss_score = cvss.score;
        f.cvss_vector = cvss.vector;
      }

      const stageRisk = calculateWeightedRisk(findings);
      const stageDuration = Date.now() - stageStart;
      stageResults[stage] = { findings, ...stageRisk, duration_ms: stageDuration };
      allFindings.push(...findings);
      completedStages.push(stage);

      await supabase.from("cloud_scans").insert({
        user_id: userId,
        target_url: normalizedUrl,
        scan_type: stage,
        status: "completed",
        risk_level: stageRisk.risk_level,
        risk_score: stageRisk.risk_score,
        findings,
        summary: {
          critical: findings.filter(f => f.severity === "critical").length,
          high: findings.filter(f => f.severity === "high").length,
          medium: findings.filter(f => f.severity === "medium").length,
          low: findings.filter(f => f.severity === "low").length,
          info: findings.filter(f => f.severity === "info").length,
        },
        scan_duration_ms: stageDuration,
        completed_at: new Date().toISOString(),
        pipeline_id: pipeline.id,
      });

      await supabase.from("cloud_scan_pipelines").update({ completed_stages: completedStages }).eq("id", pipeline.id);
    }

    // Calculate overall risk
    const overall = calculateWeightedRisk(allFindings);
    const totalDuration = Date.now() - startTime;
    const counts = {
      critical: allFindings.filter(f => f.severity === "critical").length,
      high: allFindings.filter(f => f.severity === "high").length,
      medium: allFindings.filter(f => f.severity === "medium").length,
      low: allFindings.filter(f => f.severity === "low").length,
      info: allFindings.filter(f => f.severity === "info").length,
    };

    // Build VAPT report data
    const owaspMapping = buildOwaspMapping(allFindings);
    const complianceFlags = checkCompliance(allFindings);
    const findingChains = detectFindingChains(allFindings);
    const remediationPriority = buildRemediationPriority(allFindings);
    const executiveSummary = generateSummary(normalizedUrl, allFindings, overall, complianceFlags, findingChains);

    const categoriesHit = new Set(allFindings.filter(f => f.severity !== "info").map(f => f.category));
    const attackSurfaceScore = Math.min(100, Math.round((categoriesHit.size / 16) * 100));

    // Finalize pipeline
    await supabase.from("cloud_scan_pipelines").update({
      status: "completed",
      overall_risk_level: overall.risk_level,
      overall_risk_score: overall.risk_score,
      total_findings: allFindings.length,
      critical_count: counts.critical,
      high_count: counts.high,
      medium_count: counts.medium,
      low_count: counts.low,
      info_count: counts.info,
      completed_stages: completedStages,
      scan_duration_ms: totalDuration,
      completed_at: new Date().toISOString(),
    }).eq("id", pipeline.id);

    // Save VAPT report
    await supabase.from("vapt_reports").insert({
      pipeline_id: pipeline.id,
      user_id: userId,
      target_url: normalizedUrl,
      executive_summary: executiveSummary,
      owasp_mapping: owaspMapping,
      attack_surface_score: attackSurfaceScore,
      compliance_flags: complianceFlags,
      remediation_priority: remediationPriority,
      finding_chains: findingChains,
      total_findings: allFindings.length,
      critical_count: counts.critical,
      high_count: counts.high,
      medium_count: counts.medium,
      low_count: counts.low,
      info_count: counts.info,
      overall_risk_score: overall.risk_score,
      overall_risk_level: overall.risk_level,
      scan_duration_ms: totalDuration,
    });

    return new Response(JSON.stringify({
      success: true,
      pipeline_id: pipeline.id,
      target_url: normalizedUrl,
      overall_risk_level: overall.risk_level,
      overall_risk_score: overall.risk_score,
      total_findings: allFindings.length,
      counts,
      stages: stageResults,
      scan_duration_ms: totalDuration,
      owasp_mapping: owaspMapping,
      compliance_flags: complianceFlags,
      remediation_priority: remediationPriority,
      executive_summary: executiveSummary,
      attack_surface_score: attackSurfaceScore,
      finding_chains: findingChains,
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  } catch (err) {
    console.error("Pipeline error:", err);
    return new Response(JSON.stringify({ error: "Pipeline failed" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
