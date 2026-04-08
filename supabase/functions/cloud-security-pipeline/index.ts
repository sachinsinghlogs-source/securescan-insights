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
}

const SCAN_STAGES = [
  "deployment", "api", "storage", "infrastructure",
  "dns_recon", "ssl_deep", "auth_session", "info_disclosure", "waf_detection", "injection_surface"
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

// Category weights for CVSS-inspired scoring
const CATEGORY_WEIGHTS: Record<string, number> = {
  "Authentication": 1.5, "Injection": 1.5, "Access Control": 1.4,
  "Transport Security": 1.3, "Cookie Security": 1.2, "CORS": 1.2,
  "Cryptographic": 1.3, "Information Disclosure": 0.8, "Infrastructure": 0.7,
  "DNS Security": 1.0, "SSL/TLS": 1.2, "WAF": 0.9, "Session": 1.3,
  "Data Exposure": 1.4, "Encryption": 1.1, "Rate Limiting": 1.0,
  "Security Headers": 1.0, "Connectivity": 0.5, "Deployment": 0.5,
  "Storage": 0.8, "API Security": 0.7,
};

function getWeight(category: string): number {
  for (const [key, w] of Object.entries(CATEGORY_WEIGHTS)) {
    if (category.toLowerCase().includes(key.toLowerCase())) return w;
  }
  return 1.0;
}

// ========== ORIGINAL 4 SCAN MODULES ==========

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
    ];

    for (const h of secHeaders) {
      if (!headers.get(h.name)) {
        findings.push({ id: h.id, category: "Security Headers", severity: h.severity, title: h.title, description: `${h.name} header is missing.`, recommendation: `Add ${h.name} header.`, owasp: h.owasp, confidence: 95 });
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

    const sensitive = [".env", "config.json", "credentials", ".pem", ".key", "secret"];
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
    ];
    const detected = providers.find(pr => pr.p.test(allH));
    if (detected) findings.push({ id: "inf-provider", category: "Infrastructure", severity: "info", title: `Provider: ${detected.n}`, description: `Hosted on ${detected.n}.`, recommendation: "Follow provider security best practices.", confidence: 85 });

    const xpb = headers.get("x-powered-by");
    if (xpb) findings.push({ id: "inf-xpowered", category: "Information Disclosure", severity: "medium", title: "X-Powered-By Exposed", description: `Reveals: ${xpb}`, recommendation: "Remove header.", owasp: "A05", confidence: 95 });

    if (url.startsWith("https://")) findings.push({ id: "inf-tls", category: "Transport", severity: "info", title: "TLS Enabled", description: "HTTPS active.", recommendation: "Ensure TLS 1.2+.", confidence: 100 });
    else findings.push({ id: "inf-notls", category: "Transport", severity: "critical", title: "No TLS/HTTPS", description: "Not using HTTPS.", recommendation: "Enable immediately.", owasp: "A02", confidence: 100 });

    if (res.status >= 300 && res.status < 400) {
      const loc = headers.get("location");
      if (loc?.startsWith("http://")) findings.push({ id: "inf-redirect", category: "Transport", severity: "high", title: "Redirect to HTTP", description: "Redirects insecurely.", recommendation: "Redirect to HTTPS only.", owasp: "A02", confidence: 95 });
    }

    const adminPaths = ["/admin", "/wp-admin", "/console", "/_admin"];
    for (const path of adminPaths) {
      try {
        const r = await fetch(`${url.replace(/\/$/, "")}${path}`, { redirect: "manual" });
        if (r.status === 200) { findings.push({ id: `inf-admin`, category: "Access Control", severity: "high", title: `Admin Panel: ${path}`, description: "Publicly accessible.", recommendation: "Restrict access.", owasp: "A01", confidence: 80 }); break; }
      } catch {}
    }

    if (findings.length === 0) findings.push({ id: "inf-ok", category: "Infrastructure", severity: "info", title: "Infrastructure Secure", description: "No issues.", recommendation: "Continue monitoring.", confidence: 100 });
  } catch (err) {
    findings.push({ id: "inf-err", category: "Connectivity", severity: "high", title: "Unreachable", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Check DNS/connectivity.", confidence: 100 });
  }
  return findings;
}

// ========== 6 NEW ADVANCED SCAN MODULES ==========

async function scanDnsRecon(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const hostname = new URL(url).hostname;

    // Check DNS via public DoH API
    const dnsTypes = ["MX", "TXT", "NS", "AAAA"];
    for (const type of dnsTypes) {
      try {
        const dnsRes = await fetch(`https://dns.google/resolve?name=${hostname}&type=${type}`);
        const dns = await dnsRes.json();
        if (dns.Answer) {
          // Check SPF/DMARC in TXT records
          if (type === "TXT") {
            const txtRecords = dns.Answer.map((a: any) => a.data).join(" ");
            if (!txtRecords.includes("v=spf1")) {
              findings.push({ id: "dns-nospf", category: "DNS Security", severity: "medium", title: "Missing SPF Record", description: "No SPF record found. Email spoofing possible.", recommendation: "Add SPF TXT record.", owasp: "A05", confidence: 90 });
            }
            if (!txtRecords.includes("v=DMARC1")) {
              // Check _dmarc subdomain
              try {
                const dmarcRes = await fetch(`https://dns.google/resolve?name=_dmarc.${hostname}&type=TXT`);
                const dmarc = await dmarcRes.json();
                const dmarcTxt = dmarc.Answer?.map((a: any) => a.data).join(" ") || "";
                if (!dmarcTxt.includes("v=DMARC1")) {
                  findings.push({ id: "dns-nodmarc", category: "DNS Security", severity: "medium", title: "Missing DMARC Record", description: "No DMARC policy. Email domain can be spoofed.", recommendation: "Add DMARC TXT record.", owasp: "A05", confidence: 90 });
                }
              } catch {}
            }
          }
        }
      } catch {}
    }

    // Check for DNSSEC
    try {
      const dnssecRes = await fetch(`https://dns.google/resolve?name=${hostname}&type=DNSKEY`);
      const dnssec = await dnssecRes.json();
      if (!dnssec.Answer || dnssec.Answer.length === 0) {
        findings.push({ id: "dns-nodnssec", category: "DNS Security", severity: "low", title: "DNSSEC Not Enabled", description: "Domain does not use DNSSEC.", recommendation: "Enable DNSSEC with your registrar.", owasp: "A05", confidence: 85 });
      }
    } catch {}

    // Check for dangling CNAME (subdomain takeover indicators)
    const subdomains = ["www", "mail", "staging", "dev", "api", "cdn", "app"];
    for (const sub of subdomains.slice(0, 3)) {
      try {
        const cnameRes = await fetch(`https://dns.google/resolve?name=${sub}.${hostname}&type=CNAME`);
        const cname = await cnameRes.json();
        if (cname.Answer) {
          const target = cname.Answer[0]?.data;
          if (target) {
            // Check if CNAME target resolves
            try {
              const checkRes = await fetch(`https://${target.replace(/\.$/, "")}`, { redirect: "manual" });
              if (checkRes.status === 404 || checkRes.status === 0) {
                findings.push({ id: `dns-dangling-${sub}`, category: "DNS Security", severity: "high", title: `Potential Subdomain Takeover: ${sub}`, description: `${sub}.${hostname} has CNAME to ${target} which may be unclaimed.`, recommendation: "Remove dangling CNAME or claim the resource.", owasp: "A05", confidence: 60 });
              }
            } catch {}
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

    // Test HTTPS connectivity and certificate info
    if (!url.startsWith("https://")) {
      findings.push({ id: "ssl-nossl", category: "SSL/TLS", severity: "critical", title: "No SSL/TLS", description: "Site does not use HTTPS.", recommendation: "Enable HTTPS immediately.", owasp: "A02", confidence: 100 });
      return findings;
    }

    const res = await fetch(url);
    const headers = res.headers;

    // Check HSTS settings deeply
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

    // Check Certificate Transparency via crt.sh
    try {
      const ctRes = await fetch(`https://crt.sh/?q=${hostname}&output=json`, { signal: AbortSignal.timeout(5000) });
      if (ctRes.ok) {
        const certs = await ctRes.json();
        if (Array.isArray(certs) && certs.length > 0) {
          // Check for expired certs still listed
          const now = new Date();
          const expiredActive = certs.filter((c: any) => new Date(c.not_after) < now).slice(0, 5);
          if (expiredActive.length > 3) {
            findings.push({ id: "ssl-expired-certs", category: "SSL/TLS", severity: "info", title: "Multiple Expired Certificates", description: `${expiredActive.length} expired certificates in CT logs.`, recommendation: "Clean up old certificates.", confidence: 70 });
          }

          // Check for wildcard certs
          const wildcards = certs.filter((c: any) => c.common_name?.startsWith("*."));
          if (wildcards.length > 0) {
            findings.push({ id: "ssl-wildcard", category: "SSL/TLS", severity: "info", title: "Wildcard Certificate in Use", description: `Wildcard cert found for *.${hostname}.`, recommendation: "Consider individual certs for better security isolation.", confidence: 75 });
          }
        }
      }
    } catch {}

    // Test for TLS version by checking if old protocols are mentioned in server headers
    const serverHeader = `${headers.get("server") || ""} ${headers.get("via") || ""}`.toLowerCase();
    if (serverHeader.includes("tls/1.0") || serverHeader.includes("ssl/3")) {
      findings.push({ id: "ssl-oldtls", category: "SSL/TLS", severity: "high", title: "Legacy TLS/SSL Detected", description: "Server may support deprecated TLS 1.0 or SSL 3.0.", recommendation: "Disable TLS 1.0/1.1 and SSL 3.0.", owasp: "A02", confidence: 70 });
    }

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
          // Test with common default credentials (passive check - just see if endpoint exists)
          findings.push({ id: `auth-endpoint-${path.replace(/\//g, "")}`, category: "Authentication", severity: "info", title: `Auth Endpoint Found: ${path}`, description: `Login endpoint discovered at ${path}.`, recommendation: "Ensure strong authentication and brute-force protection.", owasp: "A07", confidence: 70 });
          break;
        }
      } catch {}
    }

    // Check for JWT in response headers or common patterns
    try {
      const mainRes = await fetch(url);
      const body = await mainRes.text();

      // Check for JWT patterns in page source
      const jwtPattern = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/;
      if (jwtPattern.test(body)) {
        findings.push({ id: "auth-jwt-exposed", category: "Session", severity: "high", title: "JWT Token Exposed in Page Source", description: "A JWT token was found in the HTML source.", recommendation: "Never embed tokens in HTML. Use HttpOnly cookies or secure storage.", owasp: "A07", confidence: 85 });
      }

      // Check for session IDs in URL
      if (body.match(/[?&](session|sid|token|auth)=[a-zA-Z0-9]{10,}/i)) {
        findings.push({ id: "auth-session-url", category: "Session", severity: "high", title: "Session Token in URL Parameters", description: "Session identifiers found in URL query parameters.", recommendation: "Use cookies or headers for session management.", owasp: "A07", confidence: 80 });
      }

      // Check for OAuth misconfig indicators
      if (body.includes("client_secret") || body.includes("client_id")) {
        findings.push({ id: "auth-oauth-leak", category: "Authentication", severity: "critical", title: "OAuth Credentials in Source", description: "OAuth client_id or client_secret found in page source.", recommendation: "Move OAuth secrets to server-side.", owasp: "A07", confidence: 85 });
      }
    } catch {}

    // Check for password reset endpoints without rate limiting
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
    // Check robots.txt
    try {
      const robotsRes = await fetch(`${baseUrl}/robots.txt`);
      if (robotsRes.ok) {
        const robots = await robotsRes.text();
        const disallowed = robots.match(/Disallow:\s*(.+)/gi) || [];
        const sensitive = disallowed.filter(d =>
          /admin|backup|config|secret|internal|private|api|debug/i.test(d)
        );
        if (sensitive.length > 0) {
          findings.push({ id: "info-robots", category: "Information Disclosure", severity: "low", title: "Sensitive Paths in robots.txt", description: `robots.txt reveals: ${sensitive.slice(0, 5).join(", ")}`, recommendation: "Review if these paths need to be in robots.txt.", owasp: "A05", confidence: 80 });
        }
      }
    } catch {}

    // Check for exposed config/source files
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
    ];

    for (const file of exposedFiles) {
      try {
        const res = await fetch(`${baseUrl}${file.path}`, { redirect: "manual" });
        if (res.status === 200) {
          const body = await res.text();
          // Verify it's not a generic 404 page
          if (body.length > 5 && !body.toLowerCase().includes("not found") && !body.toLowerCase().includes("404")) {
            findings.push({ id: file.id, category: "Information Disclosure", severity: file.severity, title: file.title, description: `${file.path} is accessible.`, recommendation: "Block access to this file.", owasp: "A05", confidence: 85 });
          }
        }
      } catch {}
    }

    // Check sitemap.xml for sensitive paths
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

    // Check for email addresses in page source
    try {
      const mainRes = await fetch(url);
      const body = await mainRes.text();
      const emails = body.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
      if (emails && emails.length > 3) {
        const unique = [...new Set(emails)];
        findings.push({ id: "info-emails", category: "Information Disclosure", severity: "low", title: "Email Addresses Exposed", description: `${unique.length} unique email(s) found in page source.`, recommendation: "Obfuscate email addresses to prevent scraping.", owasp: "A05", confidence: 75 });
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

    // WAF fingerprinting
    const wafSignatures = [
      { pattern: /cloudflare/i, name: "Cloudflare", header: "cf-ray" },
      { pattern: /aws/i, name: "AWS WAF", header: "x-amzn-waf" },
      { pattern: /akamai/i, name: "Akamai", header: "x-akamai" },
      { pattern: /sucuri/i, name: "Sucuri", header: "x-sucuri" },
      { pattern: /imperva|incapsula/i, name: "Imperva/Incapsula", header: "x-iinfo" },
      { pattern: /f5|big-?ip/i, name: "F5 BIG-IP", header: "x-cnection" },
      { pattern: /barracuda/i, name: "Barracuda", header: "barra_counter" },
      { pattern: /fortinet|fortigate/i, name: "Fortinet", header: "fortigate" },
    ];

    let wafDetected = false;
    for (const waf of wafSignatures) {
      if (waf.pattern.test(allHeaders) || headers.get(waf.header)) {
        findings.push({ id: `waf-${waf.name.toLowerCase().replace(/\s/g, "")}`, category: "WAF", severity: "info", title: `WAF Detected: ${waf.name}`, description: `${waf.name} WAF/CDN is protecting this application.`, recommendation: "Ensure WAF rules are up to date.", confidence: 85 });
        wafDetected = true;
        break;
      }
    }

    // Check Cloudflare specifically
    if (headers.get("cf-ray")) {
      if (!wafDetected) {
        findings.push({ id: "waf-cloudflare", category: "WAF", severity: "info", title: "WAF Detected: Cloudflare", description: "Cloudflare is active.", recommendation: "Review Cloudflare security settings.", confidence: 95 });
        wafDetected = true;
      }
    }

    if (!wafDetected) {
      findings.push({ id: "waf-none", category: "WAF", severity: "high", title: "No WAF Detected", description: "No Web Application Firewall detected. Application is directly exposed.", recommendation: "Deploy a WAF (e.g., Cloudflare, AWS WAF) to protect against common attacks.", owasp: "A05", confidence: 70 });
    }

    // Test if WAF blocks common attack patterns
    if (wafDetected) {
      try {
        const attackRes = await fetch(`${url}?id=1%20OR%201%3D1`, { redirect: "manual" });
        if (attackRes.status !== 403 && attackRes.status !== 406 && attackRes.status !== 429) {
          findings.push({ id: "waf-bypass", category: "WAF", severity: "medium", title: "WAF May Not Block SQLi Patterns", description: "Basic SQL injection pattern was not blocked.", recommendation: "Review and tighten WAF rules.", owasp: "A03", confidence: 55 });
        }
      } catch {}
    }

    // Check for rate limiting on malicious patterns
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
    // SQL injection error detection (passive - just checking error messages)
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

    // Path traversal detection
    try {
      const travRes = await fetch(`${baseUrl}?file=../../etc/passwd`, { redirect: "manual" });
      const body = await travRes.text();
      if (body.includes("root:") && body.includes("/bin/")) {
        findings.push({ id: "inj-traversal", category: "Injection", severity: "critical", title: "Path Traversal Vulnerability", description: "Server responded with /etc/passwd content.", recommendation: "Sanitize file path inputs. Use allowlists.", owasp: "A03", confidence: 90 });
      }
    } catch {}

    // Open redirect detection
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

    // Check for SSTI patterns
    try {
      const sstiRes = await fetch(`${baseUrl}?name={{7*7}}`, { redirect: "manual" });
      const body = await sstiRes.text();
      if (body.includes("49") && !body.includes("{{7*7}}")) {
        findings.push({ id: "inj-ssti", category: "Injection", severity: "critical", title: "Server-Side Template Injection", description: "Template expression was evaluated on the server.", recommendation: "Sanitize all user inputs in templates.", owasp: "A03", confidence: 75 });
      }
    } catch {}

    // Check for command injection indicators
    try {
      const cmdRes = await fetch(`${baseUrl}?cmd=;id`, { redirect: "manual" });
      const body = await cmdRes.text();
      if (body.match(/uid=\d+\(/) || body.match(/gid=\d+/)) {
        findings.push({ id: "inj-cmdi", category: "Injection", severity: "critical", title: "Command Injection Detected", description: "System command output detected in response.", recommendation: "Never pass user input to system commands.", owasp: "A03", confidence: 85 });
      }
    } catch {}

    if (findings.length === 0) findings.push({ id: "inj-ok", category: "Injection", severity: "info", title: "No Injection Surfaces Found", description: "No obvious injection vulnerabilities detected.", recommendation: "Conduct manual penetration testing.", confidence: 100 });
  } catch (err) {
    findings.push({ id: "inj-err", category: "Injection", severity: "info", title: "Injection Scan Limited", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Manual injection testing recommended.", confidence: 50 });
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
    weightedScore += base * weight * confidence;
  }

  // Combination bonuses (synergistic risk)
  const hasNoWaf = findings.some(f => f.id === "waf-none");
  const hasInjection = findings.some(f => f.category === "Injection" && f.severity !== "info");
  const hasNoAuth = findings.some(f => f.id === "api-noauth");
  const hasNoHTTPS = findings.some(f => f.id === "dep-https" || f.id === "inf-notls");

  if (hasNoWaf && hasInjection) weightedScore += 15;
  if (hasNoAuth && hasInjection) weightedScore += 20;
  if (hasNoHTTPS && hasNoAuth) weightedScore += 10;

  const score = Math.min(100, Math.round(weightedScore));
  const risk_level = score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : "low";
  return { risk_level, risk_score: score };
}

// ========== OWASP MAPPING ==========

function buildOwaspMapping(findings: Finding[]): Record<string, { count: number; severity: string; findings: string[] }> {
  const mapping: Record<string, { count: number; severity: string; findings: string[] }> = {};
  for (const [code, name] of Object.entries(OWASP_CATEGORIES)) {
    mapping[code] = { count: 0, severity: "none", findings: [] };
  }

  for (const f of findings) {
    if (f.owasp && mapping[f.owasp]) {
      mapping[f.owasp].count++;
      mapping[f.owasp].findings.push(f.title);
      // Elevate severity
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

    // PCI-DSS checks
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

    // SOC2 checks
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

    // ISO27001 checks
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

function generateSummary(url: string, findings: Finding[], risk: { risk_level: string; risk_score: number }, compliance: Record<string, any>): string {
  const hostname = (() => { try { return new URL(url).hostname; } catch { return url; } })();
  const critCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const failedCompliance = Object.entries(compliance).filter(([, v]) => v.status === "fail").map(([k]) => k);

  let summary = `VAPT Assessment for ${hostname} — Risk Level: ${risk.risk_level.toUpperCase()} (${risk.risk_score}/100). `;
  summary += `Identified ${findings.length} findings across 10 security modules. `;

  if (critCount > 0) summary += `⚠️ ${critCount} critical vulnerabilities require immediate attention. `;
  if (highCount > 0) summary += `${highCount} high-severity issues should be prioritized. `;
  if (failedCompliance.length > 0) summary += `Compliance failures: ${failedCompliance.join(", ")}. `;
  if (critCount === 0 && highCount === 0) summary += `No critical or high-severity issues found. Security posture is strong. `;

  return summary;
}

// ========== REMEDIATION PRIORITY ==========

function buildRemediationPriority(findings: Finding[]): Array<{ title: string; severity: string; effort: string; impact: string; category: string }> {
  const effortMap: Record<string, string> = {
    "Security Headers": "Low", "Cookie Security": "Low", "Information Disclosure": "Low",
    "CORS": "Medium", "Rate Limiting": "Medium", "WAF": "Medium", "DNS Security": "Medium",
    "SSL/TLS": "Medium", "Encryption": "Medium",
    "Authentication": "High", "Injection": "High", "Access Control": "High", "Session": "High",
  };

  const actionable = findings.filter(f => f.severity !== "info");
  const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

  return actionable
    .sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4))
    .map(f => ({
      title: f.title,
      severity: f.severity,
      effort: effortMap[f.category] || "Medium",
      impact: f.severity === "critical" ? "Critical" : f.severity === "high" ? "High" : "Moderate",
      category: f.category,
    }));
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
      .insert({ user_id: userId, target_url: normalizedUrl, status: "running", webhook_trigger: webhook, total_stages: 10 })
      .select("id")
      .single();

    if (pipeErr || !pipeline) {
      return new Response(JSON.stringify({ error: "Failed to create pipeline" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const allFindings: Finding[] = [];
    const stageResults: Record<string, { findings: Finding[]; risk_level: string; risk_score: number; duration_ms: number }> = {};
    const completedStages: string[] = [];

    // Run all 10 scan stages sequentially
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
    };

    for (const stage of SCAN_STAGES) {
      const stageStart = Date.now();
      const scanFn = scanFunctions[stage];
      const findings = await scanFn(normalizedUrl);

      const stageRisk = calculateWeightedRisk(findings);
      const stageDuration = Date.now() - stageStart;
      stageResults[stage] = { findings, ...stageRisk, duration_ms: stageDuration };
      allFindings.push(...findings);
      completedStages.push(stage);

      // Save individual scan record linked to pipeline
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

      // Update pipeline progress
      await supabase.from("cloud_scan_pipelines").update({ completed_stages: completedStages }).eq("id", pipeline.id);
    }

    // Calculate overall risk with weighted scoring
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
    const remediationPriority = buildRemediationPriority(allFindings);
    const executiveSummary = generateSummary(normalizedUrl, allFindings, overall, complianceFlags);

    // Calculate attack surface score
    const categoriesHit = new Set(allFindings.filter(f => f.severity !== "info").map(f => f.category));
    const attackSurfaceScore = Math.min(100, Math.round((categoriesHit.size / 12) * 100));

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
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  } catch (err) {
    console.error("Pipeline error:", err);
    return new Response(JSON.stringify({ error: "Pipeline failed" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
