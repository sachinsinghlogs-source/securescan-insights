import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
};

interface Finding {
  id: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  recommendation: string;
}

// ============================================
// SCAN MODULES
// ============================================

async function scanDeployment(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  
  try {
    const res = await fetch(url, { redirect: "manual" });
    const headers = res.headers;

    // HTTPS check
    if (url.startsWith("http://")) {
      findings.push({
        id: "dep-https",
        category: "Transport Security",
        severity: "critical",
        title: "No HTTPS Encryption",
        description: "The deployment is not using HTTPS, exposing all traffic to interception.",
        recommendation: "Enable HTTPS/TLS on your deployment. Use services like Let's Encrypt for free certificates.",
      });
    }

    // Security headers
    const secHeaders: { name: string; id: string; severity: "high" | "medium"; desc: string; rec: string }[] = [
      { name: "strict-transport-security", id: "dep-hsts", severity: "high", desc: "HSTS header missing — browsers won't enforce HTTPS.", rec: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains" },
      { name: "x-content-type-options", id: "dep-xcto", severity: "medium", desc: "X-Content-Type-Options missing — MIME sniffing attacks possible.", rec: "Add X-Content-Type-Options: nosniff" },
      { name: "x-frame-options", id: "dep-xfo", severity: "medium", desc: "X-Frame-Options missing — clickjacking attacks possible.", rec: "Add X-Frame-Options: DENY or SAMEORIGIN" },
      { name: "content-security-policy", id: "dep-csp", severity: "high", desc: "Content-Security-Policy missing — XSS attacks more likely.", rec: "Implement a strict CSP policy for your deployment." },
      { name: "x-xss-protection", id: "dep-xxss", severity: "low", desc: "X-XSS-Protection header not set.", rec: "Add X-XSS-Protection: 1; mode=block" },
      { name: "referrer-policy", id: "dep-ref", severity: "medium", desc: "Referrer-Policy missing — sensitive URLs may leak in referrers.", rec: "Add Referrer-Policy: strict-origin-when-cross-origin" },
      { name: "permissions-policy", id: "dep-perm", severity: "medium", desc: "Permissions-Policy missing — browser features not restricted.", rec: "Add Permissions-Policy to restrict camera, microphone, geolocation access." },
    ];

    for (const h of secHeaders) {
      if (!headers.get(h.name)) {
        findings.push({
          id: h.id,
          category: "Security Headers",
          severity: h.severity,
          title: `Missing ${h.name}`,
          description: h.desc,
          recommendation: h.rec,
        });
      }
    }

    // Server info disclosure
    const server = headers.get("server");
    if (server && (server.includes("/") || server.match(/\d+\.\d+/))) {
      findings.push({
        id: "dep-server",
        category: "Information Disclosure",
        severity: "low",
        title: "Server Version Exposed",
        description: `Server header reveals: "${server}". This helps attackers target known vulnerabilities.`,
        recommendation: "Remove or obfuscate the Server header to hide version information.",
      });
    }

    // Cookie security
    const cookies = res.headers.get("set-cookie");
    if (cookies) {
      if (!cookies.toLowerCase().includes("secure")) {
        findings.push({ id: "dep-cookie-secure", category: "Cookie Security", severity: "high", title: "Cookie Missing Secure Flag", description: "Cookies sent over insecure connections.", recommendation: "Add Secure flag to all cookies." });
      }
      if (!cookies.toLowerCase().includes("httponly")) {
        findings.push({ id: "dep-cookie-http", category: "Cookie Security", severity: "medium", title: "Cookie Missing HttpOnly Flag", description: "Cookies accessible via JavaScript.", recommendation: "Add HttpOnly flag to session cookies." });
      }
      if (!cookies.toLowerCase().includes("samesite")) {
        findings.push({ id: "dep-cookie-same", category: "Cookie Security", severity: "medium", title: "Cookie Missing SameSite Flag", description: "Cookies vulnerable to CSRF attacks.", recommendation: "Add SameSite=Strict or SameSite=Lax to cookies." });
      }
    }

    // No findings = good
    if (findings.length === 0) {
      findings.push({ id: "dep-ok", category: "Deployment", severity: "info", title: "Deployment Security Looks Good", description: "No major deployment security issues found.", recommendation: "Continue monitoring for changes." });
    }
  } catch (err) {
    findings.push({ id: "dep-err", category: "Connectivity", severity: "high", title: "Could Not Reach Deployment", description: `Failed to connect: ${err instanceof Error ? err.message : "Unknown error"}`, recommendation: "Verify the URL is correct and the service is running." });
  }

  return findings;
}

async function scanApi(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // Test unauthenticated access
    const unauthRes = await fetch(url, { method: "GET" });
    
    if (unauthRes.ok) {
      findings.push({
        id: "api-noauth",
        category: "Authentication",
        severity: "critical",
        title: "API Accessible Without Authentication",
        description: "The API endpoint responds with 200 without any authentication token.",
        recommendation: "Require authentication (JWT, API key, OAuth) for all API endpoints.",
      });
    }

    // CORS check
    const corsRes = await fetch(url, {
      method: "OPTIONS",
      headers: { "Origin": "https://evil-attacker.com", "Access-Control-Request-Method": "POST" },
    });
    
    const allowOrigin = corsRes.headers.get("access-control-allow-origin");
    if (allowOrigin === "*") {
      findings.push({
        id: "api-cors-wild",
        category: "CORS",
        severity: "high",
        title: "CORS Allows All Origins",
        description: "The API accepts requests from any origin (Access-Control-Allow-Origin: *)",
        recommendation: "Restrict CORS to specific trusted origins only.",
      });
    } else if (allowOrigin === "https://evil-attacker.com") {
      findings.push({
        id: "api-cors-reflect",
        category: "CORS",
        severity: "critical",
        title: "CORS Origin Reflection",
        description: "The API reflects any Origin header, allowing cross-origin attacks.",
        recommendation: "Validate the Origin header against a whitelist of allowed domains.",
      });
    }

    // Rate limiting check
    const headers = unauthRes.headers;
    const hasRateLimit = headers.get("x-ratelimit-limit") || headers.get("ratelimit-limit") || headers.get("retry-after") || headers.get("x-rate-limit-limit");
    if (!hasRateLimit) {
      findings.push({
        id: "api-norate",
        category: "Rate Limiting",
        severity: "high",
        title: "No Rate Limiting Detected",
        description: "No rate limit headers found. The API may be vulnerable to abuse.",
        recommendation: "Implement rate limiting (e.g., 100 req/min) and return X-RateLimit-* headers.",
      });
    }

    // Error handling - test with bad input
    try {
      const errorRes = await fetch(url + "/<script>alert(1)</script>", { method: "GET" });
      const errorBody = await errorRes.text();
      if (errorBody.includes("<script>alert(1)</script>")) {
        findings.push({
          id: "api-xss",
          category: "Injection",
          severity: "critical",
          title: "Potential XSS in Error Response",
          description: "The API reflects user input in error responses without sanitization.",
          recommendation: "Sanitize all user input in error messages. Use Content-Type: application/json.",
        });
      }
      if (errorBody.includes("stack") || errorBody.includes("trace") || errorBody.includes("at /")) {
        findings.push({
          id: "api-stack",
          category: "Information Disclosure",
          severity: "high",
          title: "Stack Trace Exposed in Errors",
          description: "The API leaks internal stack traces in error responses.",
          recommendation: "Return generic error messages in production. Log details server-side only.",
        });
      }
    } catch {
      // ignore
    }

    // Content-Type check
    const ct = unauthRes.headers.get("content-type");
    if (ct && !ct.includes("application/json") && !ct.includes("text/plain")) {
      findings.push({
        id: "api-ct",
        category: "Response Security",
        severity: "low",
        title: "Non-Standard Content-Type",
        description: `API returns Content-Type: ${ct}. Expected application/json for API responses.`,
        recommendation: "Use Content-Type: application/json for all API responses.",
      });
    }

    if (findings.length === 0) {
      findings.push({ id: "api-ok", category: "API Security", severity: "info", title: "API Security Looks Good", description: "No major API security issues detected.", recommendation: "Continue monitoring and testing with different input payloads." });
    }
  } catch (err) {
    findings.push({ id: "api-err", category: "Connectivity", severity: "high", title: "Could Not Reach API", description: `Failed to connect: ${err instanceof Error ? err.message : "Unknown error"}`, recommendation: "Verify the URL and that the API is running." });
  }

  return findings;
}

async function scanStorage(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // Check if URL is publicly accessible
    const res = await fetch(url, { method: "GET" });
    
    if (res.ok) {
      findings.push({
        id: "sto-public",
        category: "Access Control",
        severity: "critical",
        title: "Storage Resource Publicly Accessible",
        description: "The storage URL is publicly accessible without authentication.",
        recommendation: "Restrict access using IAM policies, signed URLs, or bucket-level permissions.",
      });
    }

    // Check for directory listing
    const body = await res.text();
    if (body.includes("<ListBucketResult") || body.includes("ListObjects") || body.includes("<Contents>")) {
      findings.push({
        id: "sto-listing",
        category: "Access Control",
        severity: "critical",
        title: "Bucket Listing Enabled",
        description: "Cloud storage bucket listing is enabled, exposing all file names.",
        recommendation: "Disable public bucket listing in your cloud provider settings.",
      });
    }

    // Check for sensitive file patterns
    const sensitivePatterns = [".env", "config.json", "credentials", ".pem", ".key", "secret"];
    const loweredBody = body.toLowerCase();
    const foundSensitive = sensitivePatterns.filter(p => loweredBody.includes(p));
    if (foundSensitive.length > 0) {
      findings.push({
        id: "sto-sensitive",
        category: "Data Exposure",
        severity: "critical",
        title: "Sensitive Files Detected",
        description: `Potentially sensitive files found: ${foundSensitive.join(", ")}`,
        recommendation: "Remove sensitive files from public storage immediately. Rotate any exposed credentials.",
      });
    }

    // CORS on storage
    const allowOrigin = res.headers.get("access-control-allow-origin");
    if (allowOrigin === "*") {
      findings.push({
        id: "sto-cors",
        category: "CORS",
        severity: "medium",
        title: "Storage CORS Allows All Origins",
        description: "Storage bucket accepts requests from any origin.",
        recommendation: "Restrict CORS to your application's domain only.",
      });
    }

    // Check for encryption headers
    const encryption = res.headers.get("x-amz-server-side-encryption") || res.headers.get("x-goog-encryption-algorithm");
    if (!encryption && res.ok) {
      findings.push({
        id: "sto-encrypt",
        category: "Encryption",
        severity: "medium",
        title: "No Server-Side Encryption Detected",
        description: "Storage objects may not be encrypted at rest.",
        recommendation: "Enable server-side encryption (SSE-S3, SSE-KMS, or CSEK) for your storage bucket.",
      });
    }

    if (findings.length === 0) {
      findings.push({ id: "sto-ok", category: "Storage Security", severity: "info", title: "Storage Security Looks Good", description: "No major storage security issues found.", recommendation: "Continue auditing storage permissions regularly." });
    }
  } catch (err) {
    findings.push({ id: "sto-err", category: "Connectivity", severity: "info", title: "Storage Not Publicly Accessible", description: "Could not access the storage URL publicly — this is generally good.", recommendation: "Verify that authorized access still works correctly." });
  }

  return findings;
}

async function scanInfrastructure(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const hostname = new URL(url).hostname;

  try {
    // Check DNS and basic connectivity
    const res = await fetch(url, { redirect: "manual" });
    const headers = res.headers;

    // Check for cloud provider identification
    const server = headers.get("server") || "";
    const via = headers.get("via") || "";
    const xPoweredBy = headers.get("x-powered-by") || "";
    const allHeaders = `${server} ${via} ${xPoweredBy}`.toLowerCase();

    const cloudProviders: { pattern: RegExp; name: string }[] = [
      { pattern: /cloudflare/i, name: "Cloudflare" },
      { pattern: /amazonaws|awselb|cloudfront/i, name: "AWS" },
      { pattern: /google|gws|gfe/i, name: "Google Cloud" },
      { pattern: /microsoft|azure/i, name: "Microsoft Azure" },
      { pattern: /vercel/i, name: "Vercel" },
      { pattern: /netlify/i, name: "Netlify" },
      { pattern: /heroku/i, name: "Heroku" },
      { pattern: /digitalocean/i, name: "DigitalOcean" },
    ];

    const detectedProvider = cloudProviders.find(p => p.pattern.test(allHeaders));
    if (detectedProvider) {
      findings.push({
        id: "inf-provider",
        category: "Infrastructure",
        severity: "info",
        title: `Cloud Provider: ${detectedProvider.name}`,
        description: `Infrastructure appears to be hosted on ${detectedProvider.name}.`,
        recommendation: "Ensure provider-specific security best practices are followed.",
      });
    }

    // Technology exposure
    if (xPoweredBy) {
      findings.push({
        id: "inf-xpowered",
        category: "Information Disclosure",
        severity: "medium",
        title: "X-Powered-By Header Exposed",
        description: `X-Powered-By: ${xPoweredBy} reveals the tech stack.`,
        recommendation: "Remove the X-Powered-By header to reduce attack surface.",
      });
    }

    // Check for redirect chains
    if (res.status >= 300 && res.status < 400) {
      const location = headers.get("location");
      if (location && location.startsWith("http://")) {
        findings.push({
          id: "inf-redirect-http",
          category: "Transport Security",
          severity: "high",
          title: "Redirect to HTTP",
          description: "The service redirects to an insecure HTTP URL.",
          recommendation: "Ensure all redirects point to HTTPS URLs.",
        });
      }
    }

    // Check TLS via HTTPS
    if (url.startsWith("https://")) {
      findings.push({
        id: "inf-tls",
        category: "Transport Security",
        severity: "info",
        title: "TLS/HTTPS Enabled",
        description: "The infrastructure is serving over HTTPS.",
        recommendation: "Ensure TLS 1.2+ and strong cipher suites.",
      });
    } else {
      findings.push({
        id: "inf-notls",
        category: "Transport Security",
        severity: "critical",
        title: "No TLS/HTTPS",
        description: "The infrastructure is not using HTTPS.",
        recommendation: "Enable HTTPS immediately. Use Let's Encrypt or your cloud provider's certificate service.",
      });
    }

    // DNS rebinding protection
    const dnsHeaders = headers.get("x-dns-prefetch-control");
    if (!dnsHeaders) {
      findings.push({
        id: "inf-dns",
        category: "DNS Security",
        severity: "low",
        title: "No DNS Prefetch Control",
        description: "X-DNS-Prefetch-Control header not set.",
        recommendation: "Add X-DNS-Prefetch-Control: off to prevent DNS prefetch attacks.",
      });
    }

    // Check for common cloud misconfigs - admin panels
    const adminPaths = ["/admin", "/_admin", "/wp-admin", "/console", "/dashboard/admin"];
    for (const path of adminPaths) {
      try {
        const adminRes = await fetch(`${url.replace(/\/$/, "")}${path}`, { redirect: "manual" });
        if (adminRes.status === 200) {
          findings.push({
            id: `inf-admin-${path.replace(/\//g, "")}`,
            category: "Access Control",
            severity: "high",
            title: `Admin Panel Accessible: ${path}`,
            description: `An admin panel at ${path} returned HTTP 200, it may be publicly accessible.`,
            recommendation: "Restrict admin panels to VPN or IP allowlists. Add authentication.",
          });
          break; // only report first one found
        }
      } catch {
        // ignore
      }
    }

  } catch (err) {
    findings.push({ id: "inf-err", category: "Connectivity", severity: "high", title: "Infrastructure Unreachable", description: `Could not connect: ${err instanceof Error ? err.message : "Unknown error"}`, recommendation: "Verify the URL and DNS configuration." });
  }

  return findings;
}

// ============================================
// RISK SCORING
// ============================================

function calculateRisk(findings: Finding[]): { risk_level: string; risk_score: number } {
  let score = 0;
  for (const f of findings) {
    switch (f.severity) {
      case "critical": score += 30; break;
      case "high": score += 20; break;
      case "medium": score += 10; break;
      case "low": score += 5; break;
    }
  }
  score = Math.min(100, score);
  
  const risk_level = score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : "low";
  return { risk_level, risk_score: score };
}

// ============================================
// MAIN HANDLER
// ============================================

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return new Response(JSON.stringify({ error: "Authentication required" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;

    const supabase = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    const token = authHeader.replace("Bearer ", "");
    const { data: claimsData, error: claimsError } = await supabase.auth.getClaims(token);
    if (claimsError || !claimsData?.claims) {
      return new Response(JSON.stringify({ error: "Invalid token" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const userId = claimsData.claims.sub as string;

    // Parse request
    let body: { url?: string; scan_type?: string };
    try {
      body = await req.json();
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { url: targetUrl, scan_type: scanType } = body;
    if (!targetUrl || !scanType) {
      return new Response(JSON.stringify({ error: "url and scan_type are required" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const validTypes = ["infrastructure", "storage", "api", "deployment"];
    if (!validTypes.includes(scanType)) {
      return new Response(JSON.stringify({ error: "Invalid scan_type" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // Normalize URL
    const normalizedUrl = targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`;

    // Create scan record
    const { data: scan, error: insertErr } = await supabase
      .from("cloud_scans")
      .insert({ user_id: userId, scan_type: scanType, target_url: normalizedUrl, status: "scanning" })
      .select("id")
      .single();

    if (insertErr || !scan) {
      return new Response(JSON.stringify({ error: "Failed to create scan" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const startTime = Date.now();

    // Run scan
    let findings: Finding[];
    switch (scanType) {
      case "infrastructure": findings = await scanInfrastructure(normalizedUrl); break;
      case "storage": findings = await scanStorage(normalizedUrl); break;
      case "api": findings = await scanApi(normalizedUrl); break;
      case "deployment": findings = await scanDeployment(normalizedUrl); break;
      default: findings = [];
    }

    const { risk_level, risk_score } = calculateRisk(findings);
    const duration = Date.now() - startTime;

    const summary = {
      total_findings: findings.length,
      critical: findings.filter(f => f.severity === "critical").length,
      high: findings.filter(f => f.severity === "high").length,
      medium: findings.filter(f => f.severity === "medium").length,
      low: findings.filter(f => f.severity === "low").length,
      info: findings.filter(f => f.severity === "info").length,
    };

    // Update scan record
    await supabase
      .from("cloud_scans")
      .update({
        status: "completed",
        risk_level,
        risk_score,
        findings,
        summary,
        scan_duration_ms: duration,
        completed_at: new Date().toISOString(),
      })
      .eq("id", scan.id);

    return new Response(JSON.stringify({
      success: true,
      scan_id: scan.id,
      risk_level,
      risk_score,
      findings,
      summary,
      scan_duration_ms: duration,
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (err) {
    console.error("Cloud scan error:", err);
    return new Response(JSON.stringify({ error: "An unexpected error occurred" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
