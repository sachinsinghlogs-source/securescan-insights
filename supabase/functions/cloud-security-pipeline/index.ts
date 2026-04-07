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
}

const SCAN_STAGES = ["deployment", "api", "storage", "infrastructure"] as const;

// ========== SCAN MODULES ==========

async function scanDeployment(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const res = await fetch(url, { redirect: "manual" });
    const headers = res.headers;

    if (url.startsWith("http://")) {
      findings.push({ id: "dep-https", category: "Transport Security", severity: "critical", title: "No HTTPS Encryption", description: "Deployment not using HTTPS.", recommendation: "Enable HTTPS/TLS." });
    }

    const secHeaders = [
      { name: "strict-transport-security", id: "dep-hsts", severity: "high" as const, title: "Missing HSTS" },
      { name: "content-security-policy", id: "dep-csp", severity: "high" as const, title: "Missing CSP" },
      { name: "x-frame-options", id: "dep-xfo", severity: "medium" as const, title: "Missing X-Frame-Options" },
      { name: "x-content-type-options", id: "dep-xcto", severity: "medium" as const, title: "Missing X-Content-Type-Options" },
      { name: "referrer-policy", id: "dep-ref", severity: "medium" as const, title: "Missing Referrer-Policy" },
      { name: "permissions-policy", id: "dep-perm", severity: "medium" as const, title: "Missing Permissions-Policy" },
    ];

    for (const h of secHeaders) {
      if (!headers.get(h.name)) {
        findings.push({ id: h.id, category: "Security Headers", severity: h.severity, title: h.title, description: `${h.name} header is missing.`, recommendation: `Add ${h.name} header.` });
      }
    }

    const server = headers.get("server");
    if (server && (server.includes("/") || server.match(/\d+\.\d+/))) {
      findings.push({ id: "dep-server", category: "Information Disclosure", severity: "low", title: "Server Version Exposed", description: `Server: "${server}"`, recommendation: "Remove or obfuscate Server header." });
    }

    const cookies = res.headers.get("set-cookie");
    if (cookies) {
      if (!cookies.toLowerCase().includes("secure")) findings.push({ id: "dep-cookie-secure", category: "Cookie Security", severity: "high", title: "Cookie Missing Secure Flag", description: "Cookies sent over insecure connections.", recommendation: "Add Secure flag." });
      if (!cookies.toLowerCase().includes("httponly")) findings.push({ id: "dep-cookie-http", category: "Cookie Security", severity: "medium", title: "Cookie Missing HttpOnly", description: "Cookies accessible via JS.", recommendation: "Add HttpOnly flag." });
      if (!cookies.toLowerCase().includes("samesite")) findings.push({ id: "dep-cookie-same", category: "Cookie Security", severity: "medium", title: "Cookie Missing SameSite", description: "CSRF risk.", recommendation: "Add SameSite flag." });
    }

    if (findings.length === 0) findings.push({ id: "dep-ok", category: "Deployment", severity: "info", title: "Deployment Secure", description: "No issues found.", recommendation: "Continue monitoring." });
  } catch (err) {
    findings.push({ id: "dep-err", category: "Connectivity", severity: "high", title: "Could Not Reach Deployment", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Verify URL." });
  }
  return findings;
}

async function scanApi(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const unauthRes = await fetch(url);
    if (unauthRes.ok) findings.push({ id: "api-noauth", category: "Authentication", severity: "critical", title: "API Without Auth", description: "Returns 200 without authentication.", recommendation: "Require auth for all endpoints." });

    const corsRes = await fetch(url, { method: "OPTIONS", headers: { Origin: "https://evil.com", "Access-Control-Request-Method": "POST" } });
    const ao = corsRes.headers.get("access-control-allow-origin");
    if (ao === "*") findings.push({ id: "api-cors-wild", category: "CORS", severity: "high", title: "CORS Allows All Origins", description: "Access-Control-Allow-Origin: *", recommendation: "Restrict to trusted origins." });
    else if (ao === "https://evil.com") findings.push({ id: "api-cors-reflect", category: "CORS", severity: "critical", title: "CORS Origin Reflection", description: "Reflects any origin.", recommendation: "Validate against whitelist." });

    const rl = unauthRes.headers;
    if (!rl.get("x-ratelimit-limit") && !rl.get("ratelimit-limit") && !rl.get("retry-after")) {
      findings.push({ id: "api-norate", category: "Rate Limiting", severity: "high", title: "No Rate Limiting", description: "No rate limit headers.", recommendation: "Implement rate limiting." });
    }

    try {
      const errRes = await fetch(url + "/<script>alert(1)</script>");
      const errBody = await errRes.text();
      if (errBody.includes("<script>alert(1)</script>")) findings.push({ id: "api-xss", category: "Injection", severity: "critical", title: "XSS in Error Response", description: "Reflects input unsanitized.", recommendation: "Sanitize all output." });
      if (errBody.includes("stack") || errBody.includes("at /")) findings.push({ id: "api-stack", category: "Information Disclosure", severity: "high", title: "Stack Trace Exposed", description: "Leaks internals.", recommendation: "Use generic errors in production." });
    } catch {}

    if (findings.length === 0) findings.push({ id: "api-ok", category: "API Security", severity: "info", title: "API Secure", description: "No issues found.", recommendation: "Continue monitoring." });
  } catch (err) {
    findings.push({ id: "api-err", category: "Connectivity", severity: "high", title: "Could Not Reach API", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Verify URL." });
  }
  return findings;
}

async function scanStorage(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const res = await fetch(url);
    if (res.ok) findings.push({ id: "sto-public", category: "Access Control", severity: "critical", title: "Storage Publicly Accessible", description: "No auth required.", recommendation: "Restrict with IAM/signed URLs." });

    const body = await res.text();
    if (body.includes("<ListBucketResult") || body.includes("<Contents>")) findings.push({ id: "sto-listing", category: "Access Control", severity: "critical", title: "Bucket Listing Enabled", description: "All files exposed.", recommendation: "Disable listing." });

    const sensitive = [".env", "config.json", "credentials", ".pem", ".key", "secret"];
    const found = sensitive.filter(p => body.toLowerCase().includes(p));
    if (found.length > 0) findings.push({ id: "sto-sensitive", category: "Data Exposure", severity: "critical", title: "Sensitive Files Found", description: `Found: ${found.join(", ")}`, recommendation: "Remove and rotate credentials." });

    if (res.headers.get("access-control-allow-origin") === "*") findings.push({ id: "sto-cors", category: "CORS", severity: "medium", title: "Storage CORS Open", description: "Allows all origins.", recommendation: "Restrict CORS." });

    if (!res.headers.get("x-amz-server-side-encryption") && !res.headers.get("x-goog-encryption-algorithm") && res.ok) {
      findings.push({ id: "sto-encrypt", category: "Encryption", severity: "medium", title: "No Encryption Detected", description: "May not be encrypted at rest.", recommendation: "Enable SSE." });
    }

    if (findings.length === 0) findings.push({ id: "sto-ok", category: "Storage", severity: "info", title: "Storage Secure", description: "No issues.", recommendation: "Continue auditing." });
  } catch {
    findings.push({ id: "sto-ok", category: "Storage", severity: "info", title: "Storage Not Public", description: "Could not access publicly — good.", recommendation: "Verify authorized access." });
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
    if (detected) findings.push({ id: "inf-provider", category: "Infrastructure", severity: "info", title: `Provider: ${detected.n}`, description: `Hosted on ${detected.n}.`, recommendation: "Follow provider security best practices." });

    const xpb = headers.get("x-powered-by");
    if (xpb) findings.push({ id: "inf-xpowered", category: "Information Disclosure", severity: "medium", title: "X-Powered-By Exposed", description: `Reveals: ${xpb}`, recommendation: "Remove header." });

    if (url.startsWith("https://")) findings.push({ id: "inf-tls", category: "Transport", severity: "info", title: "TLS Enabled", description: "HTTPS active.", recommendation: "Ensure TLS 1.2+." });
    else findings.push({ id: "inf-notls", category: "Transport", severity: "critical", title: "No TLS/HTTPS", description: "Not using HTTPS.", recommendation: "Enable immediately." });

    if (res.status >= 300 && res.status < 400) {
      const loc = headers.get("location");
      if (loc?.startsWith("http://")) findings.push({ id: "inf-redirect", category: "Transport", severity: "high", title: "Redirect to HTTP", description: "Redirects insecurely.", recommendation: "Redirect to HTTPS only." });
    }

    const adminPaths = ["/admin", "/wp-admin", "/console", "/_admin"];
    for (const path of adminPaths) {
      try {
        const r = await fetch(`${url.replace(/\/$/, "")}${path}`, { redirect: "manual" });
        if (r.status === 200) { findings.push({ id: `inf-admin`, category: "Access Control", severity: "high", title: `Admin Panel: ${path}`, description: "Publicly accessible.", recommendation: "Restrict access." }); break; }
      } catch {}
    }

    if (findings.length === 0) findings.push({ id: "inf-ok", category: "Infrastructure", severity: "info", title: "Infrastructure Secure", description: "No issues.", recommendation: "Continue monitoring." });
  } catch (err) {
    findings.push({ id: "inf-err", category: "Connectivity", severity: "high", title: "Unreachable", description: `${err instanceof Error ? err.message : "Unknown"}`, recommendation: "Check DNS/connectivity." });
  }
  return findings;
}

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
  return { risk_level: score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : "low", risk_score: score };
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
      .insert({ user_id: userId, target_url: normalizedUrl, status: "running", webhook_trigger: webhook })
      .select("id")
      .single();

    if (pipeErr || !pipeline) {
      return new Response(JSON.stringify({ error: "Failed to create pipeline" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const allFindings: Finding[] = [];
    const stageResults: Record<string, { findings: Finding[]; risk_level: string; risk_score: number; duration_ms: number }> = {};
    const completedStages: string[] = [];

    // Run all 4 scan stages sequentially
    for (const stage of SCAN_STAGES) {
      const stageStart = Date.now();
      let findings: Finding[];

      switch (stage) {
        case "deployment": findings = await scanDeployment(normalizedUrl); break;
        case "api": findings = await scanApi(normalizedUrl); break;
        case "storage": findings = await scanStorage(normalizedUrl); break;
        case "infrastructure": findings = await scanInfrastructure(normalizedUrl); break;
      }

      const stageRisk = calculateRisk(findings);
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

    // Calculate overall risk
    const overall = calculateRisk(allFindings);
    const totalDuration = Date.now() - startTime;
    const counts = {
      critical: allFindings.filter(f => f.severity === "critical").length,
      high: allFindings.filter(f => f.severity === "high").length,
      medium: allFindings.filter(f => f.severity === "medium").length,
      low: allFindings.filter(f => f.severity === "low").length,
      info: allFindings.filter(f => f.severity === "info").length,
    };

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
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  } catch (err) {
    console.error("Pipeline error:", err);
    return new Response(JSON.stringify({ error: "Pipeline failed" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
