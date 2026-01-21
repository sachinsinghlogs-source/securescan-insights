/**
 * SecureScan Edge Function - Security-Hardened API Entry Point
 * 
 * SECURITY ARCHITECTURE:
 * ----------------------
 * 1. AUTHENTICATION: JWT validation via getClaims() - prevents unauthorized access
 * 2. AUTHORIZATION: User can only scan their own quota - prevents privilege escalation
 * 3. RATE LIMITING: Database-backed rate limiting - prevents DoS attacks
 * 4. INPUT VALIDATION: Strict URL validation with allowlist - prevents SSRF attacks
 * 5. OUTPUT SANITIZATION: Error messages are sanitized - prevents information disclosure
 * 6. AUDIT LOGGING: All actions logged - enables forensics and compliance
 * 7. SECURE HEADERS: Strict response headers - prevents XSS, clickjacking
 * 
 * OWASP Top 10 Protections:
 * - A01:2021 Broken Access Control: RLS + JWT validation
 * - A02:2021 Cryptographic Failures: TLS enforced, no sensitive data in logs
 * - A03:2021 Injection: Parameterized queries only
 * - A04:2021 Insecure Design: Defense in depth approach
 * - A05:2021 Security Misconfiguration: Strict CORS, secure defaults
 * - A07:2021 Auth Failures: Token validation, rate limiting
 * - A09:2021 Security Logging: Comprehensive audit trail
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { runSecurityScan, type ScanResult } from "./scanEngine.ts";
import { 
  securityHeaders, 
  validateUrl, 
  errorResponse, 
  successResponse,
  getSafeHostname 
} from "./utils.ts";

// ============================================
// MAIN REQUEST HANDLER
// ============================================

Deno.serve(async (req) => {
  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: securityHeaders });
  }

  // SECURITY: Only allow POST method for scans
  if (req.method !== "POST") {
    return errorResponse("Method not allowed", 405);
  }

  // Get client IP for logging (if available)
  const clientIp = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || null;
  const userAgent = req.headers.get("user-agent") || null;

  try {
    // ============================================
    // AUTHENTICATION CHECK
    // Validates JWT token to ensure user is authenticated
    // ============================================
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return errorResponse("Authentication required", 401);
    }

    // Create Supabase clients
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

    // User client for authenticated operations
    const supabase = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    // Service client for audit logging (bypasses RLS)
    const serviceClient = createClient(supabaseUrl, supabaseServiceKey);

    // Validate JWT and get claims
    const token = authHeader.replace("Bearer ", "");
    const { data: claimsData, error: claimsError } = await supabase.auth.getClaims(token);
    
    if (claimsError || !claimsData?.claims) {
      return errorResponse("Invalid or expired token", 401);
    }

    const userId = claimsData.claims.sub as string;

    // ============================================
    // RATE LIMITING CHECK
    // Prevents abuse and DoS attacks
    // ============================================
    const { data: rateLimitAllowed, error: rateLimitError } = await serviceClient.rpc(
      "check_rate_limit",
      {
        p_user_id: userId,
        p_endpoint: "security-scan",
        p_max_requests: 10, // 10 scans per 15 minutes
        p_window_minutes: 15,
      }
    );

    if (rateLimitError) {
      console.error("Rate limit check error:", rateLimitError.message);
    }

    if (rateLimitAllowed === false) {
      // Log rate limit exceeded
      await serviceClient.rpc("log_security_event", {
        p_event_type: "rate_limit_exceeded",
        p_event_category: "security",
        p_user_id: userId,
        p_ip_address: clientIp,
        p_user_agent: userAgent,
        p_resource_type: "scan",
        p_details: { endpoint: "security-scan" },
        p_severity: "warning",
      });

      return errorResponse("Rate limit exceeded. Please try again later.", 429);
    }

    // ============================================
    // INPUT VALIDATION
    // Strict validation prevents injection and SSRF
    // ============================================
    let requestBody: { url?: unknown };
    try {
      requestBody = await req.json();
    } catch {
      return errorResponse("Invalid JSON body", 400);
    }

    const validation = validateUrl(requestBody.url);
    if (!validation.valid || !validation.url) {
      return errorResponse(validation.error || "Invalid URL", 400);
    }

    const targetUrl = validation.url;
    const safeHostname = getSafeHostname(targetUrl);
    console.log(`[SCAN] User ${userId} scanning ${safeHostname}`);

    // ============================================
    // AUTHORIZATION CHECK
    // Verify user has scan quota remaining
    // ============================================
    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("plan_type, daily_scans_used, last_scan_date")
      .eq("id", userId)
      .single();

    if (profileError || !profile) {
      return errorResponse("Unable to verify account status", 403);
    }

    // Check scan limit for free users
    const today = new Date().toISOString().split("T")[0];
    let dailyScansUsed = profile.daily_scans_used || 0;

    // Reset counter if new day
    if (profile.last_scan_date !== today) {
      dailyScansUsed = 0;
    }

    // Free users limited to 3 scans/day
    if (profile.plan_type === "free" && dailyScansUsed >= 3) {
      return errorResponse("Daily scan limit reached. Upgrade to Pro for unlimited scans.", 403);
    }

    // ============================================
    // CREATE SCAN RECORD
    // ============================================
    const { data: scan, error: insertError } = await supabase
      .from("scans")
      .insert({
        user_id: userId,
        target_url: targetUrl,
        status: "scanning",
      })
      .select("id")
      .single();

    if (insertError || !scan) {
      console.error("Insert error:", insertError?.message);
      return errorResponse("Failed to initialize scan", 500);
    }

    // Log scan start
    await serviceClient.rpc("log_security_event", {
      p_event_type: "scan_started",
      p_event_category: "scan",
      p_user_id: userId,
      p_ip_address: clientIp,
      p_user_agent: userAgent,
      p_resource_type: "scan",
      p_resource_id: scan.id,
      p_details: { target_url: safeHostname },
      p_severity: "info",
    });

    // ============================================
    // PERFORM SECURITY SCAN
    // Uses modular scan engine for clean separation
    // ============================================
    const startTime = Date.now();
    
    try {
      const result: ScanResult = await runSecurityScan(targetUrl);
      const scanDuration = Date.now() - startTime;

      // Update scan record with results
      await supabase
        .from("scans")
        .update({
          status: "completed",
          risk_level: result.risk_level,
          risk_score: result.risk_score,
          ssl_valid: result.ssl_valid,
          ssl_expiry_date: result.ssl_expiry_date,
          ssl_issuer: result.ssl_issuer,
          headers_score: result.headers_score,
          missing_headers: result.missing_headers,
          present_headers: result.present_headers,
          detected_technologies: result.detected_technologies,
          detected_cms: result.detected_cms,
          server_info: result.server_info,
          scan_duration_ms: scanDuration,
          completed_at: new Date().toISOString(),
          raw_results: result,
        })
        .eq("id", scan.id);

      // Update user's daily scan count
      await supabase
        .from("profiles")
        .update({
          daily_scans_used: dailyScansUsed + 1,
          last_scan_date: today,
        })
        .eq("id", userId);

      // Log scan completion
      await serviceClient.rpc("log_security_event", {
        p_event_type: "scan_completed",
        p_event_category: "scan",
        p_user_id: userId,
        p_ip_address: clientIp,
        p_user_agent: userAgent,
        p_resource_type: "scan",
        p_resource_id: scan.id,
        p_details: { 
          target_url: safeHostname,
          risk_level: result.risk_level,
          duration_ms: scanDuration,
        },
        p_severity: "info",
      });

      console.log(`[SCAN] Completed for ${safeHostname} in ${scanDuration}ms`);

      return successResponse({ 
        success: true, 
        scan_id: scan.id, 
        result 
      });

    } catch (scanError) {
      const errorMessage = scanError instanceof Error ? scanError.message : "Scan failed";
      
      // Update scan record as failed
      await supabase
        .from("scans")
        .update({
          status: "failed",
          raw_results: { error: errorMessage },
        })
        .eq("id", scan.id);

      // Log scan failure
      await serviceClient.rpc("log_security_event", {
        p_event_type: "scan_failed",
        p_event_category: "scan",
        p_user_id: userId,
        p_ip_address: clientIp,
        p_user_agent: userAgent,
        p_resource_type: "scan",
        p_resource_id: scan.id,
        p_details: { target_url: safeHostname, error: errorMessage },
        p_severity: "warning",
      });

      return errorResponse(errorMessage, 500);
    }

  } catch (error) {
    // SECURITY: Never expose internal error details to clients
    console.error("Function error:", error instanceof Error ? error.message : "Unknown error");
    return errorResponse("An unexpected error occurred", 500);
  }
});
