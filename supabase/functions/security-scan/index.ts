import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

// Important security headers to check
const SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "x-frame-options",
  "x-xss-protection",
  "referrer-policy",
  "permissions-policy",
];

// Technology detection patterns
const TECH_PATTERNS: Record<string, RegExp[]> = {
  WordPress: [/wp-content/i, /wp-includes/i, /wordpress/i],
  Drupal: [/drupal/i, /sites\/default/i],
  Joomla: [/joomla/i, /com_content/i],
  Shopify: [/shopify/i, /cdn\.shopify\.com/i],
  Wix: [/wix\.com/i, /parastorage\.com/i],
  Squarespace: [/squarespace/i, /static\.squarespace/i],
  React: [/react/i, /_next/i, /__next/i],
  Vue: [/vue/i, /nuxt/i],
  Angular: [/ng-version/i, /angular/i],
  Bootstrap: [/bootstrap/i],
  jQuery: [/jquery/i],
  Cloudflare: [/cloudflare/i, /cf-ray/i],
  nginx: [/nginx/i],
  Apache: [/apache/i],
};

interface ScanResult {
  ssl_valid: boolean;
  ssl_expiry_date: string | null;
  ssl_issuer: string | null;
  headers_score: number;
  missing_headers: string[];
  present_headers: string[];
  detected_technologies: string[];
  detected_cms: string | null;
  server_info: string | null;
  risk_score: number;
  risk_level: "low" | "medium" | "high" | "critical";
}

async function performScan(url: string): Promise<ScanResult> {
  const startTime = Date.now();
  
  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": "SecureScan/1.0 (Security Analysis Bot)",
      },
      redirect: "follow",
    });
  } catch (error) {
    console.error("Fetch error:", error);
    throw new Error("Failed to connect to the target URL. Please check the URL and try again.");
  }

  const html = await response.text();
  const headers = response.headers;

  // Check SSL (if HTTPS)
  const isHttps = url.startsWith("https://");
  const ssl_valid = isHttps && response.ok;
  
  // SSL certificate info would require additional TLS analysis
  // For now, we check if HTTPS is working
  const ssl_expiry_date = null;
  const ssl_issuer = null;

  // Check security headers
  const present_headers: string[] = [];
  const missing_headers: string[] = [];
  
  for (const header of SECURITY_HEADERS) {
    if (headers.get(header)) {
      present_headers.push(header);
    } else {
      missing_headers.push(header);
    }
  }

  // Calculate headers score
  const headers_score = Math.round((present_headers.length / SECURITY_HEADERS.length) * 100);

  // Detect technologies
  const detected_technologies: string[] = [];
  let detected_cms: string | null = null;

  // Check response headers for server info
  const server_info = headers.get("server") || headers.get("x-powered-by") || null;
  
  // Check for Cloudflare
  if (headers.get("cf-ray")) {
    detected_technologies.push("Cloudflare");
  }

  // Analyze HTML and headers for technology patterns
  const combinedContent = html + " " + Array.from(headers.entries()).join(" ");
  
  for (const [tech, patterns] of Object.entries(TECH_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(combinedContent)) {
        if (!detected_technologies.includes(tech)) {
          detected_technologies.push(tech);
        }
        // Set CMS if detected
        if (["WordPress", "Drupal", "Joomla", "Shopify", "Wix", "Squarespace"].includes(tech)) {
          detected_cms = tech;
        }
        break;
      }
    }
  }

  // Calculate risk score
  let risk_score = 0;
  
  // SSL issues add significant risk
  if (!isHttps) {
    risk_score += 40;
  } else if (!ssl_valid) {
    risk_score += 30;
  }

  // Missing security headers increase risk
  risk_score += missing_headers.length * 8;

  // Certain technologies may have known vulnerabilities
  if (detected_cms && ["WordPress", "Drupal", "Joomla"].includes(detected_cms)) {
    risk_score += 10; // CMS platforms often have plugins with vulnerabilities
  }

  // Cap at 100
  risk_score = Math.min(100, risk_score);

  // Determine risk level
  let risk_level: "low" | "medium" | "high" | "critical";
  if (risk_score <= 25) {
    risk_level = "low";
  } else if (risk_score <= 50) {
    risk_level = "medium";
  } else if (risk_score <= 75) {
    risk_level = "high";
  } else {
    risk_level = "critical";
  }

  return {
    ssl_valid,
    ssl_expiry_date,
    ssl_issuer,
    headers_score,
    missing_headers,
    present_headers,
    detected_technologies,
    detected_cms,
    server_info,
    risk_score,
    risk_level,
  };
}

Deno.serve(async (req) => {
  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Get the authorization header
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return new Response(
        JSON.stringify({ error: "Missing authorization header" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Create Supabase client
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    const supabase = createClient(supabaseUrl, supabaseKey, {
      global: { headers: { Authorization: authHeader } },
    });

    // Get the current user
    const { data: { user }, error: userError } = await supabase.auth.getUser();
    if (userError || !user) {
      return new Response(
        JSON.stringify({ error: "Unauthorized" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Get request body
    const { url } = await req.json();
    
    if (!url) {
      return new Response(
        JSON.stringify({ error: "URL is required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    console.log(`Starting scan for ${url} by user ${user.id}`);

    // Check user's plan and daily scan limit
    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", user.id)
      .single();

    if (profileError) {
      console.error("Profile error:", profileError);
      return new Response(
        JSON.stringify({ error: "Failed to fetch user profile" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Check scan limit for free users
    const today = new Date().toISOString().split("T")[0];
    const lastScanDate = profile.last_scan_date;
    let dailyScansUsed = profile.daily_scans_used || 0;

    // Reset counter if it's a new day
    if (lastScanDate !== today) {
      dailyScansUsed = 0;
    }

    // Check if user can scan (free users limited to 3/day)
    if (profile.plan_type === "free" && dailyScansUsed >= 3) {
      return new Response(
        JSON.stringify({ error: "Daily scan limit reached. Upgrade to Pro for unlimited scans." }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Create scan record
    const { data: scan, error: insertError } = await supabase
      .from("scans")
      .insert({
        user_id: user.id,
        target_url: url,
        status: "scanning",
      })
      .select()
      .single();

    if (insertError) {
      console.error("Insert error:", insertError);
      return new Response(
        JSON.stringify({ error: "Failed to create scan record" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Perform the actual scan
    const startTime = Date.now();
    
    try {
      const result = await performScan(url);
      const scanDuration = Date.now() - startTime;

      // Update scan record with results
      const { error: updateError } = await supabase
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

      if (updateError) {
        console.error("Update error:", updateError);
      }

      // Update user's daily scan count
      await supabase
        .from("profiles")
        .update({
          daily_scans_used: dailyScansUsed + 1,
          last_scan_date: today,
        })
        .eq("id", user.id);

      console.log(`Scan completed for ${url} in ${scanDuration}ms`);

      return new Response(
        JSON.stringify({ success: true, scan_id: scan.id, result }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );

    } catch (scanError) {
      console.error("Scan error:", scanError);
      
      // Update scan record as failed
      await supabase
        .from("scans")
        .update({
          status: "failed",
          raw_results: { error: scanError instanceof Error ? scanError.message : "Unknown error" },
        })
        .eq("id", scan.id);

      return new Response(
        JSON.stringify({ error: scanError instanceof Error ? scanError.message : "Scan failed" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

  } catch (error) {
    console.error("Function error:", error);
    return new Response(
      JSON.stringify({ error: error instanceof Error ? error.message : "Internal server error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
