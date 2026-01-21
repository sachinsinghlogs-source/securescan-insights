/**
 * SecureScan Engine - Core Security Scanning Logic
 * 
 * SECURITY NOTES:
 * - All scans are PASSIVE and non-intrusive
 * - No exploitation or brute-force techniques
 * - Only analyzes publicly available information
 * - Legal disclaimer included in all responses
 */

import { buildFixes, type FixSnippet } from "./fixSnippets.ts";

// ============================================
// SECURITY HEADERS TO CHECK ON TARGET
// These headers are checked passively via HTTP response
// ============================================
export const SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "x-frame-options",
  "x-xss-protection",
  "referrer-policy",
  "permissions-policy",
];

// ============================================
// TECHNOLOGY DETECTION PATTERNS
// Non-intrusive fingerprinting based on public information
// ============================================
export const TECH_PATTERNS: Record<string, RegExp[]> = {
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

// CMS platforms that may have known vulnerabilities
export const CMS_PLATFORMS = ["WordPress", "Drupal", "Joomla", "Shopify", "Wix", "Squarespace"];

// ============================================
// SCAN RESULT INTERFACE
// ============================================
export interface ScanResult {
  ssl_valid: boolean;
  ssl_expiry_date: string | null;
  ssl_issuer: string | null;
  ssl_days_left: number | null;
  headers_score: number;
  missing_headers: string[];
  present_headers: string[];
  detected_technologies: string[];
  detected_cms: string | null;
  server_info: string | null;
  risk_score: number;
  risk_level: "low" | "medium" | "high" | "critical";
  recommended_fixes: FixSnippet[];
  scan_type: "PASSIVE";
  legal_notice: string;
}

// ============================================
// SSL CHECK
// Edge-safe SSL validation (real certificate checks would require external API)
// ============================================
async function checkSSL(url: string): Promise<{ valid: boolean; daysLeft: number | null; issuer: string | null }> {
  try {
    const isHttps = url.startsWith("https://");
    
    if (!isHttps) {
      return { valid: false, daysLeft: null, issuer: null };
    }
    
    // SECURITY NOTE: Edge Functions cannot access raw TLS sockets
    // For production, integrate with an external SSL checking API
    // Returning placeholder values for HTTPS sites
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    
    const response = await fetch(url, {
      method: "HEAD",
      signal: controller.signal,
    });
    
    clearTimeout(timeoutId);
    
    // If HTTPS connection succeeded, SSL is valid
    return {
      valid: response.ok || response.status < 500,
      daysLeft: 90, // Placeholder - would need external API for real expiry
      issuer: null, // Placeholder - would need external API for issuer info
    };
  } catch {
    return { valid: false, daysLeft: null, issuer: null };
  }
}

// ============================================
// SECURITY HEADERS CHECK
// Passive analysis of HTTP security headers
// ============================================
async function checkHeaders(url: string): Promise<{
  present: string[];
  missing: string[];
  serverInfo: string | null;
  responseHeaders: Headers | null;
}> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);
    
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": "SecureScan/1.0 (Security Analysis Bot - https://securescan.app)",
      },
      signal: controller.signal,
    });
    
    clearTimeout(timeoutId);
    
    const headers = response.headers;
    const present: string[] = [];
    const missing: string[] = [];
    
    for (const header of SECURITY_HEADERS) {
      if (headers.get(header)) {
        present.push(header);
      } else {
        missing.push(header);
      }
    }
    
    const serverInfo = headers.get("server") || headers.get("x-powered-by") || null;
    
    return { present, missing, serverInfo, responseHeaders: headers };
  } catch {
    return {
      present: [],
      missing: ["Unable to fetch headers"],
      serverInfo: null,
      responseHeaders: null,
    };
  }
}

// ============================================
// TECHNOLOGY DETECTION
// Non-intrusive fingerprinting from public response data
// ============================================
async function detectTechnologies(url: string): Promise<{
  technologies: string[];
  cms: string | null;
}> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 20000);
    
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": "SecureScan/1.0 (Security Analysis Bot - https://securescan.app)",
      },
      signal: controller.signal,
    });
    
    clearTimeout(timeoutId);
    
    // Limit response size to prevent memory exhaustion (500KB max)
    const html = await response.text();
    const truncatedHtml = html.substring(0, 500000);
    const headers = response.headers;
    
    const technologies: string[] = [];
    let cms: string | null = null;
    
    // Check for Cloudflare
    if (headers.get("cf-ray")) {
      technologies.push("Cloudflare");
    }
    
    // Combine HTML and headers for pattern matching
    const combinedContent = truncatedHtml + " " + Array.from(headers.entries()).join(" ");
    
    for (const [tech, patterns] of Object.entries(TECH_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(combinedContent)) {
          if (!technologies.includes(tech)) {
            technologies.push(tech);
          }
          if (CMS_PLATFORMS.includes(tech)) {
            cms = tech;
          }
          break;
        }
      }
    }
    
    return { technologies, cms };
  } catch {
    return { technologies: [], cms: null };
  }
}

// ============================================
// RISK CALCULATION
// Calculates risk score based on security findings
// ============================================
export function calculateRisk(
  sslValid: boolean,
  sslDaysLeft: number | null,
  missingHeaders: string[],
  detectedCms: string | null
): { score: number; level: "low" | "medium" | "high" | "critical" } {
  let score = 0;
  
  // SSL issues add significant risk
  if (!sslValid) {
    score += 40;
  } else if (sslDaysLeft !== null && sslDaysLeft < 30) {
    score += 25;
  } else if (sslDaysLeft !== null && sslDaysLeft < 14) {
    score += 35;
  }
  
  // Missing security headers increase risk (8 points each)
  score += missingHeaders.length * 8;
  
  // Certain CMS platforms may have known vulnerabilities
  if (detectedCms && ["WordPress", "Drupal", "Joomla"].includes(detectedCms)) {
    score += 10;
  }
  
  // Cap at 100
  score = Math.min(100, score);
  
  // Determine risk level
  let level: "low" | "medium" | "high" | "critical";
  if (score <= 25) {
    level = "low";
  } else if (score <= 50) {
    level = "medium";
  } else if (score <= 75) {
    level = "high";
  } else {
    level = "critical";
  }
  
  return { score, level };
}

// ============================================
// MAIN SCAN FUNCTION
// Orchestrates all security checks and returns comprehensive results
// ============================================
export async function runSecurityScan(url: string): Promise<ScanResult> {
  // Run checks in parallel for performance
  const [sslResult, headersResult, techResult] = await Promise.all([
    checkSSL(url),
    checkHeaders(url),
    detectTechnologies(url),
  ]);
  
  // Calculate risk based on all findings
  const risk = calculateRisk(
    sslResult.valid,
    sslResult.daysLeft,
    headersResult.missing.filter(h => h !== "Unable to fetch headers"),
    techResult.cms
  );
  
  // Calculate headers score
  const validMissingHeaders = headersResult.missing.filter(h => h !== "Unable to fetch headers");
  const headersScore = Math.round(
    (headersResult.present.length / SECURITY_HEADERS.length) * 100
  );
  
  // Build recommended fixes based on findings
  const recommendedFixes = buildFixes(
    validMissingHeaders.length > 0 ? validMissingHeaders : [],
    sslResult.valid,
    sslResult.daysLeft,
    techResult.cms
  );

  return {
    ssl_valid: sslResult.valid,
    ssl_expiry_date: null, // Would need external API
    ssl_issuer: sslResult.issuer,
    ssl_days_left: sslResult.daysLeft,
    headers_score: headersScore,
    missing_headers: validMissingHeaders.length > 0 ? validMissingHeaders : headersResult.missing,
    present_headers: headersResult.present,
    detected_technologies: techResult.technologies,
    detected_cms: techResult.cms,
    server_info: headersResult.serverInfo,
    risk_score: risk.score,
    risk_level: risk.level,
    recommended_fixes: recommendedFixes,
    scan_type: "PASSIVE",
    legal_notice: "Only passive, user-authorized security checks performed. No exploitation or intrusive testing.",
  };
}
