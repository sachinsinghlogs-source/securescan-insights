/**
 * SecureScan Utilities - Security Helper Functions
 * 
 * Contains input validation, response helpers, and security constants
 */

// ============================================
// SECURITY RESPONSE HEADERS
// These headers protect against common web attacks
// ============================================
export const securityHeaders = {
  // CORS - Restrict to same origin in production
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  
  // Prevent MIME type sniffing attacks
  "X-Content-Type-Options": "nosniff",
  
  // Prevent clickjacking
  "X-Frame-Options": "DENY",
  
  // XSS Protection (legacy but still useful)
  "X-XSS-Protection": "1; mode=block",
  
  // Referrer policy - prevent leaking URLs
  "Referrer-Policy": "strict-origin-when-cross-origin",
  
  // Content type for JSON responses
  "Content-Type": "application/json",
  
  // Cache control - prevent caching sensitive responses
  "Cache-Control": "no-store, no-cache, must-revalidate, private",
  "Pragma": "no-cache",
};

// ============================================
// URL VALIDATION RESULT
// ============================================
export interface UrlValidationResult {
  valid: boolean;
  url: string | null;
  error: string | null;
}

// ============================================
// INPUT VALIDATION
// Strict validation prevents SSRF and injection attacks
// ============================================

/**
 * Validates and sanitizes URL input
 * SECURITY: Prevents SSRF by blocking internal IPs and dangerous protocols
 */
export function validateUrl(input: unknown): UrlValidationResult {
  // Type check
  if (typeof input !== "string") {
    return { valid: false, url: null, error: "URL must be a string" };
  }

  // Length check - prevent DoS via extremely long URLs
  if (input.length > 2000) {
    return { valid: false, url: null, error: "URL exceeds maximum length" };
  }

  // Trim and normalize
  let url = input.trim();
  
  // Add protocol if missing
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = `https://${url}`;
  }

  try {
    const parsed = new URL(url);

    // SECURITY: Only allow http/https protocols
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return { valid: false, url: null, error: "Only HTTP and HTTPS protocols are allowed" };
    }

    // SECURITY: Block internal/private IP ranges (SSRF protection)
    const hostname = parsed.hostname.toLowerCase();
    const blockedPatterns = [
      /^localhost$/i,
      /^127\./,
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^169\.254\./,
      /^0\./,
      /^\[::1\]$/,
      /^\[fc/i,
      /^\[fd/i,
      /^\[fe80:/i,
      /\.local$/i,
      /\.internal$/i,
      /\.localhost$/i,
    ];

    for (const pattern of blockedPatterns) {
      if (pattern.test(hostname)) {
        return { valid: false, url: null, error: "Internal or reserved addresses are not allowed" };
      }
    }

    // SECURITY: Block URLs with credentials
    if (parsed.username || parsed.password) {
      return { valid: false, url: null, error: "URLs with credentials are not allowed" };
    }

    return { valid: true, url: parsed.href, error: null };
  } catch {
    return { valid: false, url: null, error: "Invalid URL format" };
  }
}

// ============================================
// RESPONSE HELPERS
// ============================================

/**
 * Creates a sanitized error response
 * SECURITY: Never exposes internal error details
 */
export function errorResponse(message: string, status: number): Response {
  return new Response(
    JSON.stringify({ 
      error: message,
      // Don't include stack traces or internal details
    }),
    { status, headers: securityHeaders }
  );
}

/**
 * Creates a success response with security headers
 */
export function successResponse(data: unknown, status = 200): Response {
  return new Response(
    JSON.stringify(data),
    { status, headers: securityHeaders }
  );
}

/**
 * Extracts hostname from URL for safe logging
 * SECURITY: Removes sensitive path/query info from logs
 */
export function getSafeHostname(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "unknown";
  }
}
