/**
 * SecureScan Security Utilities
 * 
 * Client-side security helpers following OWASP guidelines.
 * These complement server-side protections but are NOT a replacement.
 * 
 * SECURITY PRINCIPLE: Defense in depth - validate on client AND server
 */

import { z } from 'zod';

// ============================================
// INPUT VALIDATION SCHEMAS
// Using Zod for type-safe validation
// ============================================

/**
 * URL validation schema
 * - Prevents XSS via javascript: URLs
 * - Prevents SSRF via internal IP addresses
 * - Limits length to prevent DoS
 */
export const urlSchema = z.string()
  .trim()
  .min(1, { message: "URL is required" })
  .max(2000, { message: "URL is too long (max 2000 characters)" })
  .refine((url) => {
    try {
      const normalized = url.startsWith('http') ? url : `https://${url}`;
      const parsed = new URL(normalized);
      
      // Only allow http/https
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return false;
      }
      
      // Block internal addresses
      const hostname = parsed.hostname.toLowerCase();
      const blockedPatterns = [
        /^localhost$/i,
        /^127\./,
        /^10\./,
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
        /^192\.168\./,
        /\.local$/i,
      ];
      
      return !blockedPatterns.some(pattern => pattern.test(hostname));
    } catch {
      return false;
    }
  }, { message: "Please enter a valid public URL" });

/**
 * Email validation schema
 * - RFC 5322 compliant
 * - Prevents injection via special characters
 */
export const emailSchema = z.string()
  .trim()
  .min(1, { message: "Email is required" })
  .max(255, { message: "Email is too long" })
  .email({ message: "Please enter a valid email address" })
  .transform(email => email.toLowerCase());

/**
 * Password validation schema
 * - Minimum 8 characters (NIST SP 800-63B)
 * - Maximum 128 characters (prevent DoS)
 * - No specific character requirements (NIST recommendation)
 */
export const passwordSchema = z.string()
  .min(8, { message: "Password must be at least 8 characters" })
  .max(128, { message: "Password is too long" });

/**
 * Strong password schema (for high-security contexts)
 */
export const strongPasswordSchema = z.string()
  .min(12, { message: "Password must be at least 12 characters" })
  .max(128, { message: "Password is too long" })
  .refine((password) => {
    // Check for basic complexity
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    return hasUpper && hasLower && hasNumber;
  }, { message: "Password must include uppercase, lowercase, and numbers" });

/**
 * Generic text input schema
 * - Prevents excessively long input
 * - Trims whitespace
 */
export const textInputSchema = (maxLength = 1000) => z.string()
  .trim()
  .max(maxLength, { message: `Input must be less than ${maxLength} characters` });

// ============================================
// OUTPUT SANITIZATION
// Prevents XSS when displaying user content
// ============================================

/**
 * HTML entity encoding map
 */
const htmlEntities: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
  '/': '&#x2F;',
  '`': '&#x60;',
  '=': '&#x3D;',
};

/**
 * Escape HTML entities to prevent XSS
 * Use when displaying user-generated content
 */
export function escapeHtml(input: string): string {
  return input.replace(/[&<>"'`=/]/g, char => htmlEntities[char] || char);
}

/**
 * Sanitize URL for safe display/linking
 * Prevents javascript: and data: URL attacks
 */
export function sanitizeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    if (['http:', 'https:'].includes(parsed.protocol)) {
      return parsed.href;
    }
    return '';
  } catch {
    return '';
  }
}

// ============================================
// SECURITY HEADERS HELPER
// For checking security posture
// ============================================

export const RECOMMENDED_HEADERS = [
  {
    name: 'Strict-Transport-Security',
    description: 'Enforces HTTPS connections',
    impact: 'high',
  },
  {
    name: 'Content-Security-Policy',
    description: 'Prevents XSS and injection attacks',
    impact: 'high',
  },
  {
    name: 'X-Content-Type-Options',
    description: 'Prevents MIME type sniffing',
    impact: 'medium',
  },
  {
    name: 'X-Frame-Options',
    description: 'Prevents clickjacking attacks',
    impact: 'medium',
  },
  {
    name: 'Referrer-Policy',
    description: 'Controls information in Referer header',
    impact: 'low',
  },
  {
    name: 'Permissions-Policy',
    description: 'Controls browser features',
    impact: 'low',
  },
] as const;

// ============================================
// ANTI-CSRF TOKEN HELPERS
// Note: Supabase handles CSRF via JWT tokens
// These are for additional protection if needed
// ============================================

/**
 * Generate a cryptographically secure random token
 */
export function generateCsrfToken(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// ============================================
// RATE LIMITING HELPERS (Client-side)
// Note: Server-side rate limiting is the primary defense
// ============================================

const requestTimestamps = new Map<string, number[]>();

/**
 * Client-side rate limiting check
 * Reduces server load by blocking obvious abuse client-side
 */
export function checkClientRateLimit(
  key: string,
  maxRequests: number,
  windowMs: number
): boolean {
  const now = Date.now();
  const timestamps = requestTimestamps.get(key) || [];
  
  // Remove old timestamps
  const validTimestamps = timestamps.filter(ts => now - ts < windowMs);
  
  if (validTimestamps.length >= maxRequests) {
    return false;
  }
  
  validTimestamps.push(now);
  requestTimestamps.set(key, validTimestamps);
  return true;
}

// ============================================
// LOGGING HELPERS
// Secure logging that doesn't expose sensitive data
// ============================================

/**
 * Mask sensitive data for logging
 */
export function maskSensitiveData(data: Record<string, unknown>): Record<string, unknown> {
  const sensitiveKeys = ['password', 'token', 'secret', 'key', 'authorization', 'cookie'];
  const masked = { ...data };
  
  for (const key of Object.keys(masked)) {
    if (sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))) {
      masked[key] = '***REDACTED***';
    }
  }
  
  return masked;
}

/**
 * Safe error message extraction
 * Prevents internal details from being exposed
 */
export function getSafeErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    // List of safe error messages to pass through
    const safeMessages = [
      'URL is required',
      'Invalid URL',
      'Authentication required',
      'Rate limit exceeded',
      'Daily scan limit reached',
      'Request timed out',
    ];
    
    for (const safe of safeMessages) {
      if (error.message.includes(safe)) {
        return error.message;
      }
    }
  }
  
  // Default generic message
  return 'An error occurred. Please try again.';
}
