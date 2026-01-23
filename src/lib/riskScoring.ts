/**
 * Risk Scoring System - Clear, Explainable Security Assessment
 * 
 * This module provides transparent risk scoring with:
 * - Clear thresholds for LOW/MEDIUM/HIGH/CRITICAL
 * - Detailed breakdown of contributing factors
 * - Actionable explanations for each risk level
 */

export interface RiskFactor {
  category: 'ssl' | 'headers' | 'cms' | 'server';
  name: string;
  points: number;
  maxPoints: number;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export interface RiskBreakdown {
  totalScore: number;
  maxPossibleScore: number;
  level: 'low' | 'medium' | 'high' | 'critical';
  levelDescription: string;
  factors: RiskFactor[];
  summary: string;
}

/**
 * Risk Level Thresholds (0-100 scale, lower is better)
 * 
 * LOW (0-25):     Excellent security posture. Minor improvements possible.
 * MEDIUM (26-50): Acceptable but improvements recommended. Some exposures.
 * HIGH (51-75):   Significant security gaps. Immediate action recommended.
 * CRITICAL (76+): Severe vulnerabilities. Urgent remediation required.
 */
export const RISK_THRESHOLDS = {
  low: { min: 0, max: 25 },
  medium: { min: 26, max: 50 },
  high: { min: 51, max: 75 },
  critical: { min: 76, max: 100 },
} as const;

export const RISK_LEVEL_DESCRIPTIONS: Record<string, { title: string; description: string; action: string }> = {
  low: {
    title: 'Low Risk',
    description: 'Your site has a strong security posture with most best practices implemented.',
    action: 'Continue monitoring and consider implementing remaining recommendations.',
  },
  medium: {
    title: 'Medium Risk',
    description: 'Your site has acceptable security but has room for improvement. Some security headers or configurations may be missing.',
    action: 'Review and implement the recommended fixes to strengthen your security posture.',
  },
  high: {
    title: 'High Risk',
    description: 'Your site has significant security gaps that could be exploited. Multiple security controls are missing or misconfigured.',
    action: 'Prioritize implementing the critical and high-severity fixes immediately.',
  },
  critical: {
    title: 'Critical Risk',
    description: 'Your site has severe vulnerabilities that require urgent attention. Users and data may be at immediate risk.',
    action: 'Take immediate action to address SSL issues and implement security headers.',
  },
};

/**
 * Point values for different security issues
 * Higher points = more severe issue
 */
const SCORING_WEIGHTS = {
  // SSL Issues (max 40 points)
  ssl_invalid: 40,
  ssl_expiring_critical: 35, // < 7 days
  ssl_expiring_warning: 25,  // < 30 days
  ssl_expiring_notice: 10,   // < 60 days
  
  // Security Headers (max 56 points - 8 per header)
  header_hsts: 10,           // HSTS is critical
  header_csp: 10,            // CSP is critical
  header_xframe: 8,          // Clickjacking protection
  header_xcontent: 6,        // MIME sniffing
  header_referrer: 6,        // Privacy
  header_permissions: 6,     // Feature control
  header_xss: 4,             // Deprecated but still useful
  
  // CMS/Technology (max 10 points)
  cms_detected: 10,          // Known CMS platform
  
  // Server Info Exposure (max 5 points)
  server_exposed: 5,         // Server version visible
} as const;

const HEADER_WEIGHTS: Record<string, number> = {
  'strict-transport-security': SCORING_WEIGHTS.header_hsts,
  'content-security-policy': SCORING_WEIGHTS.header_csp,
  'x-frame-options': SCORING_WEIGHTS.header_xframe,
  'x-content-type-options': SCORING_WEIGHTS.header_xcontent,
  'referrer-policy': SCORING_WEIGHTS.header_referrer,
  'permissions-policy': SCORING_WEIGHTS.header_permissions,
  'x-xss-protection': SCORING_WEIGHTS.header_xss,
};

const HEADER_DESCRIPTIONS: Record<string, string> = {
  'strict-transport-security': 'Forces HTTPS connections, preventing man-in-the-middle attacks',
  'content-security-policy': 'Prevents XSS attacks by controlling resource loading',
  'x-frame-options': 'Prevents clickjacking by blocking iframe embedding',
  'x-content-type-options': 'Prevents MIME-sniffing attacks',
  'referrer-policy': 'Controls information leaked to external sites',
  'permissions-policy': 'Restricts browser feature access (camera, mic, etc.)',
  'x-xss-protection': 'Legacy XSS filter for older browsers',
};

/**
 * Calculate comprehensive risk score with detailed breakdown
 */
export function calculateRiskBreakdown(
  sslValid: boolean,
  sslDaysLeft: number | null,
  missingHeaders: string[],
  presentHeaders: string[],
  detectedCms: string | null,
  serverInfo: string | null
): RiskBreakdown {
  const factors: RiskFactor[] = [];
  let totalScore = 0;
  
  // === SSL Assessment ===
  if (!sslValid) {
    factors.push({
      category: 'ssl',
      name: 'SSL Certificate Invalid or Missing',
      points: SCORING_WEIGHTS.ssl_invalid,
      maxPoints: SCORING_WEIGHTS.ssl_invalid,
      description: 'Your site is not using HTTPS or has an invalid certificate. All traffic is vulnerable to interception.',
      severity: 'critical',
    });
    totalScore += SCORING_WEIGHTS.ssl_invalid;
  } else if (sslDaysLeft !== null) {
    if (sslDaysLeft < 7) {
      factors.push({
        category: 'ssl',
        name: 'SSL Certificate Expiring Imminently',
        points: SCORING_WEIGHTS.ssl_expiring_critical,
        maxPoints: SCORING_WEIGHTS.ssl_invalid,
        description: `Certificate expires in ${sslDaysLeft} days. Browsers will show security warnings after expiry.`,
        severity: 'critical',
      });
      totalScore += SCORING_WEIGHTS.ssl_expiring_critical;
    } else if (sslDaysLeft < 30) {
      factors.push({
        category: 'ssl',
        name: 'SSL Certificate Expiring Soon',
        points: SCORING_WEIGHTS.ssl_expiring_warning,
        maxPoints: SCORING_WEIGHTS.ssl_invalid,
        description: `Certificate expires in ${sslDaysLeft} days. Schedule renewal to avoid service disruption.`,
        severity: 'high',
      });
      totalScore += SCORING_WEIGHTS.ssl_expiring_warning;
    } else if (sslDaysLeft < 60) {
      factors.push({
        category: 'ssl',
        name: 'SSL Certificate Renewal Recommended',
        points: SCORING_WEIGHTS.ssl_expiring_notice,
        maxPoints: SCORING_WEIGHTS.ssl_invalid,
        description: `Certificate expires in ${sslDaysLeft} days. Consider setting up auto-renewal.`,
        severity: 'medium',
      });
      totalScore += SCORING_WEIGHTS.ssl_expiring_notice;
    } else {
      factors.push({
        category: 'ssl',
        name: 'SSL Certificate Valid',
        points: 0,
        maxPoints: SCORING_WEIGHTS.ssl_invalid,
        description: `Certificate is valid with ${sslDaysLeft} days remaining.`,
        severity: 'info',
      });
    }
  }

  // === Security Headers Assessment ===
  for (const header of missingHeaders) {
    const headerLower = header.toLowerCase();
    const weight = HEADER_WEIGHTS[headerLower] || 6;
    const description = HEADER_DESCRIPTIONS[headerLower] || `Security header "${header}" is not configured`;
    
    let severity: RiskFactor['severity'] = 'medium';
    if (weight >= 10) severity = 'high';
    else if (weight <= 4) severity = 'low';

    factors.push({
      category: 'headers',
      name: `Missing: ${header}`,
      points: weight,
      maxPoints: weight,
      description,
      severity,
    });
    totalScore += weight;
  }

  // Note present headers as info
  for (const header of presentHeaders) {
    const headerLower = header.toLowerCase();
    const weight = HEADER_WEIGHTS[headerLower] || 6;
    const description = HEADER_DESCRIPTIONS[headerLower] || `Security header "${header}" is properly configured`;
    
    factors.push({
      category: 'headers',
      name: `Present: ${header}`,
      points: 0,
      maxPoints: weight,
      description: `✓ ${description}`,
      severity: 'info',
    });
  }

  // === CMS Detection ===
  if (detectedCms && ['WordPress', 'Drupal', 'Joomla'].includes(detectedCms)) {
    factors.push({
      category: 'cms',
      name: `CMS Detected: ${detectedCms}`,
      points: SCORING_WEIGHTS.cms_detected,
      maxPoints: SCORING_WEIGHTS.cms_detected,
      description: `${detectedCms} is a common target for automated attacks. Ensure it's updated to the latest version.`,
      severity: 'medium',
    });
    totalScore += SCORING_WEIGHTS.cms_detected;
  }

  // === Server Info Exposure ===
  if (serverInfo) {
    factors.push({
      category: 'server',
      name: 'Server Version Exposed',
      points: SCORING_WEIGHTS.server_exposed,
      maxPoints: SCORING_WEIGHTS.server_exposed,
      description: `Server reveals "${serverInfo}". This helps attackers identify known vulnerabilities.`,
      severity: 'low',
    });
    totalScore += SCORING_WEIGHTS.server_exposed;
  }

  // Cap at 100
  totalScore = Math.min(100, totalScore);

  // Determine risk level
  let level: RiskBreakdown['level'];
  if (totalScore <= RISK_THRESHOLDS.low.max) {
    level = 'low';
  } else if (totalScore <= RISK_THRESHOLDS.medium.max) {
    level = 'medium';
  } else if (totalScore <= RISK_THRESHOLDS.high.max) {
    level = 'high';
  } else {
    level = 'critical';
  }

  const levelInfo = RISK_LEVEL_DESCRIPTIONS[level];

  // Generate summary
  const criticalCount = factors.filter(f => f.severity === 'critical' && f.points > 0).length;
  const highCount = factors.filter(f => f.severity === 'high' && f.points > 0).length;
  const mediumCount = factors.filter(f => f.severity === 'medium' && f.points > 0).length;
  
  let summary = `Risk Score: ${totalScore}/100 (${levelInfo.title}).`;
  if (criticalCount > 0) {
    summary += ` ${criticalCount} critical issue${criticalCount > 1 ? 's' : ''} found.`;
  }
  if (highCount > 0) {
    summary += ` ${highCount} high-priority fix${highCount > 1 ? 'es' : ''} recommended.`;
  }
  if (mediumCount > 0) {
    summary += ` ${mediumCount} medium issue${mediumCount > 1 ? 's' : ''} to address.`;
  }

  return {
    totalScore,
    maxPossibleScore: 100,
    level,
    levelDescription: levelInfo.description,
    factors: factors.sort((a, b) => b.points - a.points), // Sort by impact
    summary,
  };
}

/**
 * Get human-readable explanation of risk level
 */
export function getRiskExplanation(level: string): { title: string; description: string; action: string } {
  return RISK_LEVEL_DESCRIPTIONS[level] || RISK_LEVEL_DESCRIPTIONS.medium;
}

/**
 * Calculate headers score as percentage
 */
export function calculateHeadersScore(presentHeaders: string[], totalChecked: number = 7): number {
  if (totalChecked === 0) return 0;
  return Math.round((presentHeaders.length / totalChecked) * 100);
}
