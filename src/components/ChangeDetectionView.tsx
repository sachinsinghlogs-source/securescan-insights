import { useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { 
  GitCompare, 
  Plus, 
  Minus, 
  AlertTriangle,
  CheckCircle,
  ShieldOff,
  Shield,
  TrendingDown,
  TrendingUp,
  Info,
  Lock,
  Unlock
} from 'lucide-react';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import type { Scan } from '@/types/database';

interface ChangeDetectionViewProps {
  currentScan: Scan;
  previousScan?: Scan;
  compact?: boolean;
}

interface Change {
  type: 'added' | 'removed' | 'changed';
  category: 'header' | 'ssl' | 'risk' | 'tech' | 'score';
  label: string;
  detail?: string;
  severity: 'good' | 'warning' | 'bad';
  impact: string;
  recommendation?: string;
}

// Security impact explanations for each header
const headerImpacts: Record<string, { impact: string; recommendation: string }> = {
  'Strict-Transport-Security': {
    impact: 'Without HSTS, attackers can downgrade connections to HTTP and intercept sensitive data.',
    recommendation: 'Add HSTS header to force HTTPS connections and protect against man-in-the-middle attacks.',
  },
  'Content-Security-Policy': {
    impact: 'Missing CSP allows XSS attacks where malicious scripts can steal user data or credentials.',
    recommendation: 'Implement a restrictive CSP to control which resources can be loaded on your pages.',
  },
  'X-Frame-Options': {
    impact: 'Your site can be embedded in malicious iframes for clickjacking attacks.',
    recommendation: 'Set X-Frame-Options to DENY or SAMEORIGIN to prevent framing attacks.',
  },
  'X-Content-Type-Options': {
    impact: 'Browsers may misinterpret file types, leading to XSS via MIME type confusion.',
    recommendation: 'Add "nosniff" header to prevent MIME type sniffing vulnerabilities.',
  },
  'Referrer-Policy': {
    impact: 'Sensitive URL information may leak to third-party sites via the Referer header.',
    recommendation: 'Set a restrictive Referrer-Policy to control information sharing.',
  },
  'Permissions-Policy': {
    impact: 'Browser features like camera, microphone, or geolocation may be exploited.',
    recommendation: 'Define which browser features your site actually needs access to.',
  },
  'X-XSS-Protection': {
    impact: 'Legacy XSS filter is disabled, reducing defense-in-depth against XSS.',
    recommendation: 'While deprecated, enabling this provides additional protection in older browsers.',
  },
};

const getDefaultImpact = (header: string, isRemoved: boolean): { impact: string; recommendation: string } => {
  return headerImpacts[header] || {
    impact: isRemoved 
      ? 'Removing security headers weakens your defense-in-depth posture.'
      : 'Adding security headers strengthens your overall security.',
    recommendation: isRemoved
      ? 'Review server configuration to ensure security headers are properly set.'
      : 'Good job! Continue maintaining your security headers.',
  };
};

export default function ChangeDetectionView({ 
  currentScan, 
  previousScan,
  compact = false
}: ChangeDetectionViewProps) {
  const changes = useMemo(() => {
    if (!previousScan) return [];

    const detectedChanges: Change[] = [];

    // SSL Changes
    if (previousScan.ssl_valid !== currentScan.ssl_valid) {
      const sslBecameValid = currentScan.ssl_valid && !previousScan.ssl_valid;
      detectedChanges.push({
        type: 'changed',
        category: 'ssl',
        label: 'SSL Status',
        detail: `${previousScan.ssl_valid ? 'Valid' : 'Invalid'} → ${currentScan.ssl_valid ? 'Valid' : 'Invalid'}`,
        severity: sslBecameValid ? 'good' : 'bad',
        impact: sslBecameValid 
          ? 'SSL is now valid, protecting data in transit with encryption.'
          : 'SSL became invalid! All traffic is now unencrypted and vulnerable to interception.',
        recommendation: sslBecameValid 
          ? 'Great! Ensure your certificate is renewed before expiry.'
          : 'CRITICAL: Immediately restore a valid SSL certificate.',
      });
    }

    // Risk Score Changes
    if (previousScan.risk_score !== null && currentScan.risk_score !== null) {
      const scoreDiff = currentScan.risk_score - (previousScan.risk_score || 0);
      if (Math.abs(scoreDiff) >= 5) {
        detectedChanges.push({
          type: 'changed',
          category: 'score',
          label: 'Risk Score',
          detail: `${previousScan.risk_score} → ${currentScan.risk_score} (${scoreDiff > 0 ? '+' : ''}${scoreDiff})`,
          severity: scoreDiff < 0 ? 'good' : 'bad',
          impact: scoreDiff < 0 
            ? `Risk reduced by ${Math.abs(scoreDiff)} points. Your security posture is improving.`
            : `Risk increased by ${scoreDiff} points. Security has degraded.`,
          recommendation: scoreDiff < 0
            ? 'Continue monitoring to maintain this improvement.'
            : 'Review recent changes to identify what caused the regression.',
        });
      }
    }

    // Risk Level Changes
    if (previousScan.risk_level !== currentScan.risk_level) {
      const riskOrder = ['low', 'medium', 'high', 'critical'];
      const prevRisk = riskOrder.indexOf(previousScan.risk_level || 'low');
      const currRisk = riskOrder.indexOf(currentScan.risk_level || 'low');
      const improved = currRisk < prevRisk;
      
      detectedChanges.push({
        type: 'changed',
        category: 'risk',
        label: 'Risk Level',
        detail: `${previousScan.risk_level} → ${currentScan.risk_level}`,
        severity: improved ? 'good' : 'bad',
        impact: improved 
          ? `Risk level improved from ${previousScan.risk_level} to ${currentScan.risk_level}.`
          : `Risk level worsened from ${previousScan.risk_level} to ${currentScan.risk_level}!`,
        recommendation: improved
          ? 'Security improvements detected. Keep up the good work!'
          : 'Investigate configuration changes and remediate issues immediately.',
      });
    }

    // Header Changes
    const prevMissing = new Set(previousScan.missing_headers || []);
    const currMissing = new Set(currentScan.missing_headers || []);
    const prevPresent = new Set(previousScan.present_headers || []);
    const currPresent = new Set(currentScan.present_headers || []);

    // Headers that were added (now present, were missing)
    prevMissing.forEach(header => {
      if (currPresent.has(header)) {
        const { impact, recommendation } = getDefaultImpact(header, false);
        detectedChanges.push({
          type: 'added',
          category: 'header',
          label: header,
          detail: 'Security header added',
          severity: 'good',
          impact: `${header} is now protecting your site. ${impact}`,
          recommendation,
        });
      }
    });

    // Headers that were removed (now missing, were present)
    prevPresent.forEach(header => {
      if (currMissing.has(header)) {
        const { impact, recommendation } = getDefaultImpact(header, true);
        detectedChanges.push({
          type: 'removed',
          category: 'header',
          label: header,
          detail: 'Security header removed — REGRESSION',
          severity: 'bad',
          impact,
          recommendation,
        });
      }
    });

    // Technology Changes
    const prevTech = new Set(previousScan.detected_technologies || []);
    const currTech = new Set(currentScan.detected_technologies || []);

    currTech.forEach(tech => {
      if (!prevTech.has(tech)) {
        detectedChanges.push({
          type: 'added',
          category: 'tech',
          label: tech,
          detail: 'New technology detected',
          severity: 'warning',
          impact: `${tech} is now detectable. New technologies may introduce new attack vectors.`,
          recommendation: 'Ensure the new technology is properly configured and up-to-date.',
        });
      }
    });

    prevTech.forEach(tech => {
      if (!currTech.has(tech)) {
        detectedChanges.push({
          type: 'removed',
          category: 'tech',
          label: tech,
          detail: 'Technology no longer detected',
          severity: 'warning',
          impact: `${tech} is no longer visible. This could mean removal or better obfuscation.`,
          recommendation: 'Verify if this was intentional or indicates a configuration issue.',
        });
      }
    });

    return detectedChanges;
  }, [currentScan, previousScan]);

  // Calculate summary stats
  const summary = useMemo(() => {
    const regressions = changes.filter(c => c.severity === 'bad');
    const improvements = changes.filter(c => c.severity === 'good');
    const notices = changes.filter(c => c.severity === 'warning');
    
    return {
      regressions,
      improvements,
      notices,
      totalChanges: changes.length,
      overallStatus: regressions.length > 0 ? 'regression' : 
                     improvements.length > 0 ? 'improvement' : 'stable',
    };
  }, [changes]);

  if (!previousScan) {
    return (
      <Card className="border-border/50">
        <CardContent className="py-6 text-center text-muted-foreground">
          <GitCompare className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">First scan — no previous data to compare</p>
          <p className="text-xs mt-1 opacity-70">Future scans will show changes here</p>
        </CardContent>
      </Card>
    );
  }

  if (changes.length === 0) {
    return (
      <Card className="border-success/30 bg-success/5">
        <CardContent className="py-6 text-center">
          <CheckCircle className="w-8 h-8 mx-auto mb-2 text-success" />
          <p className="text-sm text-success font-medium">No changes detected</p>
          <p className="text-xs text-muted-foreground mt-1">
            Security configuration is stable since last scan
          </p>
        </CardContent>
      </Card>
    );
  }

  const ChangeItem = ({ change }: { change: Change }) => (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <div 
            className={`flex items-start gap-3 p-3 rounded-lg cursor-help transition-colors ${
              change.severity === 'bad' 
                ? 'bg-critical/10 border border-critical/20 hover:bg-critical/15'
                : change.severity === 'warning'
                ? 'bg-warning/10 border border-warning/20 hover:bg-warning/15'
                : 'bg-success/10 border border-success/20 hover:bg-success/15'
            }`}
          >
            {/* Icon based on type and severity */}
            <div className="shrink-0 mt-0.5">
              {change.category === 'ssl' ? (
                change.severity === 'good' ? <Lock className="w-4 h-4 text-success" /> : <Unlock className="w-4 h-4 text-critical" />
              ) : change.category === 'risk' || change.category === 'score' ? (
                change.severity === 'good' ? <TrendingDown className="w-4 h-4 text-success" /> : <TrendingUp className="w-4 h-4 text-critical" />
              ) : change.type === 'removed' ? (
                <Minus className="w-4 h-4 text-critical" />
              ) : change.type === 'added' && change.severity === 'good' ? (
                <Plus className="w-4 h-4 text-success" />
              ) : change.severity === 'warning' ? (
                <AlertTriangle className="w-4 h-4 text-warning" />
              ) : (
                <ShieldOff className="w-4 h-4 text-critical" />
              )}
            </div>
            
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">{change.label}</span>
                <Badge 
                  variant="outline" 
                  className={`text-xs ${
                    change.severity === 'bad' 
                      ? 'border-critical/30 text-critical'
                      : change.severity === 'warning'
                      ? 'border-warning/30 text-warning'
                      : 'border-success/30 text-success'
                  }`}
                >
                  {change.severity === 'bad' ? 'Regression' : 
                   change.severity === 'good' ? 'Improvement' : 'Notice'}
                </Badge>
              </div>
              {change.detail && (
                <p className="text-xs text-muted-foreground mt-1">{change.detail}</p>
              )}
              {!compact && (
                <div className="flex items-start gap-1 mt-2 text-xs text-muted-foreground">
                  <Info className="w-3 h-3 mt-0.5 shrink-0" />
                  <span className="line-clamp-2">{change.impact}</span>
                </div>
              )}
            </div>
          </div>
        </TooltipTrigger>
        <TooltipContent side="left" className="max-w-sm p-4">
          <div className="space-y-2">
            <p className="font-medium text-sm">{change.label}</p>
            <p className="text-xs text-muted-foreground">{change.impact}</p>
            {change.recommendation && (
              <div className="pt-2 border-t border-border">
                <p className="text-xs font-medium">Recommendation:</p>
                <p className="text-xs text-muted-foreground">{change.recommendation}</p>
              </div>
            )}
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );

  return (
    <Card className={`border-glow glass ${
      summary.overallStatus === 'regression' ? 'border-critical/30' :
      summary.overallStatus === 'improvement' ? 'border-success/30' : ''
    }`}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <GitCompare className="w-4 h-4 text-primary" />
            What Changed
          </CardTitle>
          <div className="flex gap-2">
            {summary.improvements.length > 0 && (
              <Badge className="bg-success/20 text-success border-success/30 gap-1">
                <TrendingDown className="w-3 h-3" />
                {summary.improvements.length} improved
              </Badge>
            )}
            {summary.regressions.length > 0 && (
              <Badge className="bg-critical/20 text-critical border-critical/30 gap-1">
                <TrendingUp className="w-3 h-3" />
                {summary.regressions.length} regression{summary.regressions.length !== 1 ? 's' : ''}
              </Badge>
            )}
            {summary.notices.length > 0 && (
              <Badge className="bg-warning/20 text-warning border-warning/30">
                {summary.notices.length} notice{summary.notices.length !== 1 ? 's' : ''}
              </Badge>
            )}
          </div>
        </div>
        
        {/* Summary Banner */}
        {summary.regressions.length > 0 && (
          <div className="mt-3 p-3 rounded-lg bg-critical/10 border border-critical/20">
            <p className="text-sm font-medium text-critical flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              Security Regression Detected
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              {summary.regressions.length} change{summary.regressions.length !== 1 ? 's' : ''} weakened your security since the last scan. 
              Review and remediate these issues.
            </p>
          </div>
        )}
        
        {summary.overallStatus === 'improvement' && summary.regressions.length === 0 && (
          <div className="mt-3 p-3 rounded-lg bg-success/10 border border-success/20">
            <p className="text-sm font-medium text-success flex items-center gap-2">
              <CheckCircle className="w-4 h-4" />
              Security Improved
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              {summary.improvements.length} improvement{summary.improvements.length !== 1 ? 's' : ''} detected. 
              Your security posture is getting stronger.
            </p>
          </div>
        )}
      </CardHeader>
      
      <CardContent className="space-y-2">
        {/* Regressions first (most important) */}
        {summary.regressions.map((change, i) => (
          <ChangeItem key={`bad-${i}`} change={change} />
        ))}

        {/* Then improvements */}
        {summary.improvements.map((change, i) => (
          <ChangeItem key={`good-${i}`} change={change} />
        ))}

        {/* Then notices */}
        {summary.notices.map((change, i) => (
          <ChangeItem key={`warn-${i}`} change={change} />
        ))}
      </CardContent>
    </Card>
  );
}
