import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { 
  Globe, 
  Clock, 
  Shield, 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX,
  Lock,
  Unlock,
  ChevronDown,
  ChevronUp,
  Server,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
  Download,
  Wrench
} from 'lucide-react';
import { generatePdfReport } from '@/lib/generatePdfReport';
import { formatDistanceToNow } from 'date-fns';
import FixSnippetCard, { type FixSnippet } from '@/components/FixSnippetCard';
import type { Scan } from '@/types/database';

interface ScanResultCardProps {
  scan: Scan;
}

export default function ScanResultCard({ scan }: ScanResultCardProps) {
  const [expanded, setExpanded] = useState(false);

  const getRiskBadge = () => {
    switch (scan.risk_level) {
      case 'low':
        return (
          <Badge className="risk-low gap-1">
            <ShieldCheck className="w-3 h-3" />
            Low Risk
          </Badge>
        );
      case 'medium':
        return (
          <Badge className="risk-medium gap-1">
            <ShieldAlert className="w-3 h-3" />
            Medium Risk
          </Badge>
        );
      case 'high':
        return (
          <Badge className="risk-high gap-1">
            <ShieldX className="w-3 h-3" />
            High Risk
          </Badge>
        );
      case 'critical':
        return (
          <Badge className="risk-critical gap-1">
            <ShieldX className="w-3 h-3" />
            Critical
          </Badge>
        );
      default:
        return null;
    }
  };

  const getStatusBadge = () => {
    switch (scan.status) {
      case 'completed':
        return <div className="status-dot active" />;
      case 'scanning':
        return <div className="status-dot scanning" />;
      case 'failed':
        return <div className="status-dot error" />;
      default:
        return <div className="status-dot bg-muted" />;
    }
  };

  const getHostname = () => {
    try {
      return new URL(scan.target_url).hostname;
    } catch {
      return scan.target_url;
    }
  };

  const formatDate = (date: string) => {
    return formatDistanceToNow(new Date(date), { addSuffix: true });
  };

  return (
    <Card className={`transition-all duration-200 hover:border-primary/30 ${expanded ? 'border-primary/20' : 'border-border/50'}`}>
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            {getStatusBadge()}
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                <span className="font-mono text-sm truncate">{getHostname()}</span>
              </div>
              <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                <Clock className="w-3 h-3" />
                <span>{formatDate(scan.created_at)}</span>
                {scan.scan_duration_ms && (
                  <>
                    <span>•</span>
                    <span>{(scan.scan_duration_ms / 1000).toFixed(1)}s</span>
                  </>
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-shrink-0">
            {scan.status === 'completed' && (
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                onClick={() => generatePdfReport(scan)}
                title="Download PDF Report"
              >
                <Download className="w-4 h-4" />
              </Button>
            )}
            {scan.status === 'completed' && getRiskBadge()}
            {scan.status === 'scanning' && (
              <Badge variant="secondary" className="gap-1">
                <Loader2 className="w-3 h-3 animate-spin" />
                Scanning
              </Badge>
            )}
            {scan.status === 'failed' && (
              <Badge variant="destructive" className="gap-1">
                <XCircle className="w-3 h-3" />
                Failed
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>

      {scan.status === 'completed' && (
        <CardContent className="pt-2">
          {/* Quick Stats */}
          <div className="grid grid-cols-3 gap-4 mb-4">
            <div className="flex items-center gap-2">
              {scan.ssl_valid ? (
                <Lock className="w-4 h-4 text-success" />
              ) : (
                <Unlock className="w-4 h-4 text-critical" />
              )}
              <span className="text-sm">
                {scan.ssl_valid ? 'Valid SSL' : 'SSL Issue'}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-primary" />
              <span className="text-sm">
                Headers: {scan.headers_score ?? 0}/100
              </span>
            </div>
            {scan.detected_cms && (
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-muted-foreground" />
                <span className="text-sm truncate">{scan.detected_cms}</span>
              </div>
            )}
          </div>

          {/* Risk Score Bar */}
          {scan.risk_score !== null && (
            <div className="mb-4">
              <div className="flex justify-between text-xs mb-1">
                <span className="text-muted-foreground">Risk Score</span>
                <span className="font-mono">{scan.risk_score}/100</span>
              </div>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-500 ${
                    scan.risk_score <= 30
                      ? 'bg-success'
                      : scan.risk_score <= 60
                      ? 'bg-warning'
                      : 'bg-critical'
                  }`}
                  style={{ width: `${scan.risk_score}%` }}
                />
              </div>
            </div>
          )}

          {/* Expand/Collapse Button */}
          <Button
            variant="ghost"
            size="sm"
            className="w-full"
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? (
              <>
                <ChevronUp className="w-4 h-4 mr-2" />
                Hide Details
              </>
            ) : (
              <>
                <ChevronDown className="w-4 h-4 mr-2" />
                View Details
              </>
            )}
          </Button>

          {/* Expanded Details */}
          {expanded && (
            <div className="mt-4 space-y-4 animate-fade-in">
              {/* SSL Details */}
              <div className="p-4 rounded-lg bg-muted/30 space-y-2">
                <h4 className="text-sm font-medium flex items-center gap-2">
                  <Lock className="w-4 h-4" />
                  SSL Certificate
                </h4>
                <div className="grid gap-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Status</span>
                    <span className={scan.ssl_valid ? 'text-success' : 'text-critical'}>
                      {scan.ssl_valid ? 'Valid' : 'Invalid/Missing'}
                    </span>
                  </div>
                  {scan.ssl_issuer && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Issuer</span>
                      <span className="font-mono text-xs">{scan.ssl_issuer}</span>
                    </div>
                  )}
                  {scan.ssl_expiry_date && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Expires</span>
                      <span>{new Date(scan.ssl_expiry_date).toLocaleDateString()}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Security Headers */}
              <div className="p-4 rounded-lg bg-muted/30 space-y-2">
                <h4 className="text-sm font-medium flex items-center gap-2">
                  <Shield className="w-4 h-4" />
                  Security Headers
                </h4>
                {scan.present_headers && scan.present_headers.length > 0 && (
                  <div className="space-y-1">
                    <span className="text-xs text-muted-foreground">Present:</span>
                    <div className="flex flex-wrap gap-1">
                      {scan.present_headers.map((header) => (
                        <Badge key={header} variant="secondary" className="text-xs gap-1">
                          <CheckCircle className="w-3 h-3 text-success" />
                          {header}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                {scan.missing_headers && scan.missing_headers.length > 0 && (
                  <div className="space-y-1 mt-2">
                    <span className="text-xs text-muted-foreground">Missing:</span>
                    <div className="flex flex-wrap gap-1">
                      {scan.missing_headers.map((header) => (
                        <Badge key={header} variant="outline" className="text-xs gap-1 border-warning/30 text-warning">
                          <AlertTriangle className="w-3 h-3" />
                          {header}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Technologies Detected */}
              {scan.detected_technologies && scan.detected_technologies.length > 0 && (
                <div className="p-4 rounded-lg bg-muted/30 space-y-2">
                  <h4 className="text-sm font-medium flex items-center gap-2">
                    <Server className="w-4 h-4" />
                    Detected Technologies
                  </h4>
                  <div className="flex flex-wrap gap-1">
                    {scan.detected_technologies.map((tech) => (
                      <Badge key={tech} variant="secondary" className="text-xs">
                        {tech}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommended Fixes */}
              {scan.raw_results && typeof scan.raw_results === 'object' && 'recommended_fixes' in scan.raw_results && (
                <FixSnippetCard fixes={(scan.raw_results as { recommended_fixes: FixSnippet[] }).recommended_fixes} />
              )}
            </div>
          )}
        </CardContent>
      )}
    </Card>
  );
}
