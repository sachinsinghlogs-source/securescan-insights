import { useState, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  ArrowLeft,
  Calendar,
  Clock,
  Download,
  Eye,
  Globe,
  Lock,
  Unlock,
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  TrendingUp,
  TrendingDown,
  Minus,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  CheckCircle
} from 'lucide-react';
import { generatePdfReport } from '@/lib/generatePdfReport';
import { formatDistanceToNow, format } from 'date-fns';
import type { Scan } from '@/types/database';

interface ScanHistoryTimelineProps {
  domain: string;
  scans: Scan[];
  onBack: () => void;
}

export default function ScanHistoryTimeline({
  domain,
  scans,
  onBack
}: ScanHistoryTimelineProps) {
  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);

  // Filter and sort scans for this domain
  const domainScans = useMemo(() => {
    return scans
      .filter(scan => {
        try {
          const url = new URL(scan.target_url);
          return url.hostname === domain;
        } catch {
          return false;
        }
      })
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }, [scans, domain]);

  const completedScans = domainScans.filter(s => s.status === 'completed');

  // Calculate risk change between consecutive scans
  const getRiskChange = (scan: Scan, index: number) => {
    if (index >= completedScans.length - 1) return null;
    const currentScore = scan.risk_score ?? 0;
    const previousScore = completedScans[index + 1].risk_score ?? 0;
    const diff = currentScore - previousScore;
    
    if (Math.abs(diff) < 5) return { type: 'stable' as const, diff: 0 };
    return {
      type: diff < 0 ? 'improved' as const : 'worsened' as const,
      diff
    };
  };

  const getRiskBadge = (riskLevel: string | null) => {
    switch (riskLevel) {
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

  const formatScanDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return {
      relative: formatDistanceToNow(date, { addSuffix: true }),
      absolute: format(date, 'MMM d, yyyy • h:mm a')
    };
  };

  return (
    <Card className="border-glow glass h-full">
      <CardHeader className="pb-3">
        <div className="flex items-center gap-3">
          <Button
            variant="ghost"
            size="icon"
            onClick={onBack}
            className="h-8 w-8"
          >
            <ArrowLeft className="w-4 h-4" />
          </Button>
          <div className="flex-1 min-w-0">
            <CardTitle className="text-lg flex items-center gap-2 truncate">
              <Globe className="w-5 h-5 text-primary flex-shrink-0" />
              <span className="truncate font-mono">{domain}</span>
            </CardTitle>
            <p className="text-sm text-muted-foreground mt-1">
              {domainScans.length} scans • {completedScans.length} completed
            </p>
          </div>
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        {domainScans.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">
            <Calendar className="w-12 h-12 mx-auto mb-3 opacity-50" />
            <p className="text-sm">No scan history for this domain</p>
          </div>
        ) : (
          <ScrollArea className="h-[500px] pr-4">
            <div className="relative">
              {/* Timeline line */}
              <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-border" />
              
              <div className="space-y-4">
                {domainScans.map((scan, index) => {
                  const isCompleted = scan.status === 'completed';
                  const isExpanded = expandedScanId === scan.id;
                  const riskChange = isCompleted
                    ? getRiskChange(scan, completedScans.indexOf(scan))
                    : null;
                  const dates = formatScanDate(scan.created_at);

                  return (
                    <div key={scan.id} className="relative pl-10">
                      {/* Timeline dot */}
                      <div
                        className={`absolute left-2 top-3 w-4 h-4 rounded-full border-2 ${
                          isCompleted
                            ? scan.risk_level === 'low'
                              ? 'bg-success border-success'
                              : scan.risk_level === 'medium'
                              ? 'bg-warning border-warning'
                              : scan.risk_level === 'high' || scan.risk_level === 'critical'
                              ? 'bg-critical border-critical'
                              : 'bg-muted border-border'
                            : scan.status === 'scanning'
                            ? 'bg-primary border-primary animate-pulse'
                            : 'bg-muted border-border'
                        }`}
                      />

                      <div
                        className={`p-4 rounded-lg transition-all ${
                          isExpanded
                            ? 'bg-accent border border-primary/30'
                            : 'bg-muted/30 hover:bg-muted/50'
                        }`}
                      >
                        {/* Header */}
                        <div className="flex items-start justify-between gap-2">
                          <div>
                            <div className="flex items-center gap-2 flex-wrap">
                              {isCompleted ? (
                                getRiskBadge(scan.risk_level)
                              ) : (
                                <Badge variant="secondary">
                                  {scan.status === 'scanning' ? 'Scanning...' : scan.status}
                                </Badge>
                              )}
                              {riskChange && riskChange.type !== 'stable' && (
                                <Badge
                                  variant="outline"
                                  className={`text-xs ${
                                    riskChange.type === 'improved'
                                      ? 'border-success/30 text-success'
                                      : 'border-critical/30 text-critical'
                                  }`}
                                >
                                  {riskChange.type === 'improved' ? (
                                    <TrendingDown className="w-3 h-3 mr-1" />
                                  ) : (
                                    <TrendingUp className="w-3 h-3 mr-1" />
                                  )}
                                  {riskChange.type === 'improved' ? '' : '+'}
                                  {riskChange.diff}
                                </Badge>
                              )}
                            </div>
                            <div className="flex items-center gap-2 mt-2 text-xs text-muted-foreground">
                              <Clock className="w-3 h-3" />
                              <span title={dates.absolute}>{dates.relative}</span>
                              {scan.scan_duration_ms && (
                                <>
                                  <span>•</span>
                                  <span>{(scan.scan_duration_ms / 1000).toFixed(1)}s</span>
                                </>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-1">
                            {isCompleted && (
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
                            {isCompleted && (
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-8 w-8"
                                onClick={() => setExpandedScanId(isExpanded ? null : scan.id)}
                              >
                                {isExpanded ? (
                                  <ChevronUp className="w-4 h-4" />
                                ) : (
                                  <ChevronDown className="w-4 h-4" />
                                )}
                              </Button>
                            )}
                          </div>
                        </div>

                        {/* Quick stats for completed scans */}
                        {isCompleted && (
                          <div className="flex items-center gap-4 mt-3 text-sm">
                            <div className="flex items-center gap-1">
                              {scan.ssl_valid ? (
                                <Lock className="w-3 h-3 text-success" />
                              ) : (
                                <Unlock className="w-3 h-3 text-critical" />
                              )}
                              <span className="text-xs">
                                {scan.ssl_valid ? 'SSL OK' : 'SSL Issue'}
                              </span>
                            </div>
                            <div className="flex items-center gap-1">
                              <Shield className="w-3 h-3 text-primary" />
                              <span className="text-xs">
                                {scan.headers_score ?? 0}/100
                              </span>
                            </div>
                            {scan.risk_score !== null && (
                              <div className="flex items-center gap-1">
                                <span className="text-xs text-muted-foreground">
                                  Risk: {scan.risk_score}
                                </span>
                              </div>
                            )}
                          </div>
                        )}

                        {/* Expanded details */}
                        {isExpanded && isCompleted && (
                          <div className="mt-4 pt-4 border-t border-border/50 space-y-3 animate-fade-in">
                            <div className="text-xs text-muted-foreground">
                              {dates.absolute}
                            </div>
                            
                            {/* SSL Details */}
                            <div className="p-3 rounded-md bg-background/50">
                              <h5 className="text-xs font-medium flex items-center gap-2 mb-2">
                                <Lock className="w-3 h-3" />
                                SSL Certificate
                              </h5>
                              <div className="grid gap-1 text-xs">
                                <div className="flex justify-between">
                                  <span className="text-muted-foreground">Status</span>
                                  <span className={scan.ssl_valid ? 'text-success' : 'text-critical'}>
                                    {scan.ssl_valid ? 'Valid' : 'Invalid'}
                                  </span>
                                </div>
                                {scan.ssl_issuer && (
                                  <div className="flex justify-between">
                                    <span className="text-muted-foreground">Issuer</span>
                                    <span className="font-mono">{scan.ssl_issuer}</span>
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

                            {/* Headers */}
                            <div className="p-3 rounded-md bg-background/50">
                              <h5 className="text-xs font-medium flex items-center gap-2 mb-2">
                                <Shield className="w-3 h-3" />
                                Security Headers
                              </h5>
                              {scan.present_headers && scan.present_headers.length > 0 && (
                                <div className="mb-2">
                                  <span className="text-xs text-muted-foreground">Present:</span>
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {scan.present_headers.map((header) => (
                                      <Badge key={header} variant="secondary" className="text-xs gap-1">
                                        <CheckCircle className="w-2 h-2 text-success" />
                                        {header}
                                      </Badge>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {scan.missing_headers && scan.missing_headers.length > 0 && (
                                <div>
                                  <span className="text-xs text-muted-foreground">Missing:</span>
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {scan.missing_headers.map((header) => (
                                      <Badge key={header} variant="outline" className="text-xs gap-1 border-warning/30 text-warning">
                                        <AlertTriangle className="w-2 h-2" />
                                        {header}
                                      </Badge>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>

                            {/* Technologies */}
                            {scan.detected_technologies && scan.detected_technologies.length > 0 && (
                              <div className="p-3 rounded-md bg-background/50">
                                <h5 className="text-xs font-medium mb-2">Technologies</h5>
                                <div className="flex flex-wrap gap-1">
                                  {scan.detected_technologies.map((tech) => (
                                    <Badge key={tech} variant="secondary" className="text-xs">
                                      {tech}
                                    </Badge>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
}
