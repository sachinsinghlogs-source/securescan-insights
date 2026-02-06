import { useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  AlertTriangle,
  CheckCircle,
  TrendingUp,
  TrendingDown,
  Shield,
  Lock,
  Unlock,
  Activity,
} from 'lucide-react';
import type { Scan } from '@/types/database';

interface SecurityEventTimelineProps {
  scans: Scan[];
}

interface SecurityEvent {
  id: string;
  date: string;
  domain: string;
  type: 'regression' | 'improvement' | 'first_scan';
  title: string;
  detail: string;
  scoreBefore?: number;
  scoreAfter: number;
  riskLevel: string;
}

export default function SecurityEventTimeline({ scans }: SecurityEventTimelineProps) {
  const events = useMemo(() => {
    const completed = scans
      .filter(s => s.status === 'completed')
      .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());

    // Group by domain
    const byDomain = new Map<string, Scan[]>();
    completed.forEach(s => {
      try {
        const domain = new URL(s.target_url).hostname;
        const arr = byDomain.get(domain) || [];
        arr.push(s);
        byDomain.set(domain, arr);
      } catch {}
    });

    const result: SecurityEvent[] = [];

    byDomain.forEach((domainScans, domain) => {
      domainScans.forEach((scan, i) => {
        if (i === 0) {
          result.push({
            id: scan.id,
            date: scan.created_at,
            domain,
            type: 'first_scan',
            title: 'First scan',
            detail: `Initial risk score: ${scan.risk_score ?? 0}`,
            scoreAfter: scan.risk_score ?? 0,
            riskLevel: scan.risk_level || 'low',
          });
          return;
        }

        const prev = domainScans[i - 1];
        const change = (scan.risk_score ?? 0) - (prev.risk_score ?? 0);

        if (change >= 10) {
          result.push({
            id: scan.id,
            date: scan.created_at,
            domain,
            type: 'regression',
            title: `Risk increased by ${change} points`,
            detail: getChangeDetail(prev, scan),
            scoreBefore: prev.risk_score ?? 0,
            scoreAfter: scan.risk_score ?? 0,
            riskLevel: scan.risk_level || 'medium',
          });
        } else if (change <= -10) {
          result.push({
            id: scan.id,
            date: scan.created_at,
            domain,
            type: 'improvement',
            title: `Risk decreased by ${Math.abs(change)} points`,
            detail: getChangeDetail(prev, scan),
            scoreBefore: prev.risk_score ?? 0,
            scoreAfter: scan.risk_score ?? 0,
            riskLevel: scan.risk_level || 'low',
          });
        }

        // SSL state changes
        if (prev.ssl_valid !== scan.ssl_valid) {
          result.push({
            id: `${scan.id}-ssl`,
            date: scan.created_at,
            domain,
            type: scan.ssl_valid ? 'improvement' : 'regression',
            title: scan.ssl_valid ? 'SSL certificate restored' : 'SSL certificate became invalid',
            detail: scan.ssl_valid
              ? 'The site now has a valid SSL certificate.'
              : 'SSL is no longer valid — traffic is unencrypted.',
            scoreAfter: scan.risk_score ?? 0,
            riskLevel: scan.risk_level || 'medium',
          });
        }
      });
    });

    // Sort by date descending (most recent first)
    return result.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
  }, [scans]);

  if (events.length === 0) {
    return (
      <Card className="border-glow glass">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <Activity className="w-5 h-5 text-primary" />
            Security Events
          </CardTitle>
        </CardHeader>
        <CardContent className="text-center py-8 text-muted-foreground">
          <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
          <p className="text-sm">No significant security events yet.</p>
          <p className="text-xs mt-1 opacity-70">Events appear when risk scores change by ≥10 points.</p>
        </CardContent>
      </Card>
    );
  }

  const regressionCount = events.filter(e => e.type === 'regression').length;
  const improvementCount = events.filter(e => e.type === 'improvement').length;

  return (
    <Card className="border-glow glass">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg flex items-center gap-2">
            <Activity className="w-5 h-5 text-primary" />
            Security Events
          </CardTitle>
          <div className="flex gap-2">
            {regressionCount > 0 && (
              <Badge className="bg-critical/20 text-critical border-critical/30 text-xs">
                {regressionCount} regression{regressionCount !== 1 ? 's' : ''}
              </Badge>
            )}
            {improvementCount > 0 && (
              <Badge className="bg-success/20 text-success border-success/30 text-xs">
                {improvementCount} fix{improvementCount !== 1 ? 'es' : ''}
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        <ScrollArea className="h-[350px] pr-4">
          <div className="relative">
            <div className="absolute left-3 top-0 bottom-0 w-0.5 bg-border" />
            <div className="space-y-3">
              {events.map(event => (
                <div key={event.id} className="relative pl-8">
                  {/* Dot */}
                  <div className={`absolute left-1.5 top-3 w-3 h-3 rounded-full border-2 ${
                    event.type === 'regression'
                      ? 'bg-critical border-critical'
                      : event.type === 'improvement'
                      ? 'bg-success border-success'
                      : 'bg-primary border-primary'
                  }`} />

                  <div className={`p-3 rounded-lg border transition-all ${
                    event.type === 'regression'
                      ? 'bg-critical/5 border-critical/20'
                      : event.type === 'improvement'
                      ? 'bg-success/5 border-success/20'
                      : 'bg-muted/30 border-border/50'
                  }`}>
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2">
                        {event.type === 'regression' ? (
                          <TrendingUp className="w-4 h-4 text-critical shrink-0" />
                        ) : event.type === 'improvement' ? (
                          <TrendingDown className="w-4 h-4 text-success shrink-0" />
                        ) : (
                          <Shield className="w-4 h-4 text-primary shrink-0" />
                        )}
                        <span className="text-sm font-medium">{event.title}</span>
                      </div>
                      {event.scoreBefore !== undefined && (
                        <span className="text-xs text-muted-foreground whitespace-nowrap">
                          {event.scoreBefore} → {event.scoreAfter}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">{event.detail}</p>
                    <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                      <span className="font-mono">{event.domain}</span>
                      <span>•</span>
                      <span>{new Date(event.date).toLocaleDateString('en-US', {
                        month: 'short', day: 'numeric', year: 'numeric'
                      })}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

function getChangeDetail(prev: Scan, curr: Scan): string {
  const details: string[] = [];

  const prevMissing = new Set(prev.missing_headers || []);
  const currMissing = new Set(curr.missing_headers || []);
  const prevPresent = new Set(prev.present_headers || []);
  const currPresent = new Set(curr.present_headers || []);

  const headersRemoved: string[] = [];
  const headersAdded: string[] = [];

  prevPresent.forEach(h => { if (currMissing.has(h)) headersRemoved.push(h); });
  prevMissing.forEach(h => { if (currPresent.has(h)) headersAdded.push(h); });

  if (headersRemoved.length > 0) details.push(`Removed: ${headersRemoved.join(', ')}`);
  if (headersAdded.length > 0) details.push(`Added: ${headersAdded.join(', ')}`);

  if (prev.risk_level !== curr.risk_level) {
    details.push(`Risk level: ${prev.risk_level} → ${curr.risk_level}`);
  }

  return details.length > 0 ? details.join(' • ') : 'Security posture changed';
}
