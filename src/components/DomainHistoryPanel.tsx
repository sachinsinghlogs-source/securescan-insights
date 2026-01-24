import { useState, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Globe,
  Search,
  Clock,
  TrendingUp,
  TrendingDown,
  Minus,
  ChevronRight,
  History,
  ShieldCheck,
  ShieldAlert,
  ShieldX
} from 'lucide-react';
import type { Scan } from '@/types/database';

interface DomainHistoryPanelProps {
  scans: Scan[];
  onSelectDomain: (domain: string) => void;
  selectedDomain: string | null;
}

interface DomainSummary {
  domain: string;
  totalScans: number;
  latestScan: Scan;
  riskTrend: 'improving' | 'worsening' | 'stable';
  averageRiskScore: number;
  firstScanDate: string;
}

export default function DomainHistoryPanel({
  scans,
  onSelectDomain,
  selectedDomain
}: DomainHistoryPanelProps) {
  const [searchQuery, setSearchQuery] = useState('');

  const domainSummaries = useMemo(() => {
    // Group scans by domain
    const domainMap = new Map<string, Scan[]>();
    
    scans.forEach(scan => {
      try {
        const url = new URL(scan.target_url);
        const domain = url.hostname;
        const existing = domainMap.get(domain) || [];
        existing.push(scan);
        domainMap.set(domain, existing);
      } catch {
        // Skip invalid URLs
      }
    });

    // Create summaries
    const summaries: DomainSummary[] = [];
    
    domainMap.forEach((domainScans, domain) => {
      // Sort by date descending
      const sorted = [...domainScans].sort(
        (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      );
      
      const completedScans = sorted.filter(s => s.status === 'completed');
      if (completedScans.length === 0) return;

      const latestScan = completedScans[0];
      const oldestScan = sorted[sorted.length - 1];
      
      // Calculate average risk score
      const riskScores = completedScans
        .filter(s => s.risk_score !== null)
        .map(s => s.risk_score as number);
      const averageRiskScore = riskScores.length > 0
        ? Math.round(riskScores.reduce((a, b) => a + b, 0) / riskScores.length)
        : 0;

      // Determine trend (compare last 2 scans)
      let riskTrend: 'improving' | 'worsening' | 'stable' = 'stable';
      if (completedScans.length >= 2) {
        const latest = completedScans[0].risk_score ?? 0;
        const previous = completedScans[1].risk_score ?? 0;
        if (latest < previous - 5) {
          riskTrend = 'improving';
        } else if (latest > previous + 5) {
          riskTrend = 'worsening';
        }
      }

      summaries.push({
        domain,
        totalScans: sorted.length,
        latestScan,
        riskTrend,
        averageRiskScore,
        firstScanDate: oldestScan.created_at
      });
    });

    // Sort by most recent scan
    return summaries.sort(
      (a, b) => new Date(b.latestScan.created_at).getTime() - new Date(a.latestScan.created_at).getTime()
    );
  }, [scans]);

  const filteredDomains = useMemo(() => {
    if (!searchQuery.trim()) return domainSummaries;
    const query = searchQuery.toLowerCase();
    return domainSummaries.filter(d => d.domain.toLowerCase().includes(query));
  }, [domainSummaries, searchQuery]);

  const getRiskBadge = (riskLevel: string | null) => {
    switch (riskLevel) {
      case 'low':
        return (
          <Badge className="risk-low gap-1 text-xs">
            <ShieldCheck className="w-3 h-3" />
            Low
          </Badge>
        );
      case 'medium':
        return (
          <Badge className="risk-medium gap-1 text-xs">
            <ShieldAlert className="w-3 h-3" />
            Medium
          </Badge>
        );
      case 'high':
      case 'critical':
        return (
          <Badge className="risk-high gap-1 text-xs">
            <ShieldX className="w-3 h-3" />
            {riskLevel === 'critical' ? 'Critical' : 'High'}
          </Badge>
        );
      default:
        return null;
    }
  };

  const getTrendIcon = (trend: 'improving' | 'worsening' | 'stable') => {
    switch (trend) {
      case 'improving':
        return <TrendingDown className="w-4 h-4 text-success" />;
      case 'worsening':
        return <TrendingUp className="w-4 h-4 text-critical" />;
      default:
        return <Minus className="w-4 h-4 text-muted-foreground" />;
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });
  };

  return (
    <Card className="border-glow glass h-full">
      <CardHeader className="pb-3">
        <CardTitle className="text-lg flex items-center gap-2">
          <History className="w-5 h-5 text-primary" />
          Monitored Domains
          <Badge variant="secondary" className="ml-auto">
            {domainSummaries.length}
          </Badge>
        </CardTitle>
        <div className="relative mt-2">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search domains..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 bg-background/50"
          />
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        {filteredDomains.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">
            <Globe className="w-12 h-12 mx-auto mb-3 opacity-50" />
            <p className="text-sm">
              {searchQuery ? 'No domains match your search' : 'No scan history yet'}
            </p>
          </div>
        ) : (
          <ScrollArea className="h-[400px] pr-4">
            <div className="space-y-2">
              {filteredDomains.map((summary) => (
                <button
                  key={summary.domain}
                  onClick={() => onSelectDomain(summary.domain)}
                  className={`w-full text-left p-3 rounded-lg transition-all hover:bg-accent/50 group ${
                    selectedDomain === summary.domain
                      ? 'bg-accent border border-primary/30'
                      : 'bg-muted/30 border border-transparent'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <Globe className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                        <span className="font-mono text-sm truncate">
                          {summary.domain}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {summary.totalScans} scans
                        </span>
                        <span>
                          Since {formatDate(summary.firstScanDate)}
                        </span>
                      </div>
                    </div>
                    <div className="flex flex-col items-end gap-2">
                      {getRiskBadge(summary.latestScan.risk_level)}
                      <div className="flex items-center gap-1 text-xs">
                        {getTrendIcon(summary.riskTrend)}
                        <span className="text-muted-foreground">
                          Avg: {summary.averageRiskScore}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center justify-end mt-2 text-xs text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity">
                    View history
                    <ChevronRight className="w-3 h-3 ml-1" />
                  </div>
                </button>
              ))}
            </div>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
}
