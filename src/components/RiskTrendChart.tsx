import { useMemo, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { TrendingUp, TrendingDown, Minus, Activity, Shield, AlertTriangle, CheckCircle } from 'lucide-react';
import {
  ChartContainer,
  ChartTooltip,
} from '@/components/ui/chart';
import { AreaChart, Area, XAxis, YAxis, ReferenceLine, Dot, CartesianGrid } from 'recharts';

interface RiskTrend {
  id: string;
  risk_score: number;
  risk_level: string;
  recorded_at: string;
  target_url: string;
}

interface RiskTrendChartProps {
  trends: RiskTrend[];
  targetUrl?: string;
  compact?: boolean;
}

// Custom dot that highlights regressions/improvements
const EventDot = (props: any) => {
  const { cx, cy, payload } = props;
  if (!payload?.event) return <Dot {...props} r={0} />;

  if (payload.event === 'regression') {
    return (
      <g>
        <circle cx={cx} cy={cy} r={8} fill="hsl(0, 84%, 60%)" opacity={0.2} />
        <circle cx={cx} cy={cy} r={4} fill="hsl(0, 84%, 60%)" stroke="hsl(0, 84%, 60%)" strokeWidth={2} />
      </g>
    );
  }
  if (payload.event === 'improvement') {
    return (
      <g>
        <circle cx={cx} cy={cy} r={8} fill="hsl(142, 76%, 45%)" opacity={0.2} />
        <circle cx={cx} cy={cy} r={4} fill="hsl(142, 76%, 45%)" stroke="hsl(142, 76%, 45%)" strokeWidth={2} />
      </g>
    );
  }
  return <Dot {...props} r={0} />;
};

// Custom tooltip
const CustomTooltip = ({ active, payload }: any) => {
  if (!active || !payload?.length) return null;
  const data = payload[0].payload;

  return (
    <div className="rounded-lg border border-border bg-card p-3 shadow-lg min-w-[180px]">
      <p className="text-xs text-muted-foreground mb-1">{data.fullDate}</p>
      <div className="flex items-center justify-between gap-4 mb-1">
        <span className="text-sm font-medium">Risk Score</span>
        <span className={`text-lg font-bold ${
          data.score <= 25 ? 'text-success' :
          data.score <= 50 ? 'text-warning' :
          'text-critical'
        }`}>
          {data.score}
        </span>
      </div>
      <Badge variant="outline" className={`text-xs ${
        data.level === 'low' ? 'border-success/30 text-success' :
        data.level === 'medium' ? 'border-warning/30 text-warning' :
        'border-critical/30 text-critical'
      }`}>
        {data.level} risk
      </Badge>
      {data.event && (
        <div className={`mt-2 pt-2 border-t border-border text-xs flex items-center gap-1 ${
          data.event === 'regression' ? 'text-critical' : 'text-success'
        }`}>
          {data.event === 'regression' ? (
            <><AlertTriangle className="w-3 h-3" /> Regression: +{data.change} pts</>
          ) : (
            <><CheckCircle className="w-3 h-3" /> Improvement: {data.change} pts</>
          )}
        </div>
      )}
      {data.domain && (
        <p className="text-xs text-muted-foreground mt-1 truncate max-w-[200px]">{data.domain}</p>
      )}
    </div>
  );
};

export default function RiskTrendChart({ trends, targetUrl, compact = false }: RiskTrendChartProps) {
  const [timeRange, setTimeRange] = useState<'7d' | '30d' | 'all'>('30d');

  // Extract unique domains
  const domains = useMemo(() => {
    const set = new Set<string>();
    trends.forEach(t => {
      try { set.add(new URL(t.target_url).hostname); } catch {}
    });
    return Array.from(set);
  }, [trends]);

  const [selectedDomain, setSelectedDomain] = useState<string>('all');

  const chartData = useMemo(() => {
    let filtered = trends;

    // Filter by domain
    if (targetUrl) {
      filtered = filtered.filter(t => t.target_url === targetUrl);
    } else if (selectedDomain !== 'all') {
      filtered = filtered.filter(t => {
        try { return new URL(t.target_url).hostname === selectedDomain; } catch { return false; }
      });
    }

    // Filter by time range
    const now = Date.now();
    if (timeRange === '7d') {
      filtered = filtered.filter(t => now - new Date(t.recorded_at).getTime() < 7 * 86400000);
    } else if (timeRange === '30d') {
      filtered = filtered.filter(t => now - new Date(t.recorded_at).getTime() < 30 * 86400000);
    }

    const sorted = [...filtered].sort(
      (a, b) => new Date(a.recorded_at).getTime() - new Date(b.recorded_at).getTime()
    );

    return sorted.map((t, i) => {
      const prev = i > 0 ? sorted[i - 1] : null;
      const change = prev ? t.risk_score - prev.risk_score : 0;
      let event: 'regression' | 'improvement' | null = null;
      if (change >= 10) event = 'regression';
      else if (change <= -10) event = 'improvement';

      const date = new Date(t.recorded_at);
      return {
        date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        fullDate: date.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }),
        score: t.risk_score,
        level: t.risk_level,
        event,
        change,
        domain: (() => { try { return new URL(t.target_url).hostname; } catch { return ''; } })(),
      };
    });
  }, [trends, targetUrl, selectedDomain, timeRange]);

  const trendAnalysis = useMemo(() => {
    if (chartData.length < 2) return { direction: 'stable' as const, change: 0, events: { regressions: 0, improvements: 0 } };

    const firstHalf = chartData.slice(0, Math.floor(chartData.length / 2));
    const secondHalf = chartData.slice(Math.floor(chartData.length / 2));

    const avgFirst = firstHalf.reduce((sum, d) => sum + d.score, 0) / firstHalf.length;
    const avgSecond = secondHalf.reduce((sum, d) => sum + d.score, 0) / secondHalf.length;

    const change = Math.round(avgSecond - avgFirst);
    const regressions = chartData.filter(d => d.event === 'regression').length;
    const improvements = chartData.filter(d => d.event === 'improvement').length;

    return {
      direction: change > 5 ? 'improving' as const : change < -5 ? 'declining' as const : 'stable' as const,
      change: Math.abs(change),
      events: { regressions, improvements },
    };
  }, [chartData]);

  const chartConfig = {
    score: {
      label: 'Risk Score',
      color: 'hsl(var(--primary))',
    },
  };

  if (chartData.length === 0) {
    return (
      <Card className="border-glow glass">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <Activity className="w-5 h-5 text-primary" />
            Risk Trend
          </CardTitle>
        </CardHeader>
        <CardContent className="text-center py-8 text-muted-foreground">
          <Activity className="w-10 h-10 mx-auto mb-3 opacity-30" />
          <p className="text-sm">Not enough data to show trends.</p>
          <p className="text-xs mt-1 opacity-70">Run more scans to see your security posture over time.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-glow glass">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <CardTitle className="text-lg flex items-center gap-2">
            <Activity className="w-5 h-5 text-primary" />
            Risk Trend
          </CardTitle>
          <div className="flex items-center gap-2 flex-wrap">
            {/* Event badges */}
            {trendAnalysis.events.regressions > 0 && (
              <Badge className="bg-critical/20 text-critical border-critical/30 gap-1 text-xs">
                <AlertTriangle className="w-3 h-3" />
                {trendAnalysis.events.regressions} regression{trendAnalysis.events.regressions !== 1 ? 's' : ''}
              </Badge>
            )}
            {trendAnalysis.events.improvements > 0 && (
              <Badge className="bg-success/20 text-success border-success/30 gap-1 text-xs">
                <CheckCircle className="w-3 h-3" />
                {trendAnalysis.events.improvements} fix{trendAnalysis.events.improvements !== 1 ? 'es' : ''}
              </Badge>
            )}

            {/* Trend direction */}
            {trendAnalysis.direction === 'improving' && (
              <Badge className="bg-success/20 text-success border-success/30 gap-1">
                <TrendingUp className="w-3 h-3" />
                +{trendAnalysis.change} pts
              </Badge>
            )}
            {trendAnalysis.direction === 'declining' && (
              <Badge className="bg-critical/20 text-critical border-critical/30 gap-1">
                <TrendingDown className="w-3 h-3" />
                -{trendAnalysis.change} pts
              </Badge>
            )}
            {trendAnalysis.direction === 'stable' && (
              <Badge variant="secondary" className="gap-1">
                <Minus className="w-3 h-3" />
                Stable
              </Badge>
            )}
          </div>
        </div>

        {/* Filters */}
        {!compact && (
          <div className="flex items-center gap-2 mt-3 flex-wrap">
            {/* Time range toggle */}
            <div className="flex rounded-lg border border-border overflow-hidden">
              {(['7d', '30d', 'all'] as const).map(range => (
                <button
                  key={range}
                  onClick={() => setTimeRange(range)}
                  className={`px-3 py-1 text-xs font-medium transition-colors ${
                    timeRange === range
                      ? 'bg-primary text-primary-foreground'
                      : 'bg-muted/30 text-muted-foreground hover:bg-muted/50'
                  }`}
                >
                  {range === '7d' ? '7 Days' : range === '30d' ? '30 Days' : 'All Time'}
                </button>
              ))}
            </div>

            {/* Domain filter */}
            {!targetUrl && domains.length > 1 && (
              <Select value={selectedDomain} onValueChange={setSelectedDomain}>
                <SelectTrigger className="w-[180px] h-8 text-xs">
                  <SelectValue placeholder="All domains" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All domains</SelectItem>
                  {domains.map(d => (
                    <SelectItem key={d} value={d} className="font-mono text-xs">{d}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </div>
        )}
      </CardHeader>
      <CardContent>
        <ChartContainer config={chartConfig} className={compact ? 'h-[150px] w-full' : 'h-[250px] w-full'}>
          <AreaChart data={chartData}>
            <defs>
              <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.4} />
                <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
            {/* Risk zone reference lines */}
            <ReferenceLine y={25} stroke="hsl(var(--success))" strokeDasharray="4 4" strokeOpacity={0.3} />
            <ReferenceLine y={50} stroke="hsl(var(--warning))" strokeDasharray="4 4" strokeOpacity={0.3} />
            <ReferenceLine y={75} stroke="hsl(var(--critical))" strokeDasharray="4 4" strokeOpacity={0.3} />
            <XAxis
              dataKey="date"
              axisLine={false}
              tickLine={false}
              tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
              interval="preserveStartEnd"
            />
            <YAxis
              domain={[0, 100]}
              axisLine={false}
              tickLine={false}
              tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
              width={30}
            />
            <ChartTooltip content={<CustomTooltip />} />
            <Area
              type="monotone"
              dataKey="score"
              stroke="hsl(var(--primary))"
              strokeWidth={2}
              fill="url(#riskGradient)"
              dot={<EventDot />}
              activeDot={{ r: 5, stroke: 'hsl(var(--primary))', strokeWidth: 2, fill: 'hsl(var(--card))' }}
            />
          </AreaChart>
        </ChartContainer>

        {/* Risk zone legend */}
        {!compact && (
          <div className="flex items-center justify-between mt-3 text-[10px] text-muted-foreground px-8">
            <span className="flex items-center gap-1">
              <span className="w-6 h-0.5 bg-success rounded" /> Low (0-25)
            </span>
            <span className="flex items-center gap-1">
              <span className="w-6 h-0.5 bg-warning rounded" /> Medium (26-50)
            </span>
            <span className="flex items-center gap-1">
              <span className="w-6 h-0.5 bg-critical rounded" /> High (51-75)
            </span>
            <span className="text-muted-foreground/50">Critical (76-100)</span>
          </div>
        )}

        {/* Event markers legend */}
        {!compact && (trendAnalysis.events.regressions > 0 || trendAnalysis.events.improvements > 0) && (
          <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground justify-center">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-critical" /> Regression (≥10pt increase)
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-success" /> Fix (≥10pt decrease)
            </span>
          </div>
        )}

        {targetUrl && (
          <p className="text-xs text-muted-foreground mt-2 truncate">
            Tracking: {targetUrl}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
