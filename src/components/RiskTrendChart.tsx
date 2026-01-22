import { useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from '@/components/ui/chart';
import { LineChart, Line, XAxis, YAxis, ResponsiveContainer, Area, AreaChart } from 'recharts';

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
}

export default function RiskTrendChart({ trends, targetUrl }: RiskTrendChartProps) {
  const chartData = useMemo(() => {
    const filtered = targetUrl 
      ? trends.filter(t => t.target_url === targetUrl)
      : trends;
    
    return filtered
      .sort((a, b) => new Date(a.recorded_at).getTime() - new Date(b.recorded_at).getTime())
      .slice(-30) // Last 30 data points
      .map(t => ({
        date: new Date(t.recorded_at).toLocaleDateString('en-US', { 
          month: 'short', 
          day: 'numeric' 
        }),
        score: t.risk_score,
        level: t.risk_level,
      }));
  }, [trends, targetUrl]);

  const trendAnalysis = useMemo(() => {
    if (chartData.length < 2) return { direction: 'stable', change: 0 };
    
    const firstHalf = chartData.slice(0, Math.floor(chartData.length / 2));
    const secondHalf = chartData.slice(Math.floor(chartData.length / 2));
    
    const avgFirst = firstHalf.reduce((sum, d) => sum + d.score, 0) / firstHalf.length;
    const avgSecond = secondHalf.reduce((sum, d) => sum + d.score, 0) / secondHalf.length;
    
    const change = avgSecond - avgFirst;
    
    if (change > 5) return { direction: 'improving', change: Math.round(change) };
    if (change < -5) return { direction: 'declining', change: Math.round(Math.abs(change)) };
    return { direction: 'stable', change: 0 };
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
            Risk Trend
          </CardTitle>
        </CardHeader>
        <CardContent className="text-center py-8 text-muted-foreground">
          Not enough data to show trends. Run more scans to see your security posture over time.
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-glow glass">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg">Risk Trend</CardTitle>
          <div className="flex items-center gap-2">
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
      </CardHeader>
      <CardContent>
        <ChartContainer config={chartConfig} className="h-[200px] w-full">
          <AreaChart data={chartData}>
            <defs>
              <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.4} />
                <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis 
              dataKey="date" 
              axisLine={false}
              tickLine={false}
              tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12 }}
            />
            <YAxis 
              domain={[0, 100]}
              axisLine={false}
              tickLine={false}
              tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12 }}
            />
            <ChartTooltip content={<ChartTooltipContent />} />
            <Area
              type="monotone"
              dataKey="score"
              stroke="hsl(var(--primary))"
              strokeWidth={2}
              fill="url(#riskGradient)"
            />
          </AreaChart>
        </ChartContainer>
        
        {targetUrl && (
          <p className="text-xs text-muted-foreground mt-2 truncate">
            Tracking: {targetUrl}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
