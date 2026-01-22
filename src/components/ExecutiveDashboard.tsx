import { useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import {
  Shield,
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ArrowRight,
  Activity,
} from 'lucide-react';
import type { Scan } from '@/types/database';

interface SecurityAlert {
  id: string;
  alert_type: string;
  severity: string;
  title: string;
  is_read: boolean;
  is_dismissed: boolean;
}

interface RiskTrend {
  risk_score: number;
  risk_level: string;
  recorded_at: string;
}

interface ExecutiveDashboardProps {
  scans: Scan[];
  alerts: SecurityAlert[];
  trends: RiskTrend[];
  onViewAlerts: () => void;
}

export default function ExecutiveDashboard({
  scans,
  alerts,
  trends,
  onViewAlerts,
}: ExecutiveDashboardProps) {
  const metrics = useMemo(() => {
    const completedScans = scans.filter(s => s.status === 'completed');
    const recentScans = completedScans.slice(0, 10);
    
    // Calculate average risk score
    const avgRiskScore = recentScans.length > 0
      ? Math.round(recentScans.reduce((sum, s) => sum + (s.risk_score || 0), 0) / recentScans.length)
      : 0;
    
    // Calculate trend
    const recentTrends = trends.slice(-14);
    let trendDirection: 'up' | 'down' | 'stable' = 'stable';
    let trendChange = 0;
    
    if (recentTrends.length >= 2) {
      const firstHalf = recentTrends.slice(0, Math.floor(recentTrends.length / 2));
      const secondHalf = recentTrends.slice(Math.floor(recentTrends.length / 2));
      
      const avgFirst = firstHalf.reduce((sum, t) => sum + t.risk_score, 0) / firstHalf.length;
      const avgSecond = secondHalf.reduce((sum, t) => sum + t.risk_score, 0) / secondHalf.length;
      
      trendChange = Math.round(avgSecond - avgFirst);
      if (trendChange > 3) trendDirection = 'up';
      else if (trendChange < -3) trendDirection = 'down';
    }
    
    // Count by risk level
    const riskCounts = {
      low: completedScans.filter(s => s.risk_level === 'low').length,
      medium: completedScans.filter(s => s.risk_level === 'medium').length,
      high: completedScans.filter(s => s.risk_level === 'high' || s.risk_level === 'critical').length,
    };
    
    // Unread critical alerts
    const criticalAlerts = alerts.filter(
      a => !a.is_dismissed && !a.is_read && (a.severity === 'critical' || a.severity === 'high')
    ).length;
    
    // Overall health
    let healthStatus: 'good' | 'warning' | 'critical' = 'good';
    if (avgRiskScore < 50 || criticalAlerts > 0 || riskCounts.high > 0) {
      healthStatus = 'critical';
    } else if (avgRiskScore < 70 || riskCounts.medium > riskCounts.low) {
      healthStatus = 'warning';
    }
    
    return {
      avgRiskScore,
      trendDirection,
      trendChange,
      riskCounts,
      criticalAlerts,
      healthStatus,
      totalScans: completedScans.length,
    };
  }, [scans, alerts, trends]);

  const getHealthColor = () => {
    switch (metrics.healthStatus) {
      case 'good':
        return 'text-success';
      case 'warning':
        return 'text-warning';
      case 'critical':
        return 'text-critical';
    }
  };

  const getHealthBg = () => {
    switch (metrics.healthStatus) {
      case 'good':
        return 'bg-success/20 border-success/30';
      case 'warning':
        return 'bg-warning/20 border-warning/30';
      case 'critical':
        return 'bg-critical/20 border-critical/30';
    }
  };

  const getHealthLabel = () => {
    switch (metrics.healthStatus) {
      case 'good':
        return 'Healthy';
      case 'warning':
        return 'Needs Attention';
      case 'critical':
        return 'Action Required';
    }
  };

  // Create action items
  const actionItems = useMemo(() => {
    const items: { label: string; severity: 'high' | 'medium' | 'low' }[] = [];
    
    if (metrics.criticalAlerts > 0) {
      items.push({
        label: `${metrics.criticalAlerts} critical alert${metrics.criticalAlerts > 1 ? 's' : ''} need attention`,
        severity: 'high',
      });
    }
    
    if (metrics.riskCounts.high > 0) {
      items.push({
        label: `${metrics.riskCounts.high} site${metrics.riskCounts.high > 1 ? 's' : ''} with high risk`,
        severity: 'high',
      });
    }
    
    if (metrics.trendDirection === 'down' && Math.abs(metrics.trendChange) > 5) {
      items.push({
        label: 'Security posture declining',
        severity: 'medium',
      });
    }
    
    if (metrics.riskCounts.medium > metrics.riskCounts.low) {
      items.push({
        label: 'More medium-risk sites than low-risk',
        severity: 'low',
      });
    }
    
    return items.slice(0, 3);
  }, [metrics]);

  return (
    <Card className="border-glow glass">
      <CardHeader className="pb-2">
        <CardTitle className="text-lg flex items-center gap-2">
          <Activity className="w-5 h-5 text-primary" />
          Security Overview
        </CardTitle>
      </CardHeader>
      
      <CardContent className="space-y-6">
        {/* Health Score Gauge */}
        <div className="flex items-center gap-6">
          <div className={`relative w-24 h-24 rounded-full border-4 ${getHealthBg()} flex items-center justify-center`}>
            <div className="text-center">
              <span className={`text-2xl font-bold ${getHealthColor()}`}>
                {metrics.avgRiskScore}
              </span>
              <span className="text-xs text-muted-foreground block">/100</span>
            </div>
          </div>
          
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-2">
              <Badge className={`${getHealthBg()} ${getHealthColor()}`}>
                {getHealthLabel()}
              </Badge>
              
              {metrics.trendDirection !== 'stable' && (
                <span className="flex items-center gap-1 text-sm">
                  {metrics.trendDirection === 'up' ? (
                    <>
                      <TrendingUp className="w-4 h-4 text-success" />
                      <span className="text-success">+{metrics.trendChange}</span>
                    </>
                  ) : (
                    <>
                      <TrendingDown className="w-4 h-4 text-critical" />
                      <span className="text-critical">{metrics.trendChange}</span>
                    </>
                  )}
                </span>
              )}
            </div>
            
            <p className="text-sm text-muted-foreground">
              Based on {metrics.totalScans} scan{metrics.totalScans !== 1 ? 's' : ''} across your monitored sites
            </p>
          </div>
        </div>

        {/* Risk Distribution */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Risk Distribution</span>
          </div>
          
          <div className="flex gap-1 h-3 rounded-full overflow-hidden bg-muted">
            {metrics.totalScans > 0 && (
              <>
                <div 
                  className="bg-success transition-all"
                  style={{ width: `${(metrics.riskCounts.low / metrics.totalScans) * 100}%` }}
                />
                <div 
                  className="bg-warning transition-all"
                  style={{ width: `${(metrics.riskCounts.medium / metrics.totalScans) * 100}%` }}
                />
                <div 
                  className="bg-critical transition-all"
                  style={{ width: `${(metrics.riskCounts.high / metrics.totalScans) * 100}%` }}
                />
              </>
            )}
          </div>
          
          <div className="flex justify-between text-xs">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-success" />
              Low: {metrics.riskCounts.low}
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-warning" />
              Medium: {metrics.riskCounts.medium}
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-critical" />
              High: {metrics.riskCounts.high}
            </span>
          </div>
        </div>

        {/* Action Items */}
        {actionItems.length > 0 && (
          <div className="space-y-2">
            <span className="text-sm font-medium">Action Required</span>
            
            <div className="space-y-2">
              {actionItems.map((item, index) => (
                <div 
                  key={index}
                  className={`flex items-center gap-2 p-2 rounded-lg text-sm ${
                    item.severity === 'high' 
                      ? 'bg-critical/10 text-critical' 
                      : item.severity === 'medium'
                      ? 'bg-warning/10 text-warning'
                      : 'bg-muted text-muted-foreground'
                  }`}
                >
                  {item.severity === 'high' ? (
                    <XCircle className="w-4 h-4 shrink-0" />
                  ) : item.severity === 'medium' ? (
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                  ) : (
                    <CheckCircle className="w-4 h-4 shrink-0" />
                  )}
                  <span>{item.label}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Quick Actions */}
        {metrics.criticalAlerts > 0 && (
          <Button 
            variant="outline" 
            className="w-full justify-between"
            onClick={onViewAlerts}
          >
            <span>View {metrics.criticalAlerts} pending alert{metrics.criticalAlerts > 1 ? 's' : ''}</span>
            <ArrowRight className="w-4 h-4" />
          </Button>
        )}
      </CardContent>
    </Card>
  );
}
