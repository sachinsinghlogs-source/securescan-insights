import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { 
  Shield, 
  Lock, 
  Server, 
  Code,
  AlertCircle,
  AlertTriangle,
  Info,
  CheckCircle,
  HelpCircle
} from 'lucide-react';
import { 
  type RiskBreakdown, 
  type RiskFactor,
  RISK_THRESHOLDS,
  getRiskExplanation 
} from '@/lib/riskScoring';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';

interface RiskBreakdownCardProps {
  breakdown: RiskBreakdown;
}

export default function RiskBreakdownCard({ breakdown }: RiskBreakdownCardProps) {
  const levelInfo = getRiskExplanation(breakdown.level);

  const getCategoryIcon = (category: RiskFactor['category']) => {
    switch (category) {
      case 'ssl': return <Lock className="w-4 h-4" />;
      case 'headers': return <Shield className="w-4 h-4" />;
      case 'cms': return <Code className="w-4 h-4" />;
      case 'server': return <Server className="w-4 h-4" />;
      default: return <Shield className="w-4 h-4" />;
    }
  };

  const getSeverityIcon = (severity: RiskFactor['severity']) => {
    switch (severity) {
      case 'critical': return <AlertCircle className="w-3.5 h-3.5 text-critical" />;
      case 'high': return <AlertTriangle className="w-3.5 h-3.5 text-destructive" />;
      case 'medium': return <AlertTriangle className="w-3.5 h-3.5 text-warning" />;
      case 'low': return <Info className="w-3.5 h-3.5 text-muted-foreground" />;
      case 'info': return <CheckCircle className="w-3.5 h-3.5 text-success" />;
    }
  };

  const getSeverityBadge = (severity: RiskFactor['severity']) => {
    switch (severity) {
      case 'critical':
        return <Badge className="bg-critical text-critical-foreground text-xs">Critical</Badge>;
      case 'high':
        return <Badge className="bg-destructive text-destructive-foreground text-xs">High</Badge>;
      case 'medium':
        return <Badge className="bg-warning text-warning-foreground text-xs">Medium</Badge>;
      case 'low':
        return <Badge variant="secondary" className="text-xs">Low</Badge>;
      case 'info':
        return <Badge variant="outline" className="text-xs text-success border-success/30">OK</Badge>;
    }
  };

  const getRiskColor = (score: number) => {
    if (score <= RISK_THRESHOLDS.low.max) return 'bg-success';
    if (score <= RISK_THRESHOLDS.medium.max) return 'bg-warning';
    if (score <= RISK_THRESHOLDS.high.max) return 'bg-destructive';
    return 'bg-critical';
  };

  // Separate issues from positive findings
  const issues = breakdown.factors.filter(f => f.points > 0);
  const positives = breakdown.factors.filter(f => f.points === 0 && f.severity === 'info');

  return (
    <Card className="border-primary/20">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Shield className="w-5 h-5 text-primary" />
              Risk Assessment
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger>
                    <HelpCircle className="w-4 h-4 text-muted-foreground" />
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs">
                    <p className="text-xs">
                      <strong>Scoring:</strong><br />
                      0-25: Low Risk<br />
                      26-50: Medium Risk<br />
                      51-75: High Risk<br />
                      76-100: Critical Risk
                    </p>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            </CardTitle>
            <p className="text-sm text-muted-foreground mt-1">
              {breakdown.summary}
            </p>
          </div>
          <div className="text-right">
            <div className="text-3xl font-bold">
              {breakdown.totalScore}
              <span className="text-lg text-muted-foreground font-normal">/100</span>
            </div>
            <Badge 
              className={`mt-1 ${
                breakdown.level === 'low' ? 'bg-success text-success-foreground' :
                breakdown.level === 'medium' ? 'bg-warning text-warning-foreground' :
                breakdown.level === 'high' ? 'bg-destructive text-destructive-foreground' :
                'bg-critical text-critical-foreground'
              }`}
            >
              {levelInfo.title}
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Risk Score Bar */}
        <div className="space-y-2">
          <div className="flex justify-between text-xs text-muted-foreground">
            <span>Lower is better</span>
            <span>{breakdown.totalScore} points</span>
          </div>
          <div className="relative h-3 bg-muted rounded-full overflow-hidden">
            <div 
              className={`absolute left-0 top-0 h-full transition-all duration-500 ${getRiskColor(breakdown.totalScore)}`}
              style={{ width: `${breakdown.totalScore}%` }}
            />
            {/* Threshold markers */}
            <div className="absolute top-0 left-[25%] w-px h-full bg-background/50" />
            <div className="absolute top-0 left-[50%] w-px h-full bg-background/50" />
            <div className="absolute top-0 left-[75%] w-px h-full bg-background/50" />
          </div>
          <div className="flex justify-between text-[10px] text-muted-foreground">
            <span>Low</span>
            <span>Medium</span>
            <span>High</span>
            <span>Critical</span>
          </div>
        </div>

        {/* Level Explanation */}
        <div className="p-3 rounded-lg bg-muted/30 border border-border/50">
          <p className="text-sm">{levelInfo.description}</p>
          <p className="text-sm text-primary mt-2 font-medium">→ {levelInfo.action}</p>
        </div>

        {/* Issues Found */}
        {issues.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-warning" />
              Issues Found ({issues.length})
            </h4>
            <div className="space-y-2">
              {issues.map((factor, idx) => (
                <div 
                  key={idx}
                  className="p-2.5 rounded-lg bg-muted/20 border border-border/30 flex items-start gap-3"
                >
                  <span className="p-1 rounded bg-muted/50 mt-0.5">
                    {getCategoryIcon(factor.category)}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      {getSeverityIcon(factor.severity)}
                      <span className="text-sm font-medium">{factor.name}</span>
                      <span className="text-xs text-muted-foreground">
                        +{factor.points} pts
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {factor.description}
                    </p>
                  </div>
                  {getSeverityBadge(factor.severity)}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Positive Findings */}
        {positives.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-sm font-medium flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-success" />
              Passing Checks ({positives.length})
            </h4>
            <div className="flex flex-wrap gap-1.5">
              {positives.map((factor, idx) => (
                <Badge 
                  key={idx} 
                  variant="outline" 
                  className="text-xs border-success/30 text-success gap-1"
                >
                  <CheckCircle className="w-3 h-3" />
                  {factor.name.replace('Present: ', '')}
                </Badge>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
