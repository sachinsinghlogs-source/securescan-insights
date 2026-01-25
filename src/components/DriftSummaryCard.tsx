import { useMemo } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { 
  TrendingDown, 
  TrendingUp, 
  Minus,
  CheckCircle,
  AlertTriangle,
  GitCompare,
  ArrowRight
} from 'lucide-react';
import type { Scan } from '@/types/database';

interface DriftSummaryCardProps {
  currentScan: Scan;
  previousScan?: Scan;
  onClick?: () => void;
}

export default function DriftSummaryCard({ 
  currentScan, 
  previousScan,
  onClick 
}: DriftSummaryCardProps) {
  const summary = useMemo(() => {
    if (!previousScan) {
      return { 
        status: 'first' as const, 
        regressions: 0, 
        improvements: 0, 
        notices: 0,
        details: []
      };
    }

    let regressions = 0;
    let improvements = 0;
    let notices = 0;
    const details: string[] = [];

    // SSL Changes
    if (previousScan.ssl_valid !== currentScan.ssl_valid) {
      if (currentScan.ssl_valid) {
        improvements++;
        details.push('SSL restored');
      } else {
        regressions++;
        details.push('SSL invalid');
      }
    }

    // Risk Level Changes
    if (previousScan.risk_level !== currentScan.risk_level) {
      const riskOrder = ['low', 'medium', 'high', 'critical'];
      const prevRisk = riskOrder.indexOf(previousScan.risk_level || 'low');
      const currRisk = riskOrder.indexOf(currentScan.risk_level || 'low');
      
      if (currRisk < prevRisk) {
        improvements++;
        details.push('Risk level improved');
      } else {
        regressions++;
        details.push('Risk level worsened');
      }
    }

    // Header Changes
    const prevMissing = new Set(previousScan.missing_headers || []);
    const currMissing = new Set(currentScan.missing_headers || []);
    const prevPresent = new Set(previousScan.present_headers || []);
    const currPresent = new Set(currentScan.present_headers || []);

    let headersAdded = 0;
    let headersRemoved = 0;

    prevMissing.forEach(header => {
      if (currPresent.has(header)) {
        headersAdded++;
      }
    });

    prevPresent.forEach(header => {
      if (currMissing.has(header)) {
        headersRemoved++;
      }
    });

    if (headersAdded > 0) {
      improvements += headersAdded;
      details.push(`${headersAdded} header${headersAdded > 1 ? 's' : ''} added`);
    }
    if (headersRemoved > 0) {
      regressions += headersRemoved;
      details.push(`${headersRemoved} header${headersRemoved > 1 ? 's' : ''} removed`);
    }

    // Technology Changes
    const prevTech = new Set(previousScan.detected_technologies || []);
    const currTech = new Set(currentScan.detected_technologies || []);
    
    let techChanges = 0;
    currTech.forEach(tech => { if (!prevTech.has(tech)) techChanges++; });
    prevTech.forEach(tech => { if (!currTech.has(tech)) techChanges++; });
    
    if (techChanges > 0) {
      notices += techChanges;
    }

    const status = regressions > 0 ? 'regression' as const : 
                   improvements > 0 ? 'improvement' as const : 
                   notices > 0 ? 'notice' as const : 'stable' as const;

    return { status, regressions, improvements, notices, details };
  }, [currentScan, previousScan]);

  const getStatusDisplay = () => {
    switch (summary.status) {
      case 'first':
        return {
          icon: <GitCompare className="w-4 h-4 text-muted-foreground" />,
          label: 'First Scan',
          color: 'text-muted-foreground',
          bg: 'bg-muted/30',
          border: 'border-border/50',
        };
      case 'regression':
        return {
          icon: <TrendingUp className="w-4 h-4 text-critical" />,
          label: 'Regression',
          color: 'text-critical',
          bg: 'bg-critical/10',
          border: 'border-critical/30',
        };
      case 'improvement':
        return {
          icon: <TrendingDown className="w-4 h-4 text-success" />,
          label: 'Improved',
          color: 'text-success',
          bg: 'bg-success/10',
          border: 'border-success/30',
        };
      case 'notice':
        return {
          icon: <AlertTriangle className="w-4 h-4 text-warning" />,
          label: 'Changes',
          color: 'text-warning',
          bg: 'bg-warning/10',
          border: 'border-warning/30',
        };
      default:
        return {
          icon: <CheckCircle className="w-4 h-4 text-success" />,
          label: 'Stable',
          color: 'text-success',
          bg: 'bg-success/5',
          border: 'border-success/20',
        };
    }
  };

  const display = getStatusDisplay();

  return (
    <Card 
      className={`${display.bg} ${display.border} border transition-all ${onClick ? 'cursor-pointer hover:scale-[1.02]' : ''}`}
      onClick={onClick}
    >
      <CardContent className="p-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {display.icon}
            <span className={`text-sm font-medium ${display.color}`}>
              {display.label}
            </span>
          </div>
          
          <div className="flex items-center gap-2">
            {summary.regressions > 0 && (
              <Badge variant="outline" className="border-critical/30 text-critical text-xs gap-1">
                <Minus className="w-3 h-3" />
                {summary.regressions}
              </Badge>
            )}
            {summary.improvements > 0 && (
              <Badge variant="outline" className="border-success/30 text-success text-xs gap-1">
                <TrendingDown className="w-3 h-3" />
                {summary.improvements}
              </Badge>
            )}
            {onClick && (
              <ArrowRight className="w-4 h-4 text-muted-foreground" />
            )}
          </div>
        </div>
        
        {summary.details.length > 0 && (
          <p className="text-xs text-muted-foreground mt-2 line-clamp-1">
            {summary.details.slice(0, 2).join(' • ')}
            {summary.details.length > 2 && ` +${summary.details.length - 2} more`}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
