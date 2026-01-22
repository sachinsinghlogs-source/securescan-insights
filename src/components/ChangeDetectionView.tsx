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
  Shield
} from 'lucide-react';
import type { Scan } from '@/types/database';

interface ChangeDetectionViewProps {
  currentScan: Scan;
  previousScan?: Scan;
}

interface Change {
  type: 'added' | 'removed' | 'changed';
  category: 'header' | 'ssl' | 'risk' | 'tech';
  label: string;
  detail?: string;
  severity: 'good' | 'warning' | 'bad';
}

export default function ChangeDetectionView({ 
  currentScan, 
  previousScan 
}: ChangeDetectionViewProps) {
  const changes = useMemo(() => {
    if (!previousScan) return [];

    const detectedChanges: Change[] = [];

    // SSL Changes
    if (previousScan.ssl_valid !== currentScan.ssl_valid) {
      detectedChanges.push({
        type: 'changed',
        category: 'ssl',
        label: 'SSL Status',
        detail: `${previousScan.ssl_valid ? 'Valid' : 'Invalid'} → ${currentScan.ssl_valid ? 'Valid' : 'Invalid'}`,
        severity: currentScan.ssl_valid ? 'good' : 'bad',
      });
    }

    // Risk Level Changes
    if (previousScan.risk_level !== currentScan.risk_level) {
      const riskOrder = ['low', 'medium', 'high', 'critical'];
      const prevRisk = riskOrder.indexOf(previousScan.risk_level || 'low');
      const currRisk = riskOrder.indexOf(currentScan.risk_level || 'low');
      
      detectedChanges.push({
        type: 'changed',
        category: 'risk',
        label: 'Risk Level',
        detail: `${previousScan.risk_level} → ${currentScan.risk_level}`,
        severity: currRisk < prevRisk ? 'good' : 'bad',
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
        detectedChanges.push({
          type: 'added',
          category: 'header',
          label: header,
          detail: 'Security header added',
          severity: 'good',
        });
      }
    });

    // Headers that were removed (now missing, were present)
    prevPresent.forEach(header => {
      if (currMissing.has(header)) {
        detectedChanges.push({
          type: 'removed',
          category: 'header',
          label: header,
          detail: 'Security header removed',
          severity: 'bad',
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
        });
      }
    });

    return detectedChanges;
  }, [currentScan, previousScan]);

  if (!previousScan) {
    return (
      <Card className="border-border/50">
        <CardContent className="py-6 text-center text-muted-foreground">
          <GitCompare className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No previous scan to compare</p>
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

  const goodChanges = changes.filter(c => c.severity === 'good');
  const badChanges = changes.filter(c => c.severity === 'bad');
  const warningChanges = changes.filter(c => c.severity === 'warning');

  return (
    <Card className="border-glow glass">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <GitCompare className="w-4 h-4 text-primary" />
            Changes Detected
          </CardTitle>
          <div className="flex gap-2">
            {goodChanges.length > 0 && (
              <Badge className="bg-success/20 text-success border-success/30">
                +{goodChanges.length}
              </Badge>
            )}
            {badChanges.length > 0 && (
              <Badge className="bg-critical/20 text-critical border-critical/30">
                -{badChanges.length}
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>
      
      <CardContent className="space-y-2">
        {/* Bad changes first */}
        {badChanges.map((change, i) => (
          <div 
            key={`bad-${i}`}
            className="flex items-center gap-3 p-2 rounded-lg bg-critical/10 border border-critical/20"
          >
            {change.type === 'removed' ? (
              <Minus className="w-4 h-4 text-critical shrink-0" />
            ) : (
              <ShieldOff className="w-4 h-4 text-critical shrink-0" />
            )}
            <div className="flex-1 min-w-0">
              <span className="text-sm font-medium">{change.label}</span>
              {change.detail && (
                <p className="text-xs text-muted-foreground">{change.detail}</p>
              )}
            </div>
          </div>
        ))}

        {/* Warning changes */}
        {warningChanges.map((change, i) => (
          <div 
            key={`warn-${i}`}
            className="flex items-center gap-3 p-2 rounded-lg bg-warning/10 border border-warning/20"
          >
            <AlertTriangle className="w-4 h-4 text-warning shrink-0" />
            <div className="flex-1 min-w-0">
              <span className="text-sm font-medium">{change.label}</span>
              {change.detail && (
                <p className="text-xs text-muted-foreground">{change.detail}</p>
              )}
            </div>
          </div>
        ))}

        {/* Good changes */}
        {goodChanges.map((change, i) => (
          <div 
            key={`good-${i}`}
            className="flex items-center gap-3 p-2 rounded-lg bg-success/10 border border-success/20"
          >
            {change.type === 'added' ? (
              <Plus className="w-4 h-4 text-success shrink-0" />
            ) : (
              <Shield className="w-4 h-4 text-success shrink-0" />
            )}
            <div className="flex-1 min-w-0">
              <span className="text-sm font-medium">{change.label}</span>
              {change.detail && (
                <p className="text-xs text-muted-foreground">{change.detail}</p>
              )}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
