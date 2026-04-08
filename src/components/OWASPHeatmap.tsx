import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

const OWASP_LABELS: Record<string, string> = {
  A01: "Broken Access Control",
  A02: "Cryptographic Failures",
  A03: "Injection",
  A04: "Insecure Design",
  A05: "Security Misconfiguration",
  A06: "Vulnerable Components",
  A07: "Auth Failures",
  A08: "Data Integrity",
  A09: "Logging Failures",
  A10: "SSRF",
};

const severityColor: Record<string, string> = {
  critical: "bg-critical text-critical-foreground",
  high: "bg-destructive text-destructive-foreground",
  medium: "bg-warning text-warning-foreground",
  low: "bg-primary/60 text-primary-foreground",
  info: "bg-muted text-muted-foreground",
  none: "bg-muted/30 text-muted-foreground/50",
};

interface OwaspEntry {
  count: number;
  severity: string;
  findings: string[];
}

interface OWASPHeatmapProps {
  mapping: Record<string, OwaspEntry>;
}

export default function OWASPHeatmap({ mapping }: OWASPHeatmapProps) {
  return (
    <Card className="border-glow glass">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">OWASP Top 10 Heatmap</CardTitle>
      </CardHeader>
      <CardContent>
        <TooltipProvider>
          <div className="grid grid-cols-5 gap-2">
            {Object.entries(OWASP_LABELS).map(([code, label]) => {
              const entry = mapping[code] || { count: 0, severity: "none", findings: [] };
              return (
                <Tooltip key={code}>
                  <TooltipTrigger asChild>
                    <div className={`p-2 rounded-lg text-center cursor-pointer transition-all hover:scale-105 ${severityColor[entry.severity]} border border-border/30`}>
                      <div className="text-xs font-bold">{code}</div>
                      <div className="text-[10px] truncate">{label}</div>
                      {entry.count > 0 && (
                        <Badge variant="outline" className="mt-1 text-[9px] px-1 py-0 bg-background/20">
                          {entry.count}
                        </Badge>
                      )}
                    </div>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs">
                    <p className="font-medium">{code}: {label}</p>
                    <p className="text-xs">{entry.count} finding(s) — {entry.severity}</p>
                    {entry.findings.length > 0 && (
                      <ul className="text-xs mt-1 list-disc pl-3">
                        {entry.findings.slice(0, 5).map((f, i) => <li key={i}>{f}</li>)}
                      </ul>
                    )}
                  </TooltipContent>
                </Tooltip>
              );
            })}
          </div>
        </TooltipProvider>
      </CardContent>
    </Card>
  );
}
