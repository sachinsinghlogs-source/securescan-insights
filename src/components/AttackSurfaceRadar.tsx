import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer } from 'recharts';

interface AttackSurfaceRadarProps {
  stages: Record<string, { findings: any[]; risk_score: number; risk_level: string }>;
}

const stageShortLabels: Record<string, string> = {
  deployment: "Deploy",
  api: "API",
  storage: "Storage",
  infrastructure: "Infra",
  dns_recon: "DNS",
  ssl_deep: "SSL/TLS",
  auth_session: "Auth",
  info_disclosure: "OSINT",
  waf_detection: "WAF",
  injection_surface: "Injection",
};

export default function AttackSurfaceRadar({ stages }: AttackSurfaceRadarProps) {
  const data = Object.entries(stages).map(([key, val]) => ({
    category: stageShortLabels[key] || key,
    score: val.risk_score,
    findings: val.findings.filter((f: any) => f.severity !== "info").length,
  }));

  return (
    <Card className="border-glow glass">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Attack Surface Radar</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={280}>
          <RadarChart data={data} cx="50%" cy="50%" outerRadius="70%">
            <PolarGrid stroke="hsl(var(--border))" />
            <PolarAngleAxis dataKey="category" tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 10 }} />
            <PolarRadiusAxis angle={90} domain={[0, 100]} tick={{ fontSize: 9 }} />
            <Radar name="Risk Score" dataKey="score" stroke="hsl(var(--primary))" fill="hsl(var(--primary))" fillOpacity={0.3} />
          </RadarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
