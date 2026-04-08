import { useState } from 'react';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Loader2, Globe, Shield, CheckCircle, XCircle, AlertTriangle, Info, Trash2, Play, Layers } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import OWASPHeatmap from '@/components/OWASPHeatmap';
import AttackSurfaceRadar from '@/components/AttackSurfaceRadar';

interface Finding {
  id: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  recommendation: string;
  owasp?: string;
  confidence?: number;
}

interface StageResult {
  findings: Finding[];
  risk_level: string;
  risk_score: number;
  duration_ms: number;
}

interface PipelineResult {
  pipeline_id: string;
  target_url: string;
  overall_risk_level: string;
  overall_risk_score: number;
  total_findings: number;
  counts: Record<string, number>;
  stages: Record<string, StageResult>;
  scan_duration_ms: number;
  owasp_mapping?: Record<string, any>;
  compliance_flags?: Record<string, any>;
  remediation_priority?: Array<{ title: string; severity: string; effort: string; impact: string; category: string }>;
  executive_summary?: string;
  attack_surface_score?: number;
}

interface Pipeline {
  id: string;
  target_url: string;
  status: string;
  overall_risk_level: string | null;
  overall_risk_score: number | null;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  completed_stages: string[];
  scan_duration_ms: number | null;
  created_at: string;
}

const stageLabels: Record<string, string> = {
  deployment: '🌐 Deployment',
  api: '🔒 API Security',
  storage: '💾 Storage Audit',
  infrastructure: '🏗️ Infrastructure',
  dns_recon: '🔍 DNS Recon',
  ssl_deep: '🔐 SSL/TLS Deep',
  auth_session: '🛡️ Auth & Session',
  info_disclosure: '📡 OSINT',
  waf_detection: '🧱 WAF Detection',
  injection_surface: '💉 Injection Surface',
};

const progressStages = [
  { pct: 10, label: 'Scanning deployment...' },
  { pct: 20, label: 'Testing API security...' },
  { pct: 30, label: 'Auditing storage...' },
  { pct: 40, label: 'Scanning infrastructure...' },
  { pct: 50, label: 'DNS reconnaissance...' },
  { pct: 58, label: 'Deep SSL/TLS analysis...' },
  { pct: 66, label: 'Auth & session testing...' },
  { pct: 74, label: 'OSINT & info disclosure...' },
  { pct: 82, label: 'WAF detection...' },
  { pct: 90, label: 'Injection surface mapping...' },
];

const riskColors: Record<string, string> = {
  critical: 'text-critical',
  high: 'text-destructive',
  medium: 'text-warning',
  low: 'text-success',
};

const severityConfig = {
  critical: { color: 'bg-critical/20 text-critical border-critical/30', icon: XCircle },
  high: { color: 'bg-destructive/20 text-destructive border-destructive/30', icon: AlertTriangle },
  medium: { color: 'bg-warning/20 text-warning border-warning/30', icon: AlertTriangle },
  low: { color: 'bg-primary/20 text-primary border-primary/30', icon: Info },
  info: { color: 'bg-muted text-muted-foreground border-border', icon: CheckCircle },
};

const complianceIcons: Record<string, typeof CheckCircle> = { pass: CheckCircle, fail: XCircle, warning: AlertTriangle };
const complianceColors: Record<string, string> = { pass: 'text-success', fail: 'text-critical', warning: 'text-warning' };

interface CloudPipelineRunnerProps {
  pipelines: Pipeline[];
  onPipelineComplete: () => void;
}

export default function CloudPipelineRunner({ pipelines, onPipelineComplete }: CloudPipelineRunnerProps) {
  const { user } = useAuth();
  const { toast } = useToast();
  const [url, setUrl] = useState('');
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentStage, setCurrentStage] = useState('');
  const [result, setResult] = useState<PipelineResult | null>(null);
  const [expandedStage, setExpandedStage] = useState<string | null>(null);

  const runPipeline = async () => {
    if (!url.trim() || !user) return;
    setIsRunning(true);
    setResult(null);
    setProgress(0);
    setCurrentStage('Initializing pipeline...');

    let stageIdx = 0;
    const progressInterval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 92) return prev;
        if (stageIdx < progressStages.length && prev >= progressStages[stageIdx].pct) {
          setCurrentStage(progressStages[stageIdx].label);
          stageIdx++;
        }
        return prev + Math.random() * 4;
      });
    }, 1200);

    try {
      const normalizedUrl = url.startsWith('http') ? url : `https://${url}`;
      const { data, error } = await supabase.functions.invoke('cloud-security-pipeline', {
        body: { url: normalizedUrl },
      });

      clearInterval(progressInterval);

      if (error) throw new Error(error.message);
      if (data?.error) throw new Error(data.error);

      setProgress(100);
      setCurrentStage('Pipeline complete!');
      setResult(data);
      toast({ title: 'VAPT Pipeline Complete', description: `Found ${data.total_findings} findings across 10 modules.` });
      onPipelineComplete();
    } catch (err) {
      clearInterval(progressInterval);
      toast({ title: 'Pipeline Failed', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
    } finally {
      setIsRunning(false);
    }
  };

  const handleDelete = async (pipelineId: string) => {
    await supabase.from('cloud_scan_pipelines').delete().eq('id', pipelineId);
    onPipelineComplete();
  };

  return (
    <div className="space-y-6">
      {/* Pipeline Runner */}
      <Card className="border-glow glass">
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center">
              <Layers className="w-5 h-5 text-primary" />
            </div>
            <div>
              <CardTitle>Cloud VAPT Pipeline</CardTitle>
              <CardDescription>10-stage comprehensive security assessment with OWASP mapping & compliance checks</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* 10 Stages overview */}
          <div className="grid grid-cols-5 gap-1.5">
            {Object.entries(stageLabels).map(([key, label]) => (
              <div key={key} className={`p-1.5 rounded-lg border text-center text-[10px] ${
                result?.stages[key] ? 'border-primary/30 bg-primary/5' : 'border-border bg-card/50'
              }`}>
                <span className="font-medium">{label}</span>
              </div>
            ))}
          </div>

          {/* URL + Run */}
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Enter URL for full VAPT assessment (e.g., app.example.com)"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="pl-10 bg-background/50 font-mono text-sm"
                disabled={isRunning}
                onKeyDown={(e) => e.key === 'Enter' && runPipeline()}
              />
            </div>
            <Button onClick={runPipeline} disabled={isRunning || !url.trim()} className="btn-glow bg-primary text-primary-foreground gap-2">
              {isRunning ? <><Loader2 className="w-4 h-4 animate-spin" />Running...</> : <><Play className="w-4 h-4" />Run VAPT</>}
            </Button>
          </div>

          {/* Progress */}
          {isRunning && (
            <div className="space-y-2 animate-fade-in">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">{currentStage}</span>
                <span className="font-mono text-xs">{Math.round(progress)}%</span>
              </div>
              <Progress value={progress} className="h-2" />
            </div>
          )}
        </CardContent>
      </Card>

      {/* Pipeline Result */}
      {result && (
        <>
          <Card className="border-glow glass animate-fade-in">
            <CardHeader>
              <div className="flex items-center justify-between flex-wrap gap-2">
                <CardTitle className="text-lg">VAPT Results</CardTitle>
                <div className="flex items-center gap-3 flex-wrap">
                  <Badge className={`${riskColors[result.overall_risk_level]} border bg-opacity-20`}>
                    Risk: {result.overall_risk_level.toUpperCase()} ({result.overall_risk_score}/100)
                  </Badge>
                  {result.attack_surface_score !== undefined && (
                    <Badge variant="outline">Attack Surface: {result.attack_surface_score}/100</Badge>
                  )}
                  {/* Compliance badges */}
                  {result.compliance_flags && Object.entries(result.compliance_flags).map(([name, val]: [string, any]) => {
                    const Icon = complianceIcons[val.status] || AlertTriangle;
                    return (
                      <Badge key={name} variant="outline" className={`text-xs gap-1 ${complianceColors[val.status] || ''}`}>
                        <Icon className="w-3 h-3" />
                        {name}
                      </Badge>
                    );
                  })}
                  <span className="text-xs text-muted-foreground">{result.scan_duration_ms}ms</span>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Executive Summary */}
              {result.executive_summary && (
                <div className="p-3 rounded-lg bg-muted/50 border border-border">
                  <p className="text-xs font-medium mb-1 text-muted-foreground">Executive Summary</p>
                  <p className="text-sm">{result.executive_summary}</p>
                </div>
              )}

              {/* Summary counts */}
              <div className="flex flex-wrap gap-2">
                {result.counts.critical > 0 && <Badge variant="destructive">{result.counts.critical} Critical</Badge>}
                {result.counts.high > 0 && <Badge className="bg-destructive/20 text-destructive border-destructive/30">{result.counts.high} High</Badge>}
                {result.counts.medium > 0 && <Badge className="bg-warning/20 text-warning border-warning/30">{result.counts.medium} Medium</Badge>}
                {result.counts.low > 0 && <Badge className="bg-primary/20 text-primary border-primary/30">{result.counts.low} Low</Badge>}
                {result.counts.info > 0 && <Badge variant="secondary">{result.counts.info} Info</Badge>}
              </div>

              {/* Stage breakdown */}
              <div className="space-y-2">
                {Object.entries(result.stages).map(([stage, data]) => (
                  <div key={stage} className="border border-border rounded-lg overflow-hidden">
                    <button
                      onClick={() => setExpandedStage(expandedStage === stage ? null : stage)}
                      className="w-full flex items-center justify-between p-3 hover:bg-muted/50 transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <span className="font-medium text-sm">{stageLabels[stage] || stage}</span>
                        <Badge variant="outline" className="text-[10px]">{data.findings.length} findings</Badge>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge className={`text-xs ${riskColors[data.risk_level]} bg-opacity-20 border`}>
                          {data.risk_level.toUpperCase()}
                        </Badge>
                        <span className="text-[10px] text-muted-foreground">{data.duration_ms}ms</span>
                      </div>
                    </button>

                    {expandedStage === stage && (
                      <div className="border-t border-border p-3 space-y-2 bg-muted/20">
                        {data.findings.map((finding) => {
                          const config = severityConfig[finding.severity];
                          const SevIcon = config.icon;
                          return (
                            <div key={finding.id} className={`p-2.5 rounded-lg border ${config.color}`}>
                              <div className="flex items-start gap-2">
                                <SevIcon className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <span className="font-medium text-xs">{finding.title}</span>
                                    <Badge variant="outline" className="text-[9px] px-1 py-0">{finding.category}</Badge>
                                    {finding.owasp && <Badge variant="outline" className="text-[9px] px-1 py-0">{finding.owasp}</Badge>}
                                    {finding.confidence && <span className="text-[9px] text-muted-foreground">{finding.confidence}% conf</span>}
                                  </div>
                                  <p className="text-[11px] text-muted-foreground mt-0.5">{finding.description}</p>
                                  <p className="text-[11px] mt-1"><strong>Fix:</strong> {finding.recommendation}</p>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* OWASP + Radar */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 animate-fade-in">
            {result.owasp_mapping && <OWASPHeatmap mapping={result.owasp_mapping} />}
            <AttackSurfaceRadar stages={result.stages} />
          </div>

          {/* Remediation Priority */}
          {result.remediation_priority && result.remediation_priority.length > 0 && (
            <Card className="border-glow glass animate-fade-in">
              <CardHeader>
                <CardTitle className="text-base">Remediation Roadmap</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-1.5 max-h-80 overflow-y-auto">
                  {result.remediation_priority.slice(0, 20).map((item, i) => (
                    <div key={i} className="flex items-center justify-between p-2 rounded-lg border border-border bg-card/50 text-xs">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="font-mono text-muted-foreground w-6">{i + 1}.</span>
                        <span className="truncate">{item.title}</span>
                      </div>
                      <div className="flex items-center gap-1.5 flex-shrink-0">
                        <Badge variant="outline" className="text-[9px] px-1 py-0">{item.category}</Badge>
                        <Badge className={`text-[9px] px-1 py-0 ${riskColors[item.severity]} bg-opacity-20 border`}>{item.severity}</Badge>
                        <span className="text-muted-foreground text-[10px]">{item.effort}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* CI/CD Webhook Info */}
      <Card className="glass">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary" />
            CI/CD Integration
          </CardTitle>
          <CardDescription>Trigger VAPT pipeline from your deployment workflow</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="p-3 rounded-lg bg-muted/50 border border-border">
            <p className="text-xs font-medium mb-2 text-muted-foreground">API Endpoint</p>
            <code className="text-xs font-mono break-all text-foreground">
              POST {`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/cloud-security-pipeline`}
            </code>
          </div>
          <div className="p-3 rounded-lg bg-muted/50 border border-border">
            <p className="text-xs font-medium mb-2 text-muted-foreground">Example (curl)</p>
            <pre className="text-[10px] font-mono text-muted-foreground overflow-x-auto whitespace-pre-wrap">
{`curl -X POST \\
  ${import.meta.env.VITE_SUPABASE_URL}/functions/v1/cloud-security-pipeline \\
  -H "Authorization: Bearer YOUR_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://your-app.com", "webhook": true}'`}
            </pre>
          </div>
        </CardContent>
      </Card>

      {/* Pipeline History */}
      {pipelines.length > 0 && (
        <Card className="glass">
          <CardHeader>
            <CardTitle className="text-lg">Pipeline History</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {pipelines.map((p) => (
                <div key={p.id} className="flex items-center justify-between p-3 rounded-lg border border-border bg-card/50">
                  <div className="flex items-center gap-3 min-w-0 flex-1">
                    <Badge variant="outline" className="text-xs flex-shrink-0">
                      {p.completed_stages?.length || 0}/10 stages
                    </Badge>
                    <span className="text-sm font-mono truncate">{(() => { try { return new URL(p.target_url).hostname; } catch { return p.target_url; } })()}</span>
                    {p.overall_risk_level && (
                      <Badge className={`text-xs ${riskColors[p.overall_risk_level] || ''} bg-opacity-20 border flex-shrink-0`}>
                        {p.overall_risk_level.toUpperCase()} ({p.overall_risk_score})
                      </Badge>
                    )}
                    {p.total_findings > 0 && (
                      <span className="text-xs text-muted-foreground flex-shrink-0">{p.total_findings} findings</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className="text-xs text-muted-foreground">{new Date(p.created_at).toLocaleDateString()}</span>
                    <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => handleDelete(p.id)}>
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
