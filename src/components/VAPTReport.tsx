import { useState, useEffect } from 'react';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Trash2, FileText, Shield, CheckCircle, XCircle, AlertTriangle, ChevronDown, ChevronUp, Link2 } from 'lucide-react';
import OWASPHeatmap from '@/components/OWASPHeatmap';

interface VAPTReportData {
  id: string;
  pipeline_id: string;
  target_url: string;
  executive_summary: string | null;
  owasp_mapping: any;
  attack_surface_score: number;
  compliance_flags: any;
  remediation_priority: any[];
  finding_chains: any[];
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  overall_risk_score: number;
  overall_risk_level: string | null;
  scan_duration_ms: number | null;
  created_at: string;
}

const riskColors: Record<string, string> = {
  critical: 'text-critical',
  high: 'text-destructive',
  medium: 'text-warning',
  low: 'text-success',
};

const complianceIcons: Record<string, typeof CheckCircle> = { pass: CheckCircle, fail: XCircle, warning: AlertTriangle };
const complianceColors: Record<string, string> = { pass: 'text-success', fail: 'text-critical', warning: 'text-warning' };

export default function VAPTReport() {
  const { user } = useAuth();
  const [reports, setReports] = useState<VAPTReportData[]>([]);
  const [expandedReport, setExpandedReport] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (user) fetchReports();
  }, [user]);

  const fetchReports = async () => {
    setLoading(true);
    const { data } = await supabase
      .from('vapt_reports')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(50);
    if (data) setReports(data as unknown as VAPTReportData[]);
    setLoading(false);
  };

  const handleDelete = async (id: string) => {
    await supabase.from('vapt_reports').delete().eq('id', id);
    fetchReports();
  };

  if (loading) {
    return (
      <Card className="glass animate-pulse">
        <CardContent className="p-6"><div className="h-4 bg-muted rounded w-1/3"></div></CardContent>
      </Card>
    );
  }

  if (reports.length === 0) {
    return (
      <Card className="glass">
        <CardContent className="p-12 text-center">
          <FileText className="w-12 h-12 mx-auto text-muted-foreground/50 mb-4" />
          <h3 className="text-lg font-medium mb-2">No VAPT Reports Yet</h3>
          <p className="text-sm text-muted-foreground">Run a Cloud Pipeline scan to generate your first comprehensive VAPT report.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {reports.map((report) => {
        const isExpanded = expandedReport === report.id;
        const hostname = (() => { try { return new URL(report.target_url).hostname; } catch { return report.target_url; } })();
        const compliance = (report.compliance_flags || {}) as Record<string, { status: string; issues: string[] }>;
        const remediation = (report.remediation_priority || []) as Array<{ title: string; severity: string; effort: string; impact: string; category: string; cvss_score?: number }>;
        const chains = (report.finding_chains || []) as Array<{ chain_id: string; title: string; severity: string; finding_ids: string[]; description: string; combined_impact: string }>;

        return (
          <Card key={report.id} className="border-glow glass">
            <CardHeader className="cursor-pointer" onClick={() => setExpandedReport(isExpanded ? null : report.id)}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3 min-w-0">
                  <Shield className="w-5 h-5 text-primary flex-shrink-0" />
                  <div className="min-w-0">
                    <CardTitle className="text-base truncate">{hostname}</CardTitle>
                    <CardDescription className="text-xs">{new Date(report.created_at).toLocaleString()}</CardDescription>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  {report.overall_risk_level && (
                    <Badge className={`${riskColors[report.overall_risk_level]} border bg-opacity-20`}>
                      {report.overall_risk_level.toUpperCase()} ({report.overall_risk_score}/100)
                    </Badge>
                  )}
                  <Badge variant="outline">{report.total_findings} findings</Badge>
                  {chains.length > 0 && (
                    <Badge variant="outline" className="gap-1 text-warning"><Link2 className="w-3 h-3" />{chains.length} chains</Badge>
                  )}
                  {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </div>
              </div>
            </CardHeader>

            {isExpanded && (
              <CardContent className="space-y-4 pt-0">
                {report.executive_summary && (
                  <div className="p-3 rounded-lg bg-muted/50 border border-border">
                    <p className="text-xs font-medium mb-1 text-muted-foreground">Executive Summary</p>
                    <p className="text-sm">{report.executive_summary}</p>
                  </div>
                )}

                <div className="flex flex-wrap gap-2">
                  {report.critical_count > 0 && <Badge variant="destructive">{report.critical_count} Critical</Badge>}
                  {report.high_count > 0 && <Badge className="bg-destructive/20 text-destructive border-destructive/30">{report.high_count} High</Badge>}
                  {report.medium_count > 0 && <Badge className="bg-warning/20 text-warning border-warning/30">{report.medium_count} Medium</Badge>}
                  {report.low_count > 0 && <Badge className="bg-primary/20 text-primary border-primary/30">{report.low_count} Low</Badge>}
                  {report.info_count > 0 && <Badge variant="secondary">{report.info_count} Info</Badge>}
                </div>

                {/* Vulnerability Chains */}
                {chains.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-sm font-medium flex items-center gap-1.5"><Link2 className="w-4 h-4 text-primary" /> Vulnerability Chains</p>
                    {chains.map((chain) => (
                      <div key={chain.chain_id} className={`p-3 rounded-lg border ${
                        chain.severity === 'critical' ? 'border-critical/30 bg-critical/5' :
                        chain.severity === 'high' ? 'border-destructive/30 bg-destructive/5' :
                        'border-warning/30 bg-warning/5'
                      }`}>
                        <div className="flex items-center gap-2 mb-1">
                          <Link2 className="w-3.5 h-3.5" />
                          <span className="text-sm font-medium">{chain.title}</span>
                          <Badge className={`text-[9px] ${riskColors[chain.severity]} bg-opacity-20 border`}>{chain.severity}</Badge>
                        </div>
                        <p className="text-xs text-muted-foreground">{chain.description}</p>
                        <p className="text-xs mt-1"><strong>Impact:</strong> {chain.combined_impact}</p>
                      </div>
                    ))}
                  </div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-3 rounded-lg bg-muted/50 border border-border">
                    <p className="text-xs font-medium mb-2 text-muted-foreground">Attack Surface Score</p>
                    <div className="flex items-end gap-2">
                      <span className="text-3xl font-bold">{report.attack_surface_score}</span>
                      <span className="text-sm text-muted-foreground mb-1">/100</span>
                    </div>
                    <div className="w-full bg-muted rounded-full h-2 mt-2">
                      <div className="bg-primary h-2 rounded-full transition-all" style={{ width: `${report.attack_surface_score}%` }} />
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-muted/50 border border-border">
                    <p className="text-xs font-medium mb-2 text-muted-foreground">Compliance Status</p>
                    <div className="space-y-1.5">
                      {Object.entries(compliance).map(([name, val]) => {
                        const Icon = complianceIcons[val.status] || AlertTriangle;
                        return (
                          <div key={name} className="flex items-center justify-between">
                            <span className="text-sm">{name}</span>
                            <div className={`flex items-center gap-1 ${complianceColors[val.status]}`}>
                              <Icon className="w-3.5 h-3.5" />
                              <span className="text-xs font-medium capitalize">{val.status}</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>

                {report.owasp_mapping && <OWASPHeatmap mapping={report.owasp_mapping} />}

                {remediation.length > 0 && (
                  <div>
                    <p className="text-sm font-medium mb-2">Remediation Priority</p>
                    <div className="space-y-1.5 max-h-60 overflow-y-auto">
                      {remediation.slice(0, 20).map((item, i) => (
                        <div key={i} className="flex items-center justify-between p-2 rounded-lg border border-border bg-card/50 text-xs">
                          <div className="flex items-center gap-2 min-w-0">
                            <span className="font-mono text-muted-foreground w-5">{i + 1}.</span>
                            <span className="truncate">{item.title}</span>
                          </div>
                          <div className="flex items-center gap-1.5 flex-shrink-0">
                            <Badge variant="outline" className="text-[9px] px-1 py-0">{item.category}</Badge>
                            <Badge className={`text-[9px] px-1 py-0 ${riskColors[item.severity]} bg-opacity-20 border`}>{item.severity}</Badge>
                            {item.cvss_score !== undefined && item.cvss_score > 0 && (
                              <Badge className="text-[9px] px-1 py-0 bg-muted border">{item.cvss_score}</Badge>
                            )}
                            <span className="text-muted-foreground text-[10px]">Effort: {item.effort}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex justify-end gap-2 pt-2">
                  <Button variant="ghost" size="sm" className="text-destructive" onClick={() => handleDelete(report.id)}>
                    <Trash2 className="w-3 h-3 mr-1" /> Delete
                  </Button>
                </div>
              </CardContent>
            )}
          </Card>
        );
      })}
    </div>
  );
}
