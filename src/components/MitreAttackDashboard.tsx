import { useState, useEffect } from 'react';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Shield, Target, ChevronDown, ChevronUp, Crosshair, Layers, X } from 'lucide-react';

// MITRE ATT&CK Enterprise Tactics (in kill chain order)
const MITRE_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance', shortName: 'Recon', color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  { id: 'TA0042', name: 'Resource Development', shortName: 'Resource', color: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30' },
  { id: 'TA0001', name: 'Initial Access', shortName: 'Init Access', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
  { id: 'TA0002', name: 'Execution', shortName: 'Execution', color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
  { id: 'TA0003', name: 'Persistence', shortName: 'Persist', color: 'bg-amber-500/20 text-amber-400 border-amber-500/30' },
  { id: 'TA0004', name: 'Privilege Escalation', shortName: 'Priv Esc', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  { id: 'TA0005', name: 'Defense Evasion', shortName: 'Evasion', color: 'bg-lime-500/20 text-lime-400 border-lime-500/30' },
  { id: 'TA0006', name: 'Credential Access', shortName: 'Cred Access', color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' },
  { id: 'TA0007', name: 'Discovery', shortName: 'Discovery', color: 'bg-teal-500/20 text-teal-400 border-teal-500/30' },
  { id: 'TA0008', name: 'Lateral Movement', shortName: 'Lateral', color: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30' },
  { id: 'TA0009', name: 'Collection', shortName: 'Collection', color: 'bg-sky-500/20 text-sky-400 border-sky-500/30' },
  { id: 'TA0011', name: 'Command & Control', shortName: 'C2', color: 'bg-violet-500/20 text-violet-400 border-violet-500/30' },
  { id: 'TA0010', name: 'Exfiltration', shortName: 'Exfil', color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
  { id: 'TA0040', name: 'Impact', shortName: 'Impact', color: 'bg-rose-500/20 text-rose-400 border-rose-500/30' },
];

// Techniques per tactic (key subset relevant to web/cloud VAPT)
const MITRE_TECHNIQUES: Record<string, Array<{ id: string; name: string }>> = {
  TA0043: [
    { id: 'T1595', name: 'Active Scanning' },
    { id: 'T1592', name: 'Gather Victim Host Info' },
    { id: 'T1589', name: 'Gather Victim Identity Info' },
    { id: 'T1590', name: 'Gather Victim Network Info' },
    { id: 'T1596', name: 'Search Open Tech Databases' },
    { id: 'T1593', name: 'Search Open Websites/Domains' },
  ],
  TA0042: [
    { id: 'T1583', name: 'Acquire Infrastructure' },
    { id: 'T1584', name: 'Compromise Infrastructure' },
    { id: 'T1587', name: 'Develop Capabilities' },
  ],
  TA0001: [
    { id: 'T1190', name: 'Exploit Public-Facing App' },
    { id: 'T1133', name: 'External Remote Services' },
    { id: 'T1078', name: 'Valid Accounts' },
    { id: 'T1189', name: 'Drive-by Compromise' },
    { id: 'T1566', name: 'Phishing' },
    { id: 'T1195', name: 'Supply Chain Compromise' },
  ],
  TA0002: [
    { id: 'T1059', name: 'Command & Scripting' },
    { id: 'T1203', name: 'Exploitation for Client Exec' },
    { id: 'T1047', name: 'WMI' },
    { id: 'T1204', name: 'User Execution' },
  ],
  TA0003: [
    { id: 'T1098', name: 'Account Manipulation' },
    { id: 'T1136', name: 'Create Account' },
    { id: 'T1505', name: 'Server Software Component' },
    { id: 'T1053', name: 'Scheduled Task/Job' },
  ],
  TA0004: [
    { id: 'T1548', name: 'Abuse Elevation Control' },
    { id: 'T1134', name: 'Access Token Manipulation' },
    { id: 'T1068', name: 'Exploitation for Priv Esc' },
    { id: 'T1078.004', name: 'Cloud Accounts' },
  ],
  TA0005: [
    { id: 'T1562', name: 'Impair Defenses' },
    { id: 'T1070', name: 'Indicator Removal' },
    { id: 'T1027', name: 'Obfuscated Files/Info' },
    { id: 'T1036', name: 'Masquerading' },
  ],
  TA0006: [
    { id: 'T1110', name: 'Brute Force' },
    { id: 'T1539', name: 'Steal Web Session Cookie' },
    { id: 'T1528', name: 'Steal App Access Token' },
    { id: 'T1552', name: 'Unsecured Credentials' },
    { id: 'T1556', name: 'Modify Auth Process' },
  ],
  TA0007: [
    { id: 'T1087', name: 'Account Discovery' },
    { id: 'T1580', name: 'Cloud Infrastructure Discovery' },
    { id: 'T1046', name: 'Network Service Discovery' },
    { id: 'T1518', name: 'Software Discovery' },
  ],
  TA0008: [
    { id: 'T1210', name: 'Exploitation of Remote Svcs' },
    { id: 'T1550', name: 'Use Alternate Auth Material' },
    { id: 'T1021', name: 'Remote Services' },
  ],
  TA0009: [
    { id: 'T1530', name: 'Data from Cloud Storage' },
    { id: 'T1213', name: 'Data from Info Repositories' },
    { id: 'T1005', name: 'Data from Local System' },
  ],
  TA0011: [
    { id: 'T1071', name: 'Application Layer Protocol' },
    { id: 'T1102', name: 'Web Service' },
    { id: 'T1572', name: 'Protocol Tunneling' },
  ],
  TA0010: [
    { id: 'T1048', name: 'Exfil Over Alternative Proto' },
    { id: 'T1567', name: 'Exfil Over Web Service' },
    { id: 'T1041', name: 'Exfil Over C2 Channel' },
  ],
  TA0040: [
    { id: 'T1485', name: 'Data Destruction' },
    { id: 'T1486', name: 'Data Encrypted for Impact' },
    { id: 'T1499', name: 'Endpoint DoS' },
    { id: 'T1498', name: 'Network DoS' },
    { id: 'T1491', name: 'Defacement' },
  ],
};

interface MitreMapping {
  [tacticId: string]: {
    [techniqueId: string]: {
      count: number;
      severity: string;
      findings: Array<{ id: string; title: string; severity: string; cvss_score?: number }>;
    };
  };
}

interface ReportOption {
  id: string;
  target_url: string;
  created_at: string;
  mitre_mapping: MitreMapping | null;
}

const severityHeatColor = (severity: string, count: number): string => {
  if (count === 0) return '';
  switch (severity) {
    case 'critical': return 'bg-red-500/40 border-red-500/60 shadow-red-500/20 shadow-sm';
    case 'high': return 'bg-orange-500/30 border-orange-500/50 shadow-orange-500/15 shadow-sm';
    case 'medium': return 'bg-yellow-500/25 border-yellow-500/40';
    case 'low': return 'bg-blue-500/20 border-blue-500/30';
    default: return 'bg-muted/30 border-border';
  }
};

export default function MitreAttackDashboard() {
  const { user } = useAuth();
  const [reports, setReports] = useState<ReportOption[]>([]);
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);
  const [mitreData, setMitreData] = useState<MitreMapping | null>(null);
  const [expandedTactic, setExpandedTactic] = useState<string | null>(null);
  const [drillDownTechnique, setDrillDownTechnique] = useState<{ tacticId: string; techniqueId: string } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (user) fetchReports();
  }, [user]);

  const fetchReports = async () => {
    setLoading(true);
    const { data } = await supabase
      .from('vapt_reports')
      .select('id, target_url, created_at, mitre_mapping')
      .order('created_at', { ascending: false })
      .limit(50);
    if (data) {
      setReports(data as unknown as ReportOption[]);
      if (data.length > 0) {
        setSelectedReportId(data[0].id);
        setMitreData((data[0] as any).mitre_mapping || null);
      }
    }
    setLoading(false);
  };

  const handleReportChange = (reportId: string) => {
    setSelectedReportId(reportId);
    const report = reports.find(r => r.id === reportId);
    setMitreData(report?.mitre_mapping || null);
    setDrillDownTechnique(null);
    setExpandedTactic(null);
  };

  // Compute tactic-level stats
  const tacticStats = MITRE_TACTICS.map(tactic => {
    const tacticData = mitreData?.[tactic.id] || {};
    let totalFindings = 0;
    let maxSeverity = 'info';
    const sevOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

    for (const tech of Object.values(tacticData)) {
      totalFindings += tech.count;
      if ((sevOrder[tech.severity] || 0) > (sevOrder[maxSeverity] || 0)) {
        maxSeverity = tech.severity;
      }
    }

    return { ...tactic, totalFindings, maxSeverity, techniques: tacticData };
  });

  const totalMappedFindings = tacticStats.reduce((sum, t) => sum + t.totalFindings, 0);
  const activeTactics = tacticStats.filter(t => t.totalFindings > 0).length;
  const criticalTactics = tacticStats.filter(t => t.maxSeverity === 'critical').length;

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
          <Target className="w-12 h-12 mx-auto text-muted-foreground/50 mb-4" />
          <h3 className="text-lg font-medium mb-2">No MITRE ATT&CK Data</h3>
          <p className="text-sm text-muted-foreground">Run a Cloud VAPT Pipeline scan to generate MITRE ATT&CK mappings.</p>
        </CardContent>
      </Card>
    );
  }

  const drillDownData = drillDownTechnique
    ? mitreData?.[drillDownTechnique.tacticId]?.[drillDownTechnique.techniqueId]
    : null;

  return (
    <div className="space-y-6">
      {/* Header + Report Selector */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center">
            <Crosshair className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h2 className="text-xl font-bold">MITRE ATT&CK Matrix</h2>
            <p className="text-sm text-muted-foreground">Enterprise technique coverage from VAPT findings</p>
          </div>
        </div>

        <Select value={selectedReportId || ''} onValueChange={handleReportChange}>
          <SelectTrigger className="w-[280px]">
            <SelectValue placeholder="Select a report" />
          </SelectTrigger>
          <SelectContent>
            {reports.map(r => {
              const hostname = (() => { try { return new URL(r.target_url).hostname; } catch { return r.target_url; } })();
              return (
                <SelectItem key={r.id} value={r.id}>
                  {hostname} — {new Date(r.created_at).toLocaleDateString()}
                </SelectItem>
              );
            })}
          </SelectContent>
        </Select>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="border-glow glass">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold">{totalMappedFindings}</p>
            <p className="text-xs text-muted-foreground">Mapped Findings</p>
          </CardContent>
        </Card>
        <Card className="border-glow glass">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold">{activeTactics}</p>
            <p className="text-xs text-muted-foreground">Active Tactics</p>
          </CardContent>
        </Card>
        <Card className="border-glow glass">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-destructive">{criticalTactics}</p>
            <p className="text-xs text-muted-foreground">Critical Tactics</p>
          </CardContent>
        </Card>
        <Card className="border-glow glass">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold">{MITRE_TACTICS.length}</p>
            <p className="text-xs text-muted-foreground">Total Tactics</p>
          </CardContent>
        </Card>
      </div>

      {/* MITRE Matrix Grid */}
      <Card className="border-glow glass">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Layers className="w-4 h-4 text-primary" />
            ATT&CK Technique Heatmap
          </CardTitle>
          <CardDescription className="text-xs">Click any cell to drill down into related findings</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-1">
            {tacticStats.map(tactic => {
              const isExpanded = expandedTactic === tactic.id;
              const techniques = MITRE_TECHNIQUES[tactic.id] || [];

              return (
                <div key={tactic.id}>
                  {/* Tactic Row */}
                  <div
                    className="flex items-center gap-2 p-2 rounded-lg cursor-pointer hover:bg-muted/30 transition-colors"
                    onClick={() => setExpandedTactic(isExpanded ? null : tactic.id)}
                  >
                    <div className="flex items-center gap-1 w-5">
                      {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </div>
                    <Badge className={`text-[10px] px-1.5 py-0 ${tactic.color} border`}>
                      {tactic.id}
                    </Badge>
                    <span className="text-sm font-medium flex-1 min-w-0 truncate">{tactic.name}</span>

                    {/* Mini technique heatmap cells */}
                    <div className="hidden sm:flex items-center gap-0.5">
                      {techniques.map(tech => {
                        const techData = tactic.techniques[tech.id];
                        const count = techData?.count || 0;
                        const sev = techData?.severity || 'info';
                        return (
                          <div
                            key={tech.id}
                            className={`w-5 h-5 rounded-[3px] border cursor-pointer transition-all hover:scale-125 flex items-center justify-center ${
                              count > 0 ? severityHeatColor(sev, count) : 'bg-muted/10 border-border/50'
                            }`}
                            title={`${tech.name}: ${count} findings (${sev})`}
                            onClick={(e) => {
                              e.stopPropagation();
                              if (count > 0) setDrillDownTechnique({ tacticId: tactic.id, techniqueId: tech.id });
                            }}
                          >
                            {count > 0 && <span className="text-[8px] font-bold">{count}</span>}
                          </div>
                        );
                      })}
                    </div>

                    <div className="flex items-center gap-2 flex-shrink-0">
                      {tactic.totalFindings > 0 && (
                        <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                          {tactic.totalFindings}
                        </Badge>
                      )}
                    </div>
                  </div>

                  {/* Expanded Technique Detail */}
                  {isExpanded && (
                    <div className="ml-8 mr-2 mb-2 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-1.5">
                      {techniques.map(tech => {
                        const techData = tactic.techniques[tech.id];
                        const count = techData?.count || 0;
                        const sev = techData?.severity || 'info';
                        const isActive = count > 0;

                        return (
                          <div
                            key={tech.id}
                            className={`flex items-center gap-2 p-2 rounded-md border text-xs transition-all ${
                              isActive
                                ? `${severityHeatColor(sev, count)} cursor-pointer hover:brightness-110`
                                : 'bg-muted/5 border-border/30 opacity-50'
                            }`}
                            onClick={() => isActive && setDrillDownTechnique({ tacticId: tactic.id, techniqueId: tech.id })}
                          >
                            <code className="text-[10px] text-muted-foreground font-mono">{tech.id}</code>
                            <span className="flex-1 truncate">{tech.name}</span>
                            {isActive && (
                              <Badge className="text-[9px] px-1 py-0 bg-background/50 border">
                                {count}
                              </Badge>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Drill-Down Panel */}
      {drillDownTechnique && drillDownData && (
        <Card className="border-glow glass animate-fade-in">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-base flex items-center gap-2">
                  <Target className="w-4 h-4 text-primary" />
                  {drillDownTechnique.techniqueId} — {
                    MITRE_TECHNIQUES[drillDownTechnique.tacticId]?.find(t => t.id === drillDownTechnique.techniqueId)?.name
                  }
                </CardTitle>
                <CardDescription className="text-xs">
                  {drillDownData.count} finding(s) mapped • Max severity: {drillDownData.severity}
                </CardDescription>
              </div>
              <Button variant="ghost" size="icon" onClick={() => setDrillDownTechnique(null)}>
                <X className="w-4 h-4" />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {drillDownData.findings.map((finding, i) => (
                <div key={i} className="flex items-center justify-between p-2.5 rounded-lg border border-border bg-card/50">
                  <div className="flex items-center gap-2 min-w-0">
                    <Shield className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
                    <span className="text-sm truncate">{finding.title}</span>
                  </div>
                  <div className="flex items-center gap-1.5 flex-shrink-0">
                    <Badge className={`text-[9px] px-1.5 py-0 border ${
                      finding.severity === 'critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                      finding.severity === 'high' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                      finding.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                      'bg-blue-500/20 text-blue-400 border-blue-500/30'
                    }`}>
                      {finding.severity}
                    </Badge>
                    {finding.cvss_score !== undefined && finding.cvss_score > 0 && (
                      <Badge variant="outline" className="text-[9px] px-1.5 py-0">
                        CVSS {finding.cvss_score}
                      </Badge>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Kill Chain Coverage Bar */}
      <Card className="border-glow glass">
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Kill Chain Coverage</CardTitle>
          <CardDescription className="text-xs">Which stages of the attack lifecycle have detected activity</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-0.5 h-8">
            {tacticStats.map(tactic => {
              const widthPct = 100 / MITRE_TACTICS.length;
              const isActive = tactic.totalFindings > 0;
              return (
                <div
                  key={tactic.id}
                  className={`h-full rounded-sm flex items-center justify-center text-[8px] font-medium transition-all cursor-pointer ${
                    isActive
                      ? tactic.maxSeverity === 'critical'
                        ? 'bg-red-500/60 text-red-100'
                        : tactic.maxSeverity === 'high'
                        ? 'bg-orange-500/50 text-orange-100'
                        : tactic.maxSeverity === 'medium'
                        ? 'bg-yellow-500/40 text-yellow-100'
                        : 'bg-blue-500/30 text-blue-100'
                      : 'bg-muted/20 text-muted-foreground/50'
                  }`}
                  style={{ width: `${widthPct}%` }}
                  title={`${tactic.name}: ${tactic.totalFindings} findings`}
                  onClick={() => setExpandedTactic(expandedTactic === tactic.id ? null : tactic.id)}
                >
                  {tactic.shortName}
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
