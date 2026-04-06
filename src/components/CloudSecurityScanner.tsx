import { useState } from 'react';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Cloud, Server, Database, Globe, Shield, Loader2, AlertTriangle, CheckCircle, XCircle, Info, Trash2 } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface Finding {
  id: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  recommendation: string;
}

interface CloudScan {
  id: string;
  scan_type: string;
  target_url: string;
  status: string;
  risk_level: string | null;
  risk_score: number | null;
  findings: Finding[];
  summary: Record<string, number>;
  scan_duration_ms: number | null;
  created_at: string;
}

const scanTypes = [
  { id: 'deployment', label: 'Deployment', icon: Globe, description: 'Check HTTPS, headers, cookies, CSP' },
  { id: 'api', label: 'API Security', icon: Shield, description: 'Test auth, CORS, rate limiting, XSS' },
  { id: 'storage', label: 'Storage Audit', icon: Database, description: 'Check public access, listing, encryption' },
  { id: 'infrastructure', label: 'Infrastructure', icon: Server, description: 'Scan cloud provider, TLS, admin panels' },
];

const severityConfig = {
  critical: { color: 'bg-critical/20 text-critical border-critical/30', icon: XCircle },
  high: { color: 'bg-destructive/20 text-destructive border-destructive/30', icon: AlertTriangle },
  medium: { color: 'bg-warning/20 text-warning border-warning/30', icon: AlertTriangle },
  low: { color: 'bg-primary/20 text-primary border-primary/30', icon: Info },
  info: { color: 'bg-muted text-muted-foreground border-border', icon: CheckCircle },
};

const riskColors: Record<string, string> = {
  critical: 'text-critical',
  high: 'text-destructive',
  medium: 'text-warning',
  low: 'text-success',
};

interface CloudSecurityScannerProps {
  scans: CloudScan[];
  onScanComplete: () => void;
}

export default function CloudSecurityScanner({ scans, onScanComplete }: CloudSecurityScannerProps) {
  const { user } = useAuth();
  const { toast } = useToast();
  const [url, setUrl] = useState('');
  const [selectedType, setSelectedType] = useState('deployment');
  const [isScanning, setIsScanning] = useState(false);
  const [latestResult, setLatestResult] = useState<{
    findings: Finding[];
    summary: Record<string, number>;
    risk_level: string;
    risk_score: number;
    scan_duration_ms: number;
  } | null>(null);

  const handleScan = async () => {
    if (!url.trim() || !user) return;
    setIsScanning(true);
    setLatestResult(null);

    try {
      const normalizedUrl = url.startsWith('http') ? url : `https://${url}`;
      const { data, error } = await supabase.functions.invoke('cloud-security-scan', {
        body: { url: normalizedUrl, scan_type: selectedType },
      });

      if (error) throw new Error(error.message);
      if (data?.error) throw new Error(data.error);

      setLatestResult(data);
      toast({ title: 'Cloud Scan Complete', description: `Found ${data.findings.length} findings.` });
      onScanComplete();
    } catch (err) {
      toast({ title: 'Scan Failed', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
    } finally {
      setIsScanning(false);
    }
  };

  const handleDelete = async (scanId: string) => {
    await supabase.from('cloud_scans').delete().eq('id', scanId);
    onScanComplete();
  };

  return (
    <div className="space-y-6">
      {/* Scanner Form */}
      <Card className="border-glow glass">
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center">
              <Cloud className="w-5 h-5 text-primary" />
            </div>
            <div>
              <CardTitle>Cloud Security Scanner</CardTitle>
              <CardDescription>Scan cloud deployments, APIs, storage, and infrastructure</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Scan Type Selection */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {scanTypes.map((type) => {
              const Icon = type.icon;
              return (
                <button
                  key={type.id}
                  onClick={() => setSelectedType(type.id)}
                  className={`p-3 rounded-lg border text-left transition-all ${
                    selectedType === type.id
                      ? 'border-primary bg-primary/10 ring-1 ring-primary/30'
                      : 'border-border bg-card hover:border-primary/40'
                  }`}
                >
                  <Icon className={`w-4 h-4 mb-1.5 ${selectedType === type.id ? 'text-primary' : 'text-muted-foreground'}`} />
                  <p className="text-xs font-medium">{type.label}</p>
                  <p className="text-[10px] text-muted-foreground leading-tight mt-0.5 hidden sm:block">{type.description}</p>
                </button>
              );
            })}
          </div>

          {/* URL Input */}
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Enter URL to scan (e.g., api.example.com)"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="pl-10 bg-background/50 font-mono text-sm"
                disabled={isScanning}
                onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              />
            </div>
            <Button onClick={handleScan} disabled={isScanning || !url.trim()} className="btn-glow bg-primary text-primary-foreground">
              {isScanning ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Scanning...</> : 'Scan'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Latest Result */}
      {latestResult && (
        <Card className="border-glow glass">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg">Scan Results</CardTitle>
              <div className="flex items-center gap-3">
                <Badge className={`${riskColors[latestResult.risk_level]} border bg-opacity-20`}>
                  Risk: {latestResult.risk_level.toUpperCase()} ({latestResult.risk_score}/100)
                </Badge>
                <span className="text-xs text-muted-foreground">{latestResult.scan_duration_ms}ms</span>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {/* Summary badges */}
            <div className="flex flex-wrap gap-2">
              {latestResult.summary.critical > 0 && <Badge variant="destructive">{latestResult.summary.critical} Critical</Badge>}
              {latestResult.summary.high > 0 && <Badge className="bg-destructive/20 text-destructive border-destructive/30">{latestResult.summary.high} High</Badge>}
              {latestResult.summary.medium > 0 && <Badge className="bg-warning/20 text-warning border-warning/30">{latestResult.summary.medium} Medium</Badge>}
              {latestResult.summary.low > 0 && <Badge className="bg-primary/20 text-primary border-primary/30">{latestResult.summary.low} Low</Badge>}
              {latestResult.summary.info > 0 && <Badge variant="secondary">{latestResult.summary.info} Info</Badge>}
            </div>

            {/* Findings */}
            <div className="space-y-2">
              {latestResult.findings.map((finding) => {
                const config = severityConfig[finding.severity];
                const SevIcon = config.icon;
                return (
                  <div key={finding.id} className={`p-3 rounded-lg border ${config.color}`}>
                    <div className="flex items-start gap-2">
                      <SevIcon className="w-4 h-4 flex-shrink-0 mt-0.5" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-medium text-sm">{finding.title}</span>
                          <Badge variant="outline" className="text-[10px] px-1.5 py-0">{finding.category}</Badge>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">{finding.description}</p>
                        <p className="text-xs mt-1.5"><strong>Fix:</strong> {finding.recommendation}</p>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Scan History */}
      {scans.length > 0 && (
        <Card className="glass">
          <CardHeader>
            <CardTitle className="text-lg">Cloud Scan History</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {scans.map((scan) => (
                <div key={scan.id} className="flex items-center justify-between p-3 rounded-lg border border-border bg-card/50">
                  <div className="flex items-center gap-3 min-w-0 flex-1">
                    <Badge variant="outline" className="text-xs capitalize flex-shrink-0">{scan.scan_type}</Badge>
                    <span className="text-sm font-mono truncate">{new URL(scan.target_url).hostname}</span>
                    {scan.risk_level && (
                      <Badge className={`text-xs ${riskColors[scan.risk_level]} bg-opacity-20 border flex-shrink-0`}>
                        {scan.risk_level.toUpperCase()}
                      </Badge>
                    )}
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className="text-xs text-muted-foreground">{new Date(scan.created_at).toLocaleDateString()}</span>
                    <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => handleDelete(scan.id)}>
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
