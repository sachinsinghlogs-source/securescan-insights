import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Shield, 
  Users, 
  ScanLine, 
  AlertTriangle,
  TrendingUp,
  Clock,
  Activity,
  FileText,
  ChevronLeft,
  RefreshCw,
  Loader2
} from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/lib/auth';
import { useRBAC } from '@/hooks/useRBAC';
import { formatDistanceToNow } from 'date-fns';

interface AdminStats {
  totalScans: number;
  totalUsers: number;
  scansToday: number;
  highRiskScans: number;
  proUsers: number;
}

interface AuditLogEntry {
  id: string;
  event_type: string;
  event_category: string;
  user_id: string | null;
  ip_address: string | null;
  severity: string;
  details: Record<string, unknown>;
  created_at: string;
}

interface RecentScan {
  id: string;
  target_url: string;
  risk_level: string | null;
  status: string;
  created_at: string;
  user_id: string;
}

export default function Admin() {
  const { user, loading: authLoading } = useAuth();
  const { isAdmin, isLoading: rbacLoading } = useRBAC();
  const navigate = useNavigate();
  
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    if (!authLoading && !user) {
      navigate('/auth');
      return;
    }

    if (!rbacLoading && !isAdmin) {
      navigate('/dashboard');
      return;
    }

    if (!rbacLoading && isAdmin) {
      fetchAdminData();
    }
  }, [user, authLoading, isAdmin, rbacLoading, navigate]);

  const fetchAdminData = async () => {
    try {
      // Fetch all stats in parallel
      const [scansResult, profilesResult, auditResult] = await Promise.all([
        supabase.from('scans').select('id, risk_level, status, target_url, created_at, user_id'),
        supabase.from('profiles').select('id, plan_type'),
        supabase.from('security_audit_log').select('*').order('created_at', { ascending: false }).limit(50),
      ]);

      const scans = scansResult.data || [];
      const profiles = profilesResult.data || [];
      const logs = auditResult.data || [];

      const today = new Date().toISOString().split('T')[0];
      const scansToday = scans.filter(s => s.created_at.startsWith(today)).length;
      const highRiskScans = scans.filter(s => s.risk_level === 'high' || s.risk_level === 'critical').length;
      const proUsers = profiles.filter(p => p.plan_type === 'pro').length;

      setStats({
        totalScans: scans.length,
        totalUsers: profiles.length,
        scansToday,
        highRiskScans,
        proUsers,
      });

      setRecentScans(scans.slice(0, 10) as RecentScan[]);
      setAuditLogs(logs as AuditLogEntry[]);
    } catch (error) {
      console.error('Error fetching admin data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    await fetchAdminData();
    setRefreshing(false);
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'error':
        return <Badge variant="destructive">Error</Badge>;
      case 'warning':
        return <Badge className="bg-warning text-warning-foreground">Warning</Badge>;
      default:
        return <Badge variant="secondary">Info</Badge>;
    }
  };

  const getRiskBadge = (risk: string | null) => {
    switch (risk) {
      case 'low':
        return <Badge className="bg-success text-success-foreground">Low</Badge>;
      case 'medium':
        return <Badge className="bg-warning text-warning-foreground">Medium</Badge>;
      case 'high':
        return <Badge variant="destructive">High</Badge>;
      case 'critical':
        return <Badge className="bg-critical text-critical-foreground">Critical</Badge>;
      default:
        return <Badge variant="outline">Pending</Badge>;
    }
  };

  if (authLoading || rbacLoading || loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center space-y-4">
          <Loader2 className="w-8 h-8 animate-spin mx-auto text-primary" />
          <p className="text-muted-foreground">Loading admin panel...</p>
        </div>
      </div>
    );
  }

  if (!isAdmin) {
    return null;
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border/50 bg-card/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button variant="ghost" size="icon" onClick={() => navigate('/dashboard')}>
              <ChevronLeft className="w-5 h-5" />
            </Button>
            <div className="flex items-center gap-2">
              <Shield className="w-6 h-6 text-primary" />
              <span className="font-bold text-lg">Admin Panel</span>
            </div>
          </div>
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        {/* Stats Overview */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-primary/10">
                  <ScanLine className="w-5 h-5 text-primary" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{stats?.totalScans || 0}</p>
                  <p className="text-xs text-muted-foreground">Total Scans</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-success/10">
                  <Users className="w-5 h-5 text-success" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{stats?.totalUsers || 0}</p>
                  <p className="text-xs text-muted-foreground">Total Users</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-primary/10">
                  <TrendingUp className="w-5 h-5 text-primary" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{stats?.scansToday || 0}</p>
                  <p className="text-xs text-muted-foreground">Today</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-warning/10">
                  <AlertTriangle className="w-5 h-5 text-warning" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{stats?.highRiskScans || 0}</p>
                  <p className="text-xs text-muted-foreground">High Risk</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-primary/10">
                  <Activity className="w-5 h-5 text-primary" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{stats?.proUsers || 0}</p>
                  <p className="text-xs text-muted-foreground">Pro Users</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Tabs for different admin views */}
        <Tabs defaultValue="scans" className="space-y-4">
          <TabsList>
            <TabsTrigger value="scans" className="gap-2">
              <ScanLine className="w-4 h-4" />
              Recent Scans
            </TabsTrigger>
            <TabsTrigger value="audit" className="gap-2">
              <FileText className="w-4 h-4" />
              Audit Logs
            </TabsTrigger>
          </TabsList>

          <TabsContent value="scans">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Recent Scans</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {recentScans.length === 0 ? (
                    <p className="text-center text-muted-foreground py-8">No scans yet</p>
                  ) : (
                    recentScans.map((scan) => (
                      <div
                        key={scan.id}
                        className="flex items-center justify-between p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors"
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          <div className="min-w-0">
                            <p className="font-mono text-sm truncate max-w-[300px]">
                              {scan.target_url}
                            </p>
                            <div className="flex items-center gap-2 text-xs text-muted-foreground">
                              <Clock className="w-3 h-3" />
                              {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          {getRiskBadge(scan.risk_level)}
                          <Badge variant="outline" className="capitalize">
                            {scan.status}
                          </Badge>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="audit">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Security Audit Logs</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-[600px] overflow-y-auto">
                  {auditLogs.length === 0 ? (
                    <p className="text-center text-muted-foreground py-8">No audit logs yet</p>
                  ) : (
                    auditLogs.map((log) => (
                      <div
                        key={log.id}
                        className="flex items-start justify-between p-3 rounded-lg bg-muted/30 gap-4"
                      >
                        <div className="space-y-1 min-w-0 flex-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            {getSeverityBadge(log.severity)}
                            <span className="font-medium text-sm">{log.event_type}</span>
                            <Badge variant="outline" className="text-xs">
                              {log.event_category}
                            </Badge>
                          </div>
                          <div className="text-xs text-muted-foreground flex items-center gap-2">
                            <Clock className="w-3 h-3" />
                            {formatDistanceToNow(new Date(log.created_at), { addSuffix: true })}
                            {log.ip_address && (
                              <>
                                <span>•</span>
                                <span className="font-mono">{log.ip_address}</span>
                              </>
                            )}
                          </div>
                          {log.details && Object.keys(log.details).length > 0 && (
                            <pre className="text-xs text-muted-foreground bg-background/50 p-2 rounded mt-2 overflow-x-auto">
                              {JSON.stringify(log.details, null, 2)}
                            </pre>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}
