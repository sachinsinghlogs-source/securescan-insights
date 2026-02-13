import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Shield, Users, ScanLine, AlertTriangle, TrendingUp, Clock, Activity, 
  FileText, ChevronLeft, RefreshCw, Loader2, Crown, Globe, Database,
  Bell, UserCog, Eye, Server, BarChart3
} from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/lib/auth';
import { useRBAC } from '@/hooks/useRBAC';
import { formatDistanceToNow, format } from 'date-fns';

interface SystemStats {
  totalScans: number;
  totalUsers: number;
  scansToday: number;
  highRiskScans: number;
  proUsers: number;
  totalAlerts: number;
  scheduledScans: number;
  criticalAlerts: number;
}

interface UserProfile {
  id: string;
  email: string;
  full_name: string | null;
  plan_type: string;
  daily_scans_used: number;
  created_at: string;
}

interface ScanRecord {
  id: string;
  target_url: string;
  risk_level: string | null;
  risk_score: number | null;
  status: string;
  created_at: string;
  user_id: string;
  completed_at: string | null;
}

interface AlertRecord {
  id: string;
  alert_type: string;
  severity: string;
  title: string;
  description: string | null;
  target_url: string | null;
  is_read: boolean;
  created_at: string;
  user_id: string;
}

interface AuditLogEntry {
  id: string;
  event_type: string;
  event_category: string;
  user_id: string | null;
  severity: string;
  details: Record<string, unknown>;
  created_at: string;
}

interface UserRole {
  id: string;
  user_id: string;
  role: string;
  granted_at: string;
}

export default function OwnerDashboard() {
  const { user, loading: authLoading } = useAuth();
  const { isOwner, isLoading: rbacLoading } = useRBAC();
  const navigate = useNavigate();

  const [stats, setStats] = useState<SystemStats | null>(null);
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [allScans, setAllScans] = useState<ScanRecord[]>([]);
  const [allAlerts, setAllAlerts] = useState<AlertRecord[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [userRoles, setUserRoles] = useState<UserRole[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    if (!authLoading && !user) { navigate('/auth'); return; }
    if (!rbacLoading && !isOwner) { navigate('/dashboard'); return; }
    if (!rbacLoading && isOwner) { fetchAllData(); }
  }, [user, authLoading, isOwner, rbacLoading, navigate]);

  const fetchAllData = async () => {
    try {
      const [scansRes, profilesRes, auditRes, alertsRes, rolesRes, scheduledRes] = await Promise.all([
        supabase.from('scans').select('*').order('created_at', { ascending: false }).limit(200),
        supabase.from('profiles').select('*').order('created_at', { ascending: false }),
        supabase.from('security_audit_log').select('*').order('created_at', { ascending: false }).limit(100),
        supabase.from('security_alerts').select('*').order('created_at', { ascending: false }).limit(100),
        supabase.from('user_roles').select('*'),
        supabase.from('scheduled_scans').select('*'),
      ]);

      const scans = scansRes.data || [];
      const profiles = profilesRes.data || [];
      const alerts = alertsRes.data || [];
      const scheduled = scheduledRes.data || [];

      const today = new Date().toISOString().split('T')[0];

      setStats({
        totalScans: scans.length,
        totalUsers: profiles.length,
        scansToday: scans.filter(s => s.created_at.startsWith(today)).length,
        highRiskScans: scans.filter(s => s.risk_level === 'high' || s.risk_level === 'critical').length,
        proUsers: profiles.filter(p => p.plan_type === 'pro').length,
        totalAlerts: alerts.length,
        scheduledScans: scheduled.length,
        criticalAlerts: alerts.filter(a => a.severity === 'critical').length,
      });

      setAllScans(scans as ScanRecord[]);
      setUsers(profiles as UserProfile[]);
      setAuditLogs((auditRes.data || []) as AuditLogEntry[]);
      setAllAlerts(alerts as AlertRecord[]);
      setUserRoles((rolesRes.data || []) as UserRole[]);
    } catch (error) {
      console.error('Error fetching owner data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    await fetchAllData();
    setRefreshing(false);
  };

  const getUserRole = (userId: string) => {
    const role = userRoles.find(r => r.user_id === userId);
    return role?.role || 'user';
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'critical': return <Badge className="bg-critical/20 text-critical border-critical/30">Critical</Badge>;
      case 'high': case 'error': return <Badge variant="destructive">High</Badge>;
      case 'medium': case 'warning': return <Badge className="bg-warning/20 text-warning border-warning/30">Medium</Badge>;
      default: return <Badge variant="secondary">Low</Badge>;
    }
  };

  const getRiskBadge = (risk: string | null) => {
    switch (risk) {
      case 'low': return <Badge className="bg-success/20 text-success border-success/30">Low</Badge>;
      case 'medium': return <Badge className="bg-warning/20 text-warning border-warning/30">Medium</Badge>;
      case 'high': return <Badge variant="destructive">High</Badge>;
      case 'critical': return <Badge className="bg-critical/20 text-critical border-critical/30">Critical</Badge>;
      default: return <Badge variant="outline">Pending</Badge>;
    }
  };

  const getRoleBadge = (role: string) => {
    switch (role) {
      case 'owner': return <Badge className="bg-primary/20 text-primary border-primary/30 gap-1"><Crown className="w-3 h-3" />Owner</Badge>;
      case 'admin': return <Badge variant="destructive" className="gap-1"><Shield className="w-3 h-3" />Admin</Badge>;
      case 'moderator': return <Badge className="bg-warning/20 text-warning border-warning/30">Moderator</Badge>;
      default: return <Badge variant="secondary">User</Badge>;
    }
  };

  if (authLoading || rbacLoading || loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center space-y-4">
          <Loader2 className="w-8 h-8 animate-spin mx-auto text-primary" />
          <p className="text-muted-foreground">Loading Owner Command Center...</p>
        </div>
      </div>
    );
  }

  if (!isOwner) return null;

  return (
    <div className="min-h-screen bg-background grid-pattern">
      {/* Header */}
      <header className="border-b border-primary/30 bg-card/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button variant="ghost" size="icon" onClick={() => navigate('/dashboard')}>
              <ChevronLeft className="w-5 h-5" />
            </Button>
            <div className="flex items-center gap-2">
              <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center">
                <Crown className="w-5 h-5 text-primary" />
              </div>
              <div>
                <span className="font-bold text-lg text-gradient-primary">Owner Command Center</span>
                <p className="text-xs text-muted-foreground">Full system visibility & control</p>
              </div>
            </div>
          </div>
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing} className="border-primary/30">
            <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        {/* Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          {[
            { icon: Users, label: 'Total Users', value: stats?.totalUsers || 0, color: 'text-primary' },
            { icon: ScanLine, label: 'Total Scans', value: stats?.totalScans || 0, color: 'text-success' },
            { icon: TrendingUp, label: 'Scans Today', value: stats?.scansToday || 0, color: 'text-primary' },
            { icon: AlertTriangle, label: 'High Risk', value: stats?.highRiskScans || 0, color: 'text-critical' },
            { icon: Bell, label: 'Total Alerts', value: stats?.totalAlerts || 0, color: 'text-warning' },
            { icon: Activity, label: 'Critical Alerts', value: stats?.criticalAlerts || 0, color: 'text-critical' },
            { icon: Globe, label: 'Scheduled Scans', value: stats?.scheduledScans || 0, color: 'text-primary' },
            { icon: Crown, label: 'Pro Users', value: stats?.proUsers || 0, color: 'text-warning' },
          ].map(({ icon: Icon, label, value, color }, i) => (
            <Card key={i} className="border-glow glass">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-muted">
                    <Icon className={`w-5 h-5 ${color}`} />
                  </div>
                  <div>
                    <p className="text-2xl font-bold">{value}</p>
                    <p className="text-xs text-muted-foreground">{label}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Tabs */}
        <Tabs defaultValue="users" className="space-y-4">
          <TabsList className="grid w-full grid-cols-4 lg:w-auto lg:inline-grid">
            <TabsTrigger value="users" className="gap-2"><UserCog className="w-4 h-4 hidden sm:block" />Users</TabsTrigger>
            <TabsTrigger value="scans" className="gap-2"><ScanLine className="w-4 h-4 hidden sm:block" />All Scans</TabsTrigger>
            <TabsTrigger value="alerts" className="gap-2"><Bell className="w-4 h-4 hidden sm:block" />All Alerts</TabsTrigger>
            <TabsTrigger value="audit" className="gap-2"><FileText className="w-4 h-4 hidden sm:block" />Audit Log</TabsTrigger>
          </TabsList>

          {/* Users Tab */}
          <TabsContent value="users">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Users className="w-5 h-5 text-primary" />
                  All Users ({users.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-[600px] overflow-y-auto">
                  {users.map((u) => (
                    <div key={u.id} className="flex items-center justify-between p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-medium text-sm">{u.full_name || 'No name'}</span>
                          {getRoleBadge(getUserRole(u.id))}
                          <Badge variant="outline" className="text-xs capitalize">{u.plan_type}</Badge>
                        </div>
                        <p className="text-xs text-muted-foreground font-mono">{u.email}</p>
                        <p className="text-xs text-muted-foreground">
                          Joined {formatDistanceToNow(new Date(u.created_at), { addSuffix: true })} · {u.daily_scans_used} scans today
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* All Scans Tab */}
          <TabsContent value="scans">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <ScanLine className="w-5 h-5 text-primary" />
                  All Scans ({allScans.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-[600px] overflow-y-auto">
                  {allScans.map((scan) => (
                    <div key={scan.id} className="flex items-center justify-between p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors">
                      <div className="min-w-0 flex-1">
                        <p className="font-mono text-sm truncate max-w-[400px]">{scan.target_url}</p>
                        <div className="flex items-center gap-2 text-xs text-muted-foreground">
                          <Clock className="w-3 h-3" />
                          {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                          <span>·</span>
                          <span className="font-mono text-[10px]">{scan.user_id.slice(0, 8)}...</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {getRiskBadge(scan.risk_level)}
                        {scan.risk_score !== null && (
                          <span className="text-xs font-mono text-muted-foreground">Score: {scan.risk_score}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* All Alerts Tab */}
          <TabsContent value="alerts">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Bell className="w-5 h-5 text-warning" />
                  All System Alerts ({allAlerts.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-[600px] overflow-y-auto">
                  {allAlerts.map((alert) => (
                    <div key={alert.id} className="p-3 rounded-lg bg-muted/30 space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        {getSeverityBadge(alert.severity)}
                        <span className="font-medium text-sm">{alert.title}</span>
                        <Badge variant="outline" className="text-xs">{alert.alert_type}</Badge>
                      </div>
                      {alert.description && <p className="text-xs text-muted-foreground">{alert.description}</p>}
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <Clock className="w-3 h-3" />
                        {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
                        {alert.target_url && <><span>·</span><span className="font-mono">{alert.target_url}</span></>}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Audit Log Tab */}
          <TabsContent value="audit">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <FileText className="w-5 h-5 text-primary" />
                  Security Audit Log
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-[600px] overflow-y-auto">
                  {auditLogs.map((log) => (
                    <div key={log.id} className="p-3 rounded-lg bg-muted/30 space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        {getSeverityBadge(log.severity)}
                        <span className="font-medium text-sm">{log.event_type}</span>
                        <Badge variant="outline" className="text-xs">{log.event_category}</Badge>
                      </div>
                      <div className="text-xs text-muted-foreground flex items-center gap-2">
                        <Clock className="w-3 h-3" />
                        {formatDistanceToNow(new Date(log.created_at), { addSuffix: true })}
                      </div>
                      {log.details && Object.keys(log.details).length > 0 && (
                        <pre className="text-xs text-muted-foreground bg-background/50 p-2 rounded mt-1 overflow-x-auto">
                          {JSON.stringify(log.details, null, 2)}
                        </pre>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}
