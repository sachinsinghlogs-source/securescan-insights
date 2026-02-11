import { useState, useMemo } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import {
  Bell, BellOff, AlertTriangle, ShieldAlert, TrendingDown, TrendingUp,
  Settings, Check, X, ChevronDown, ChevronUp, Globe, Shield, Zap,
  Filter
} from 'lucide-react';
import { toast } from 'sonner';

interface SecurityAlert {
  id: string;
  alert_type: string;
  severity: string;
  title: string;
  description: string | null;
  previous_value: string | null;
  current_value: string | null;
  is_read: boolean;
  is_dismissed: boolean;
  created_at: string;
  target_url?: string | null;
}

interface AlertsPanelProps {
  alerts: SecurityAlert[];
  onAlertUpdated: () => void;
}

const IMPROVEMENT_TYPES = ['risk_decreased', 'ssl_restored', 'headers_improved'];

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';
type TypeFilter = 'all' | 'regressions' | 'improvements';

export default function AlertsPanel({ alerts, onAlertUpdated }: AlertsPanelProps) {
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all');
  const [expandedDomains, setExpandedDomains] = useState<Set<string>>(new Set());

  const filteredAlerts = useMemo(() => {
    let result = alerts.filter(a => !a.is_dismissed);
    if (severityFilter !== 'all') {
      result = result.filter(a => a.severity === severityFilter);
    }
    if (typeFilter === 'regressions') {
      result = result.filter(a => !IMPROVEMENT_TYPES.includes(a.alert_type));
    } else if (typeFilter === 'improvements') {
      result = result.filter(a => IMPROVEMENT_TYPES.includes(a.alert_type));
    }
    return result;
  }, [alerts, severityFilter, typeFilter]);

  // Group by domain
  const groupedByDomain = useMemo(() => {
    const groups = new Map<string, SecurityAlert[]>();
    for (const alert of filteredAlerts) {
      const domain = alert.target_url || 'Unknown';
      const existing = groups.get(domain) || [];
      existing.push(alert);
      groups.set(domain, existing);
    }
    // Sort domains by most recent alert
    return [...groups.entries()].sort((a, b) => {
      const aLatest = Math.max(...a[1].map(al => new Date(al.created_at).getTime()));
      const bLatest = Math.max(...b[1].map(al => new Date(al.created_at).getTime()));
      return bLatest - aLatest;
    });
  }, [filteredAlerts]);

  // Auto-expand first domain
  useMemo(() => {
    if (groupedByDomain.length > 0 && expandedDomains.size === 0) {
      setExpandedDomains(new Set([groupedByDomain[0][0]]));
    }
  }, [groupedByDomain.length]);

  const toggleDomain = (domain: string) => {
    setExpandedDomains(prev => {
      const next = new Set(prev);
      if (next.has(domain)) next.delete(domain);
      else next.add(domain);
      return next;
    });
  };

  const markAsRead = async (alertId: string) => {
    setUpdatingId(alertId);
    const { error } = await supabase
      .from('security_alerts')
      .update({ is_read: true })
      .eq('id', alertId);
    if (error) toast.error('Failed to update alert');
    else onAlertUpdated();
    setUpdatingId(null);
  };

  const dismissAlert = async (alertId: string) => {
    setUpdatingId(alertId);
    const { error } = await supabase
      .from('security_alerts')
      .update({ is_dismissed: true })
      .eq('id', alertId);
    if (error) toast.error('Failed to dismiss alert');
    else { toast.success('Alert dismissed'); onAlertUpdated(); }
    setUpdatingId(null);
  };

  const markAllAsRead = async () => {
    const unreadIds = filteredAlerts.filter(a => !a.is_read).map(a => a.id);
    if (unreadIds.length === 0) return;
    const { error } = await supabase
      .from('security_alerts')
      .update({ is_read: true })
      .in('id', unreadIds);
    if (error) toast.error('Failed to update alerts');
    else { toast.success('All alerts marked as read'); onAlertUpdated(); }
  };

  const isImprovement = (alertType: string) => IMPROVEMENT_TYPES.includes(alertType);

  const getSeverityStyle = (severity: string, alertType: string) => {
    if (isImprovement(alertType)) return 'bg-green-500/20 text-green-400 border-green-500/30';
    switch (severity) {
      case 'critical': return 'bg-critical/20 text-critical border-critical/30';
      case 'high': return 'bg-critical/15 text-critical border-critical/20';
      case 'medium': return 'bg-warning/20 text-warning border-warning/30';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getAlertIcon = (alertType: string) => {
    switch (alertType) {
      case 'risk_increased': return <TrendingUp className="w-4 h-4" />;
      case 'risk_decreased': return <TrendingDown className="w-4 h-4" />;
      case 'ssl_invalid':
      case 'ssl_expiring': return <ShieldAlert className="w-4 h-4" />;
      case 'ssl_restored': return <Shield className="w-4 h-4" />;
      case 'config_drift': return <Settings className="w-4 h-4" />;
      case 'headers_improved': return <Shield className="w-4 h-4" />;
      case 'new_technology': return <Zap className="w-4 h-4" />;
      default: return <AlertTriangle className="w-4 h-4" />;
    }
  };

  const formatTime = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  const getWeekAlertCount = (domain: string) => {
    const weekAgo = Date.now() - 7 * 86400000;
    return alerts.filter(a => (a.target_url || 'Unknown') === domain && new Date(a.created_at).getTime() > weekAgo).length;
  };

  const unreadCount = filteredAlerts.filter(a => !a.is_read).length;

  const AlertItem = ({ alert }: { alert: SecurityAlert }) => (
    <div
      className={`p-3 rounded-lg border transition-all ${
        isImprovement(alert.alert_type)
          ? 'bg-green-500/5 border-green-500/20'
          : alert.is_read
            ? 'bg-muted/30 border-border/50'
            : 'bg-card border-primary/30 shadow-sm'
      }`}
    >
      <div className="flex items-start gap-3">
        <div className={`p-2 rounded-lg ${getSeverityStyle(alert.severity, alert.alert_type)}`}>
          {getAlertIcon(alert.alert_type)}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h4 className="font-medium text-sm truncate">{alert.title}</h4>
            <Badge variant="outline" className={`text-xs ${getSeverityStyle(alert.severity, alert.alert_type)}`}>
              {isImprovement(alert.alert_type) ? 'improvement' : alert.severity}
            </Badge>
          </div>
          {alert.description && (
            <p className="text-xs text-muted-foreground mb-2 line-clamp-2">{alert.description}</p>
          )}
          {(alert.previous_value || alert.current_value) && (
            <div className="flex items-center gap-2 text-xs">
              {alert.previous_value && <span className="text-muted-foreground">{alert.previous_value}</span>}
              {alert.previous_value && alert.current_value && <span className="text-muted-foreground">→</span>}
              {alert.current_value && (
                <span className={`font-medium ${isImprovement(alert.alert_type) ? 'text-green-400' : 'text-foreground'}`}>
                  {alert.current_value}
                </span>
              )}
            </div>
          )}
          <div className="flex items-center justify-between mt-2">
            <span className="text-xs text-muted-foreground">{formatTime(alert.created_at)}</span>
            <div className="flex gap-1">
              {!alert.is_read && (
                <Button variant="ghost" size="sm" className="h-6 px-2 text-xs"
                  onClick={() => markAsRead(alert.id)} disabled={updatingId === alert.id}>
                  <Check className="w-3 h-3 mr-1" />Read
                </Button>
              )}
              <Button variant="ghost" size="sm" className="h-6 px-2 text-xs text-muted-foreground"
                onClick={() => dismissAlert(alert.id)} disabled={updatingId === alert.id}>
                <X className="w-3 h-3" />
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <Card className="border-glow glass">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg flex items-center gap-2">
            <Bell className="w-5 h-5 text-primary" />
            Security Alerts
            {unreadCount > 0 && (
              <Badge className="bg-critical text-critical-foreground">{unreadCount}</Badge>
            )}
          </CardTitle>
          {unreadCount > 0 && (
            <Button variant="ghost" size="sm" onClick={markAllAsRead} className="text-xs">
              Mark all read
            </Button>
          )}
        </div>

        {/* Filters */}
        <div className="flex items-center gap-2 mt-2">
          <Filter className="w-3.5 h-3.5 text-muted-foreground" />
          <Select value={severityFilter} onValueChange={(v) => setSeverityFilter(v as SeverityFilter)}>
            <SelectTrigger className="h-7 text-xs w-[110px]">
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all" className="text-xs">All severities</SelectItem>
              <SelectItem value="critical" className="text-xs">Critical</SelectItem>
              <SelectItem value="high" className="text-xs">High</SelectItem>
              <SelectItem value="medium" className="text-xs">Medium</SelectItem>
              <SelectItem value="low" className="text-xs">Low</SelectItem>
            </SelectContent>
          </Select>
          <Select value={typeFilter} onValueChange={(v) => setTypeFilter(v as TypeFilter)}>
            <SelectTrigger className="h-7 text-xs w-[120px]">
              <SelectValue placeholder="Type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all" className="text-xs">All types</SelectItem>
              <SelectItem value="regressions" className="text-xs">Regressions</SelectItem>
              <SelectItem value="improvements" className="text-xs">Improvements</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </CardHeader>

      <CardContent>
        {filteredAlerts.length === 0 ? (
          <div className="text-center py-8">
            <BellOff className="w-10 h-10 mx-auto text-muted-foreground/50 mb-3" />
            <p className="text-muted-foreground text-sm">No security alerts</p>
            <p className="text-xs text-muted-foreground/70 mt-1">
              Alerts appear when security changes are detected
            </p>
          </div>
        ) : (
          <ScrollArea className="h-[400px] pr-4">
            <div className="space-y-3">
              {groupedByDomain.map(([domain, domainAlerts]) => {
                const isExpanded = expandedDomains.has(domain);
                const domainUnread = domainAlerts.filter(a => !a.is_read).length;
                const weekCount = getWeekAlertCount(domain);

                return (
                  <Collapsible key={domain} open={isExpanded} onOpenChange={() => toggleDomain(domain)}>
                    <CollapsibleTrigger asChild>
                      <Button
                        variant="ghost"
                        className="w-full flex items-center justify-between p-2 h-auto rounded-lg hover:bg-muted/30"
                      >
                        <div className="flex items-center gap-2">
                          <Globe className="w-4 h-4 text-muted-foreground" />
                          <span className="text-sm font-medium truncate max-w-[200px]">{domain}</span>
                          {domainUnread > 0 && (
                            <Badge className="bg-critical/80 text-critical-foreground text-xs h-5">
                              {domainUnread}
                            </Badge>
                          )}
                          <span className="text-xs text-muted-foreground">
                            {weekCount} this week
                          </span>
                        </div>
                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </Button>
                    </CollapsibleTrigger>
                    <CollapsibleContent className="space-y-2 mt-1">
                      {domainAlerts.map(alert => (
                        <AlertItem key={alert.id} alert={alert} />
                      ))}
                    </CollapsibleContent>
                  </Collapsible>
                );
              })}
            </div>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
}
