import { useState } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  Bell, 
  BellOff, 
  AlertTriangle, 
  ShieldAlert, 
  TrendingDown,
  Settings,
  Check,
  X
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
}

interface AlertsPanelProps {
  alerts: SecurityAlert[];
  onAlertUpdated: () => void;
}

export default function AlertsPanel({ alerts, onAlertUpdated }: AlertsPanelProps) {
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  const unreadAlerts = alerts.filter(a => !a.is_read && !a.is_dismissed);
  const readAlerts = alerts.filter(a => a.is_read && !a.is_dismissed);

  const markAsRead = async (alertId: string) => {
    setUpdatingId(alertId);
    const { error } = await supabase
      .from('security_alerts')
      .update({ is_read: true })
      .eq('id', alertId);

    if (error) {
      toast.error('Failed to update alert');
    } else {
      onAlertUpdated();
    }
    setUpdatingId(null);
  };

  const dismissAlert = async (alertId: string) => {
    setUpdatingId(alertId);
    const { error } = await supabase
      .from('security_alerts')
      .update({ is_dismissed: true })
      .eq('id', alertId);

    if (error) {
      toast.error('Failed to dismiss alert');
    } else {
      toast.success('Alert dismissed');
      onAlertUpdated();
    }
    setUpdatingId(null);
  };

  const markAllAsRead = async () => {
    const unreadIds = unreadAlerts.map(a => a.id);
    if (unreadIds.length === 0) return;

    const { error } = await supabase
      .from('security_alerts')
      .update({ is_read: true })
      .in('id', unreadIds);

    if (error) {
      toast.error('Failed to update alerts');
    } else {
      toast.success('All alerts marked as read');
      onAlertUpdated();
    }
  };

  const getSeverityStyle = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-critical/20 text-critical border-critical/30';
      case 'high':
        return 'bg-critical/15 text-critical border-critical/20';
      case 'medium':
        return 'bg-warning/20 text-warning border-warning/30';
      default:
        return 'bg-muted text-muted-foreground';
    }
  };

  const getAlertIcon = (alertType: string) => {
    switch (alertType) {
      case 'risk_increased':
        return <TrendingDown className="w-4 h-4" />;
      case 'ssl_invalid':
      case 'ssl_expiring':
        return <ShieldAlert className="w-4 h-4" />;
      case 'config_drift':
        return <Settings className="w-4 h-4" />;
      default:
        return <AlertTriangle className="w-4 h-4" />;
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

  const AlertItem = ({ alert }: { alert: SecurityAlert }) => (
    <div 
      className={`p-3 rounded-lg border transition-all ${
        alert.is_read 
          ? 'bg-muted/30 border-border/50' 
          : 'bg-card border-primary/30 shadow-sm'
      }`}
    >
      <div className="flex items-start gap-3">
        <div className={`p-2 rounded-lg ${getSeverityStyle(alert.severity)}`}>
          {getAlertIcon(alert.alert_type)}
        </div>
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h4 className="font-medium text-sm truncate">{alert.title}</h4>
            <Badge variant="outline" className={`text-xs ${getSeverityStyle(alert.severity)}`}>
              {alert.severity}
            </Badge>
          </div>
          
          {alert.description && (
            <p className="text-xs text-muted-foreground mb-2 line-clamp-2">
              {alert.description}
            </p>
          )}
          
          {(alert.previous_value || alert.current_value) && (
            <div className="flex items-center gap-2 text-xs">
              {alert.previous_value && (
                <span className="text-muted-foreground">
                  {alert.previous_value}
                </span>
              )}
              {alert.previous_value && alert.current_value && (
                <span className="text-muted-foreground">→</span>
              )}
              {alert.current_value && (
                <span className="text-foreground font-medium">
                  {alert.current_value}
                </span>
              )}
            </div>
          )}
          
          <div className="flex items-center justify-between mt-2">
            <span className="text-xs text-muted-foreground">
              {formatTime(alert.created_at)}
            </span>
            
            <div className="flex gap-1">
              {!alert.is_read && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 px-2 text-xs"
                  onClick={() => markAsRead(alert.id)}
                  disabled={updatingId === alert.id}
                >
                  <Check className="w-3 h-3 mr-1" />
                  Read
                </Button>
              )}
              <Button
                variant="ghost"
                size="sm"
                className="h-6 px-2 text-xs text-muted-foreground"
                onClick={() => dismissAlert(alert.id)}
                disabled={updatingId === alert.id}
              >
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
            {unreadAlerts.length > 0 && (
              <Badge className="bg-critical text-critical-foreground">
                {unreadAlerts.length}
              </Badge>
            )}
          </CardTitle>
          
          {unreadAlerts.length > 0 && (
            <Button
              variant="ghost"
              size="sm"
              onClick={markAllAsRead}
              className="text-xs"
            >
              Mark all read
            </Button>
          )}
        </div>
      </CardHeader>
      
      <CardContent>
        {alerts.length === 0 ? (
          <div className="text-center py-8">
            <BellOff className="w-10 h-10 mx-auto text-muted-foreground/50 mb-3" />
            <p className="text-muted-foreground text-sm">
              No security alerts
            </p>
            <p className="text-xs text-muted-foreground/70 mt-1">
              Alerts appear when security changes are detected
            </p>
          </div>
        ) : (
          <ScrollArea className="h-[400px] pr-4">
            <div className="space-y-3">
              {unreadAlerts.length > 0 && (
                <>
                  <h5 className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    New
                  </h5>
                  {unreadAlerts.map(alert => (
                    <AlertItem key={alert.id} alert={alert} />
                  ))}
                </>
              )}
              
              {readAlerts.length > 0 && (
                <>
                  <h5 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mt-4">
                    Earlier
                  </h5>
                  {readAlerts.slice(0, 10).map(alert => (
                    <AlertItem key={alert.id} alert={alert} />
                  ))}
                </>
              )}
            </div>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
}
