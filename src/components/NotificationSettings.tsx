import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/lib/auth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Mail, Bell, Shield, Clock, AlertTriangle } from 'lucide-react';
import { toast } from 'sonner';

interface NotificationSettingsProps {
  isPro: boolean;
}

export default function NotificationSettings({ isPro }: NotificationSettingsProps) {
  const { user } = useAuth();
  const [emailNotifications, setEmailNotifications] = useState(true);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    if (user) {
      fetchSettings();
    }
  }, [user]);

  const fetchSettings = async () => {
    if (!user) return;

    const { data, error } = await supabase
      .from('profiles')
      .select('email_notifications')
      .eq('id', user.id)
      .maybeSingle();

    if (!error && data) {
      setEmailNotifications(data.email_notifications ?? true);
    }
    setIsLoading(false);
  };

  const updateEmailNotifications = async (enabled: boolean) => {
    if (!user) return;

    setIsSaving(true);
    const { error } = await supabase
      .from('profiles')
      .update({ email_notifications: enabled })
      .eq('id', user.id);

    if (error) {
      toast.error('Failed to update notification settings');
    } else {
      setEmailNotifications(enabled);
      toast.success(enabled ? 'Email notifications enabled' : 'Email notifications disabled');
    }
    setIsSaving(false);
  };

  return (
    <Card className="border-glow glass">
      <CardHeader className="pb-3">
        <CardTitle className="text-lg flex items-center gap-2">
          <Bell className="w-5 h-5 text-primary" />
          Notification Settings
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Email Notifications Toggle */}
        <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Mail className="w-4 h-4 text-primary" />
            </div>
            <div>
              <Label htmlFor="email-notifications" className="font-medium cursor-pointer">
                Email Alerts
              </Label>
              <p className="text-xs text-muted-foreground mt-0.5">
                Receive emails for critical security changes
              </p>
            </div>
          </div>
          <Switch
            id="email-notifications"
            checked={emailNotifications}
            onCheckedChange={updateEmailNotifications}
            disabled={isLoading || isSaving || !isPro}
          />
        </div>

        {!isPro && (
          <div className="p-3 rounded-lg bg-warning/10 border border-warning/30">
            <div className="flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-warning mt-0.5" />
              <div>
                <p className="text-sm font-medium text-warning">Pro Feature</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Email notifications are available for Pro users. Upgrade to receive instant alerts.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Alert Types Info */}
        <div className="space-y-2">
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
            Alert Types
          </p>
          <div className="grid gap-2">
            <div className="flex items-center gap-2 text-sm">
              <Badge className="bg-critical/20 text-critical border-critical/30 text-xs">
                Critical
              </Badge>
              <span className="text-muted-foreground">SSL invalid, security breach</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Badge className="bg-warning/20 text-warning border-warning/30 text-xs">
                High
              </Badge>
              <span className="text-muted-foreground">Risk increased, config drift</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Badge className="bg-primary/20 text-primary border-primary/30 text-xs">
                Medium
              </Badge>
              <span className="text-muted-foreground">SSL expiring soon (&lt;30 days)</span>
            </div>
          </div>
        </div>

        {/* Monitoring Schedule */}
        <div className="pt-2 border-t border-border/50">
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Clock className="w-4 h-4" />
            <span>Background scans run hourly • Email checks run every 15 minutes</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
