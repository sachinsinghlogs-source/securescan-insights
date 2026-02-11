import { useState, useEffect, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/lib/auth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import {
  Mail, Bell, Shield, Clock, AlertTriangle, TrendingUp, TrendingDown,
  ShieldAlert, Settings, Zap, ChevronDown, ChevronUp
} from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';

interface NotificationSettingsProps {
  isPro: boolean;
}

interface AlertPreference {
  alert_type: string;
  enabled: boolean;
  min_severity: string;
  cooldown_hours: number;
}

const ALERT_TYPE_CONFIG = {
  regressions: {
    label: 'Security Regressions',
    icon: AlertTriangle,
    types: [
      {
        type: 'risk_increased',
        label: 'Risk Level Increased',
        description: 'When security risk level goes up',
        icon: TrendingUp,
        defaultSeverity: 'medium',
        severityBadge: 'high',
      },
      {
        type: 'ssl_invalid',
        label: 'SSL Certificate Invalid',
        description: 'When SSL becomes invalid',
        icon: ShieldAlert,
        defaultSeverity: 'medium',
        severityBadge: 'critical',
      },
      {
        type: 'ssl_expiring',
        label: 'SSL Expiring Soon',
        description: 'When SSL expires within 30 days',
        icon: Clock,
        defaultSeverity: 'medium',
        severityBadge: 'medium',
      },
      {
        type: 'config_drift',
        label: 'Configuration Drift',
        description: 'When security headers are removed',
        icon: Settings,
        defaultSeverity: 'medium',
        severityBadge: 'high',
      },
      {
        type: 'new_technology',
        label: 'New Technology Detected',
        description: 'When new technologies appear on a domain',
        icon: Zap,
        defaultSeverity: 'low',
        severityBadge: 'low',
      },
    ],
  },
  improvements: {
    label: 'Improvements',
    icon: TrendingDown,
    types: [
      {
        type: 'risk_decreased',
        label: 'Risk Level Decreased',
        description: 'When security risk improves',
        icon: TrendingDown,
        defaultSeverity: 'low',
        severityBadge: 'low',
      },
      {
        type: 'ssl_restored',
        label: 'SSL Restored',
        description: 'When SSL becomes valid again',
        icon: Shield,
        defaultSeverity: 'low',
        severityBadge: 'low',
      },
      {
        type: 'headers_improved',
        label: 'Headers Improved',
        description: 'When security headers are added',
        icon: Shield,
        defaultSeverity: 'low',
        severityBadge: 'low',
      },
    ],
  },
};

const COOLDOWN_OPTIONS = [
  { value: 1, label: '1 hour' },
  { value: 6, label: '6 hours' },
  { value: 12, label: '12 hours' },
  { value: 24, label: '24 hours' },
  { value: 48, label: '48 hours' },
];

const SEVERITY_OPTIONS = [
  { value: 'low', label: 'Low+' },
  { value: 'medium', label: 'Medium+' },
  { value: 'high', label: 'High+' },
  { value: 'critical', label: 'Critical only' },
];

export default function NotificationSettings({ isPro }: NotificationSettingsProps) {
  const { user } = useAuth();
  const [emailNotifications, setEmailNotifications] = useState(true);
  const [preferences, setPreferences] = useState<Map<string, AlertPreference>>(new Map());
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [expandedSection, setExpandedSection] = useState<string | null>('regressions');

  const fetchSettings = useCallback(async () => {
    if (!user) return;

    const [profileRes, prefsRes] = await Promise.all([
      supabase.from('profiles').select('email_notifications').eq('id', user.id).maybeSingle(),
      supabase.from('alert_preferences').select('*').eq('user_id', user.id),
    ]);

    if (!profileRes.error && profileRes.data) {
      setEmailNotifications(profileRes.data.email_notifications ?? true);
    }

    const prefsMap = new Map<string, AlertPreference>();
    if (!prefsRes.error && prefsRes.data) {
      for (const p of prefsRes.data) {
        prefsMap.set(p.alert_type, {
          alert_type: p.alert_type,
          enabled: p.enabled,
          min_severity: p.min_severity,
          cooldown_hours: p.cooldown_hours,
        });
      }
    }
    setPreferences(prefsMap);
    setIsLoading(false);
  }, [user]);

  useEffect(() => {
    if (user) fetchSettings();
  }, [user, fetchSettings]);

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

  const upsertPreference = async (alertType: string, updates: Partial<AlertPreference>) => {
    if (!user) return;

    const existing = preferences.get(alertType);
    const newPref: AlertPreference = {
      alert_type: alertType,
      enabled: updates.enabled ?? existing?.enabled ?? true,
      min_severity: updates.min_severity ?? existing?.min_severity ?? 'medium',
      cooldown_hours: updates.cooldown_hours ?? existing?.cooldown_hours ?? 24,
    };

    // Optimistic update
    setPreferences(prev => new Map(prev).set(alertType, newPref));

    const { error } = await supabase
      .from('alert_preferences')
      .upsert(
        {
          user_id: user.id,
          alert_type: alertType,
          enabled: newPref.enabled,
          min_severity: newPref.min_severity,
          cooldown_hours: newPref.cooldown_hours,
        },
        { onConflict: 'user_id,alert_type' }
      );

    if (error) {
      toast.error('Failed to save preference');
      // Revert
      if (existing) {
        setPreferences(prev => new Map(prev).set(alertType, existing));
      } else {
        setPreferences(prev => {
          const next = new Map(prev);
          next.delete(alertType);
          return next;
        });
      }
    }
  };

  const getPref = (alertType: string): AlertPreference => {
    return preferences.get(alertType) ?? {
      alert_type: alertType,
      enabled: true,
      min_severity: 'medium',
      cooldown_hours: 24,
    };
  };

  const getSeverityBadgeStyle = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-critical/20 text-critical border-critical/30';
      case 'high': return 'bg-warning/20 text-warning border-warning/30';
      case 'medium': return 'bg-primary/20 text-primary border-primary/30';
      default: return 'bg-muted text-muted-foreground border-border';
    }
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
        {/* Master Email Toggle */}
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
                Master toggle for all email notifications
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
                  Granular alert preferences are available for Pro users.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Per-type preferences */}
        {Object.entries(ALERT_TYPE_CONFIG).map(([sectionKey, section]) => {
          const SectionIcon = section.icon;
          const isOpen = expandedSection === sectionKey;

          return (
            <Collapsible
              key={sectionKey}
              open={isOpen}
              onOpenChange={(open) => setExpandedSection(open ? sectionKey : null)}
            >
              <CollapsibleTrigger asChild>
                <Button
                  variant="ghost"
                  className="w-full flex items-center justify-between p-3 h-auto rounded-lg hover:bg-muted/30"
                >
                  <div className="flex items-center gap-2">
                    <SectionIcon className={`w-4 h-4 ${sectionKey === 'improvements' ? 'text-green-400' : 'text-warning'}`} />
                    <span className="text-sm font-medium">{section.label}</span>
                    <Badge variant="outline" className="text-xs">
                      {section.types.length}
                    </Badge>
                  </div>
                  {isOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </Button>
              </CollapsibleTrigger>

              <CollapsibleContent className="space-y-2 mt-1">
                {section.types.map((alertConfig) => {
                  const pref = getPref(alertConfig.type);
                  const TypeIcon = alertConfig.icon;

                  return (
                    <div
                      key={alertConfig.type}
                      className={`p-3 rounded-lg border transition-all ${
                        pref.enabled ? 'bg-card border-border/50' : 'bg-muted/20 border-border/30 opacity-60'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <TypeIcon className="w-4 h-4 text-muted-foreground" />
                          <div>
                            <span className="text-sm font-medium">{alertConfig.label}</span>
                            <p className="text-xs text-muted-foreground">{alertConfig.description}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className={`text-xs ${getSeverityBadgeStyle(alertConfig.severityBadge)}`}>
                            {alertConfig.severityBadge}
                          </Badge>
                          <Switch
                            checked={pref.enabled}
                            onCheckedChange={(enabled) => upsertPreference(alertConfig.type, { enabled })}
                            disabled={isLoading || !isPro}
                          />
                        </div>
                      </div>

                      {pref.enabled && sectionKey === 'regressions' && (
                        <div className="flex items-center gap-3 mt-2 pt-2 border-t border-border/30">
                          <div className="flex items-center gap-1.5">
                            <Label className="text-xs text-muted-foreground whitespace-nowrap">Min severity</Label>
                            <Select
                              value={pref.min_severity}
                              onValueChange={(v) => upsertPreference(alertConfig.type, { min_severity: v })}
                              disabled={!isPro}
                            >
                              <SelectTrigger className="h-7 text-xs w-[110px]">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                {SEVERITY_OPTIONS.map(opt => (
                                  <SelectItem key={opt.value} value={opt.value} className="text-xs">
                                    {opt.label}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </div>

                          <div className="flex items-center gap-1.5">
                            <Label className="text-xs text-muted-foreground whitespace-nowrap">Cooldown</Label>
                            <Select
                              value={String(pref.cooldown_hours)}
                              onValueChange={(v) => upsertPreference(alertConfig.type, { cooldown_hours: Number(v) })}
                              disabled={!isPro}
                            >
                              <SelectTrigger className="h-7 text-xs w-[100px]">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                {COOLDOWN_OPTIONS.map(opt => (
                                  <SelectItem key={opt.value} value={String(opt.value)} className="text-xs">
                                    {opt.label}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </CollapsibleContent>
            </Collapsible>
          );
        })}

        {/* Schedule info */}
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
