import { useState } from 'react';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Calendar, Clock, Globe, Plus, Trash2, Cloud } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface ScheduledCloudScan {
  id: string;
  target_url: string;
  scan_frequency: string;
  is_active: boolean;
  next_scan_at: string | null;
  created_at: string;
}

interface ScheduledCloudScansProps {
  scheduledScans: ScheduledCloudScan[];
  onUpdated: () => void;
}

export default function ScheduledCloudScans({ scheduledScans, onUpdated }: ScheduledCloudScansProps) {
  const { user } = useAuth();
  const { toast } = useToast();
  const [showForm, setShowForm] = useState(false);
  const [url, setUrl] = useState('');
  const [frequency, setFrequency] = useState('daily');

  const handleCreate = async () => {
    if (!url.trim() || !user) return;

    const normalizedUrl = url.startsWith('http') ? url : `https://${url}`;
    const nextScanAt = new Date();
    switch (frequency) {
      case 'hourly': nextScanAt.setHours(nextScanAt.getHours() + 1); break;
      case 'daily': nextScanAt.setDate(nextScanAt.getDate() + 1); break;
      case 'weekly': nextScanAt.setDate(nextScanAt.getDate() + 7); break;
    }

    const { error } = await supabase.from('scheduled_cloud_scans').insert({
      user_id: user.id,
      target_url: normalizedUrl,
      scan_frequency: frequency,
      next_scan_at: nextScanAt.toISOString(),
    });

    if (error) {
      toast({ title: 'Error', description: error.message, variant: 'destructive' });
    } else {
      toast({ title: 'Scheduled', description: `Cloud pipeline will run ${frequency}.` });
      setUrl('');
      setShowForm(false);
      onUpdated();
    }
  };

  const toggleActive = async (id: string, isActive: boolean) => {
    await supabase.from('scheduled_cloud_scans').update({ is_active: !isActive }).eq('id', id);
    onUpdated();
  };

  const handleDelete = async (id: string) => {
    await supabase.from('scheduled_cloud_scans').delete().eq('id', id);
    onUpdated();
  };

  return (
    <Card className="border-glow glass">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center">
              <Calendar className="w-5 h-5 text-primary" />
            </div>
            <div>
              <CardTitle className="text-lg">Scheduled Cloud Scans</CardTitle>
              <CardDescription>Automate recurring cloud security pipeline runs</CardDescription>
            </div>
          </div>
          <Button size="sm" onClick={() => setShowForm(!showForm)} className="gap-1">
            <Plus className="w-4 h-4" />
            Schedule
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Add Form */}
        {showForm && (
          <div className="p-4 rounded-lg border border-primary/30 bg-primary/5 space-y-3 animate-fade-in">
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="URL to monitor (e.g., api.example.com)"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="pl-10 bg-background/50 font-mono text-sm"
                />
              </div>
              <Select value={frequency} onValueChange={setFrequency}>
                <SelectTrigger className="w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="hourly">Hourly</SelectItem>
                  <SelectItem value="daily">Daily</SelectItem>
                  <SelectItem value="weekly">Weekly</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex gap-2 justify-end">
              <Button variant="outline" size="sm" onClick={() => setShowForm(false)}>Cancel</Button>
              <Button size="sm" onClick={handleCreate} disabled={!url.trim()}>Create Schedule</Button>
            </div>
          </div>
        )}

        {/* Scheduled list */}
        {scheduledScans.length === 0 ? (
          <div className="text-center py-6">
            <Cloud className="w-10 h-10 mx-auto text-muted-foreground/50 mb-2" />
            <p className="text-sm text-muted-foreground">No scheduled cloud scans yet</p>
          </div>
        ) : (
          <div className="space-y-2">
            {scheduledScans.map((scan) => (
              <div key={scan.id} className="flex items-center justify-between p-3 rounded-lg border border-border bg-card/50">
                <div className="flex items-center gap-3 min-w-0 flex-1">
                  <Switch checked={scan.is_active} onCheckedChange={() => toggleActive(scan.id, scan.is_active)} />
                  <span className="text-sm font-mono truncate">{(() => { try { return new URL(scan.target_url).hostname; } catch { return scan.target_url; } })()}</span>
                  <Badge variant="outline" className="text-xs capitalize flex-shrink-0">{scan.scan_frequency}</Badge>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  {scan.next_scan_at && (
                    <span className="text-xs text-muted-foreground flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {new Date(scan.next_scan_at).toLocaleString()}
                    </span>
                  )}
                  <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => handleDelete(scan.id)}>
                    <Trash2 className="w-3 h-3" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
