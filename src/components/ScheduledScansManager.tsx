import { useState } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/lib/auth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { 
  Calendar, 
  Plus, 
  Trash2, 
  Clock, 
  Globe,
  Server,
  Code,
  RefreshCw
} from 'lucide-react';
import { toast } from 'sonner';

type ScanEnvironment = 'production' | 'staging' | 'development';

interface ScheduledScan {
  id: string;
  target_url: string;
  environment: ScanEnvironment;
  scan_frequency: string;
  is_active: boolean;
  next_scan_at: string | null;
  created_at: string;
}

interface ScheduledScansManagerProps {
  scheduledScans: ScheduledScan[];
  onUpdated: () => void;
  isPro: boolean;
}

export default function ScheduledScansManager({ 
  scheduledScans, 
  onUpdated,
  isPro 
}: ScheduledScansManagerProps) {
  const { user } = useAuth();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [newScan, setNewScan] = useState({
    url: '',
    environment: 'production' as ScanEnvironment,
    frequency: 'daily',
  });

  const createScheduledScan = async () => {
    if (!user || !newScan.url) return;

    // Validate URL
    try {
      new URL(newScan.url.startsWith('http') ? newScan.url : `https://${newScan.url}`);
    } catch {
      toast.error('Please enter a valid URL');
      return;
    }

    setIsCreating(true);
    
    const targetUrl = newScan.url.startsWith('http') 
      ? newScan.url 
      : `https://${newScan.url}`;

    // Calculate next scan time
    const nextScanAt = new Date();
    switch (newScan.frequency) {
      case 'hourly':
        nextScanAt.setHours(nextScanAt.getHours() + 1);
        break;
      case 'daily':
        nextScanAt.setDate(nextScanAt.getDate() + 1);
        break;
      case 'weekly':
        nextScanAt.setDate(nextScanAt.getDate() + 7);
        break;
    }

    const { error } = await supabase
      .from('scheduled_scans')
      .insert({
        user_id: user.id,
        target_url: targetUrl,
        environment: newScan.environment,
        scan_frequency: newScan.frequency,
        next_scan_at: nextScanAt.toISOString(),
      });

    if (error) {
      toast.error('Failed to create scheduled scan');
    } else {
      toast.success('Scheduled scan created');
      setNewScan({ url: '', environment: 'production', frequency: 'daily' });
      setIsDialogOpen(false);
      onUpdated();
    }
    
    setIsCreating(false);
  };

  const toggleActive = async (scan: ScheduledScan) => {
    const { error } = await supabase
      .from('scheduled_scans')
      .update({ is_active: !scan.is_active })
      .eq('id', scan.id);

    if (error) {
      toast.error('Failed to update scan');
    } else {
      onUpdated();
    }
  };

  const deleteScheduledScan = async (scanId: string) => {
    const { error } = await supabase
      .from('scheduled_scans')
      .delete()
      .eq('id', scanId);

    if (error) {
      toast.error('Failed to delete scheduled scan');
    } else {
      toast.success('Scheduled scan deleted');
      onUpdated();
    }
  };

  const getEnvironmentIcon = (env: ScanEnvironment) => {
    switch (env) {
      case 'production':
        return <Globe className="w-4 h-4" />;
      case 'staging':
        return <Server className="w-4 h-4" />;
      case 'development':
        return <Code className="w-4 h-4" />;
    }
  };

  const getEnvironmentStyle = (env: ScanEnvironment) => {
    switch (env) {
      case 'production':
        return 'bg-critical/20 text-critical border-critical/30';
      case 'staging':
        return 'bg-warning/20 text-warning border-warning/30';
      case 'development':
        return 'bg-primary/20 text-primary border-primary/30';
    }
  };

  const getFrequencyLabel = (freq: string) => {
    switch (freq) {
      case 'hourly':
        return 'Every hour';
      case 'daily':
        return 'Daily';
      case 'weekly':
        return 'Weekly';
      default:
        return freq;
    }
  };

  const extractHostname = (url: string) => {
    try {
      return new URL(url).hostname;
    } catch {
      return url;
    }
  };

  if (!isPro) {
    return (
      <Card className="border-glow glass">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <Calendar className="w-5 h-5 text-primary" />
            Continuous Monitoring
          </CardTitle>
        </CardHeader>
        <CardContent className="text-center py-8">
          <RefreshCw className="w-10 h-10 mx-auto text-muted-foreground/50 mb-3" />
          <p className="text-muted-foreground mb-2">
            Upgrade to Pro for continuous monitoring
          </p>
          <p className="text-xs text-muted-foreground/70">
            Automatic daily scans with intelligent alerts
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-glow glass">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg flex items-center gap-2">
            <Calendar className="w-5 h-5 text-primary" />
            Continuous Monitoring
          </CardTitle>
          
          <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
            <DialogTrigger asChild>
              <Button size="sm" className="gap-1">
                <Plus className="w-4 h-4" />
                Add
              </Button>
            </DialogTrigger>
            
            <DialogContent className="sm:max-w-md">
              <DialogHeader>
                <DialogTitle>Schedule Continuous Monitoring</DialogTitle>
              </DialogHeader>
              
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="url">Website URL</Label>
                  <Input
                    id="url"
                    placeholder="example.com"
                    value={newScan.url}
                    onChange={(e) => setNewScan(s => ({ ...s, url: e.target.value }))}
                  />
                </div>
                
                <div className="space-y-2">
                  <Label>Environment</Label>
                  <Select
                    value={newScan.environment}
                    onValueChange={(v) => setNewScan(s => ({ ...s, environment: v as ScanEnvironment }))}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="production">
                        <div className="flex items-center gap-2">
                          <Globe className="w-4 h-4" />
                          Production
                        </div>
                      </SelectItem>
                      <SelectItem value="staging">
                        <div className="flex items-center gap-2">
                          <Server className="w-4 h-4" />
                          Staging
                        </div>
                      </SelectItem>
                      <SelectItem value="development">
                        <div className="flex items-center gap-2">
                          <Code className="w-4 h-4" />
                          Development
                        </div>
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                
                <div className="space-y-2">
                  <Label>Scan Frequency</Label>
                  <Select
                    value={newScan.frequency}
                    onValueChange={(v) => setNewScan(s => ({ ...s, frequency: v }))}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="hourly">Every hour</SelectItem>
                      <SelectItem value="daily">Daily</SelectItem>
                      <SelectItem value="weekly">Weekly</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                
                <Button 
                  onClick={createScheduledScan} 
                  className="w-full"
                  disabled={isCreating || !newScan.url}
                >
                  {isCreating ? 'Creating...' : 'Start Monitoring'}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </CardHeader>
      
      <CardContent>
        {scheduledScans.length === 0 ? (
          <div className="text-center py-6">
            <Calendar className="w-10 h-10 mx-auto text-muted-foreground/50 mb-3" />
            <p className="text-muted-foreground text-sm">
              No scheduled scans yet
            </p>
            <p className="text-xs text-muted-foreground/70 mt-1">
              Add a website to monitor continuously
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {scheduledScans.map((scan) => (
              <div 
                key={scan.id}
                className={`p-3 rounded-lg border transition-all ${
                  scan.is_active 
                    ? 'bg-card border-primary/30' 
                    : 'bg-muted/30 border-border/50 opacity-60'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium text-sm truncate">
                        {extractHostname(scan.target_url)}
                      </span>
                      <Badge 
                        variant="outline" 
                        className={`text-xs gap-1 ${getEnvironmentStyle(scan.environment)}`}
                      >
                        {getEnvironmentIcon(scan.environment)}
                        {scan.environment}
                      </Badge>
                    </div>
                    
                    <div className="flex items-center gap-3 text-xs text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {getFrequencyLabel(scan.scan_frequency)}
                      </span>
                      {scan.next_scan_at && scan.is_active && (
                        <span>
                          Next: {new Date(scan.next_scan_at).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-2">
                    <Switch
                      checked={scan.is_active}
                      onCheckedChange={() => toggleActive(scan)}
                    />
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8 text-muted-foreground hover:text-critical"
                      onClick={() => deleteScheduledScan(scan.id)}
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
