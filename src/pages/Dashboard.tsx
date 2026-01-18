import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Shield, LogOut, Plus, Clock, Globe, AlertTriangle, CheckCircle, XCircle, Zap, Crown } from 'lucide-react';
import ScanForm from '@/components/ScanForm';
import ScanResultCard from '@/components/ScanResultCard';
import type { Scan, Profile } from '@/types/database';

export default function Dashboard() {
  const navigate = useNavigate();
  const { user, signOut, loading } = useAuth();
  const [scans, setScans] = useState<Scan[]>([]);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [showScanForm, setShowScanForm] = useState(false);
  const [isLoadingScans, setIsLoadingScans] = useState(true);

  useEffect(() => {
    if (!user && !loading) {
      navigate('/auth');
    }
  }, [user, loading, navigate]);

  useEffect(() => {
    if (user) {
      fetchProfile();
      fetchScans();
    }
  }, [user]);

  const fetchProfile = async () => {
    if (!user) return;
    
    const { data, error } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', user.id)
      .maybeSingle();

    if (!error && data) {
      setProfile(data as Profile);
    }
  };

  const fetchScans = async () => {
    if (!user) return;
    
    setIsLoadingScans(true);
    const { data, error } = await supabase
      .from('scans')
      .select('*')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false });

    if (!error && data) {
      setScans(data as Scan[]);
    }
    setIsLoadingScans(false);
  };

  const handleSignOut = async () => {
    await signOut();
    navigate('/');
  };

  const handleScanComplete = () => {
    setShowScanForm(false);
    fetchScans();
    fetchProfile();
  };

  const getScansRemaining = () => {
    if (!profile) return 3;
    if (profile.plan_type === 'pro') return 'Unlimited';
    return Math.max(0, 3 - (profile.daily_scans_used || 0));
  };

  const canScan = () => {
    if (!profile) return true;
    if (profile.plan_type === 'pro') return true;
    return (profile.daily_scans_used || 0) < 3;
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background grid-pattern">
        <div className="animate-pulse text-primary">Loading...</div>
      </div>
    );
  }

  const completedScans = scans.filter(s => s.status === 'completed');
  const riskCounts = {
    low: completedScans.filter(s => s.risk_level === 'low').length,
    medium: completedScans.filter(s => s.risk_level === 'medium').length,
    high: completedScans.filter(s => s.risk_level === 'high' || s.risk_level === 'critical').length,
  };

  return (
    <div className="min-h-screen bg-background grid-pattern">
      {/* Header */}
      <header className="border-b border-border glass sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center">
              <Shield className="w-5 h-5 text-primary" />
            </div>
            <span className="text-xl font-bold text-gradient-primary">SecureScan</span>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden sm:flex items-center gap-2">
              {profile?.plan_type === 'pro' ? (
                <Badge className="bg-warning/20 text-warning border-warning/30 gap-1">
                  <Crown className="w-3 h-3" />
                  Pro
                </Badge>
              ) : (
                <Badge variant="secondary" className="gap-1">
                  <Zap className="w-3 h-3" />
                  Free
                </Badge>
              )}
              <span className="text-sm text-muted-foreground">
                {getScansRemaining()} scans {typeof getScansRemaining() === 'number' ? 'remaining today' : ''}
              </span>
            </div>
            <Button variant="ghost" size="icon" onClick={handleSignOut}>
              <LogOut className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        {/* Stats Overview */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <Card className="border-glow glass">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Total Scans</p>
                  <p className="text-2xl font-bold">{scans.length}</p>
                </div>
                <Globe className="w-8 h-8 text-primary/50" />
              </div>
            </CardContent>
          </Card>

          <Card className="border-glow glass">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Low Risk</p>
                  <p className="text-2xl font-bold text-success">{riskCounts.low}</p>
                </div>
                <CheckCircle className="w-8 h-8 text-success/50" />
              </div>
            </CardContent>
          </Card>

          <Card className="border-glow glass">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Medium Risk</p>
                  <p className="text-2xl font-bold text-warning">{riskCounts.medium}</p>
                </div>
                <AlertTriangle className="w-8 h-8 text-warning/50" />
              </div>
            </CardContent>
          </Card>

          <Card className="border-glow glass">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">High Risk</p>
                  <p className="text-2xl font-bold text-critical">{riskCounts.high}</p>
                </div>
                <XCircle className="w-8 h-8 text-critical/50" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Scan Form or Button */}
        {showScanForm ? (
          <div className="mb-8 animate-fade-in">
            <ScanForm 
              onCancel={() => setShowScanForm(false)} 
              onComplete={handleScanComplete}
              canScan={canScan()}
            />
          </div>
        ) : (
          <Card className="border-glow glass mb-8">
            <CardContent className="p-6">
              <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
                <div>
                  <h3 className="text-lg font-semibold">Start a New Scan</h3>
                  <p className="text-muted-foreground text-sm">
                    Analyze any website for security vulnerabilities
                  </p>
                </div>
                <Button 
                  onClick={() => setShowScanForm(true)}
                  className="btn-glow bg-primary text-primary-foreground hover:bg-primary/90 gap-2"
                  disabled={!canScan()}
                >
                  <Plus className="w-4 h-4" />
                  New Scan
                </Button>
              </div>
              {!canScan() && (
                <p className="text-sm text-warning mt-4">
                  You've reached your daily scan limit. Upgrade to Pro for unlimited scans.
                </p>
              )}
            </CardContent>
          </Card>
        )}

        {/* Scan History */}
        <div>
          <div className="flex items-center gap-2 mb-4">
            <Clock className="w-5 h-5 text-muted-foreground" />
            <h2 className="text-xl font-semibold">Scan History</h2>
          </div>

          {isLoadingScans ? (
            <div className="grid gap-4">
              {[1, 2, 3].map((i) => (
                <Card key={i} className="border-border/50 animate-pulse">
                  <CardContent className="p-6">
                    <div className="h-4 bg-muted rounded w-1/3 mb-2"></div>
                    <div className="h-3 bg-muted rounded w-1/2"></div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : scans.length === 0 ? (
            <Card className="border-border/50">
              <CardContent className="p-12 text-center">
                <Globe className="w-12 h-12 mx-auto text-muted-foreground/50 mb-4" />
                <h3 className="text-lg font-medium mb-2">No scans yet</h3>
                <p className="text-muted-foreground text-sm">
                  Start your first scan to analyze a website's security posture
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-4">
              {scans.map((scan, index) => (
                <div 
                  key={scan.id} 
                  className="animate-fade-in"
                  style={{ animationDelay: `${index * 50}ms` }}
                >
                  <ScanResultCard scan={scan} />
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
