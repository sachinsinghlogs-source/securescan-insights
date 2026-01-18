import { useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '@/lib/auth';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { 
  Shield, 
  Lock, 
  Globe, 
  Zap, 
  CheckCircle, 
  ArrowRight,
  ShieldCheck,
  Server,
  AlertTriangle,
  Crown
} from 'lucide-react';

export default function Index() {
  const { user, loading } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (user && !loading) {
      navigate('/dashboard');
    }
  }, [user, loading, navigate]);

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border/50 glass sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center">
              <Shield className="w-5 h-5 text-primary" />
            </div>
            <span className="text-xl font-bold text-gradient-primary">SecureScan</span>
          </div>
          <div className="flex items-center gap-3">
            <Link to="/auth">
              <Button variant="ghost">Sign In</Button>
            </Link>
            <Link to="/auth">
              <Button className="btn-glow bg-primary text-primary-foreground hover:bg-primary/90">
                Get Started
              </Button>
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 grid-pattern opacity-50" />
        <div className="container mx-auto px-4 py-24 md:py-32 relative">
          <div className="max-w-3xl mx-auto text-center">
            <Badge className="mb-6 bg-primary/10 text-primary border-primary/30">
              Passive Security Analysis
            </Badge>
            <h1 className="text-4xl md:text-6xl font-bold mb-6 leading-tight">
              Protect Your{' '}
              <span className="text-gradient-primary">Web Presence</span>
            </h1>
            <p className="text-xl text-muted-foreground mb-8 leading-relaxed">
              Scan any website for security vulnerabilities in seconds. 
              Get detailed reports on SSL certificates, security headers, 
              and potential risks—all without invasive testing.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link to="/auth">
                <Button size="lg" className="btn-glow bg-primary text-primary-foreground hover:bg-primary/90 gap-2 w-full sm:w-auto">
                  Start Free Scan
                  <ArrowRight className="w-4 h-4" />
                </Button>
              </Link>
              <Button size="lg" variant="outline" className="gap-2 border-border hover:bg-muted">
                <Globe className="w-4 h-4" />
                See Demo
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 border-t border-border/50">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold mb-4">Comprehensive Security Checks</h2>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              Our passive scanning technology analyzes multiple aspects of your website's security posture.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Card className="border-glow glass group hover:scale-105 transition-transform duration-300">
              <CardContent className="p-6 text-center">
                <div className="w-12 h-12 mx-auto mb-4 rounded-xl bg-success/10 border border-success/30 flex items-center justify-center group-hover:scale-110 transition-transform">
                  <Lock className="w-6 h-6 text-success" />
                </div>
                <h3 className="font-semibold mb-2">SSL Certificate</h3>
                <p className="text-sm text-muted-foreground">
                  Verify certificate validity, expiration dates, and issuer information
                </p>
              </CardContent>
            </Card>

            <Card className="border-glow glass group hover:scale-105 transition-transform duration-300">
              <CardContent className="p-6 text-center">
                <div className="w-12 h-12 mx-auto mb-4 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center group-hover:scale-110 transition-transform">
                  <ShieldCheck className="w-6 h-6 text-primary" />
                </div>
                <h3 className="font-semibold mb-2">Security Headers</h3>
                <p className="text-sm text-muted-foreground">
                  Audit HTTP headers for Content-Security-Policy, HSTS, and more
                </p>
              </CardContent>
            </Card>

            <Card className="border-glow glass group hover:scale-105 transition-transform duration-300">
              <CardContent className="p-6 text-center">
                <div className="w-12 h-12 mx-auto mb-4 rounded-xl bg-warning/10 border border-warning/30 flex items-center justify-center group-hover:scale-110 transition-transform">
                  <Server className="w-6 h-6 text-warning" />
                </div>
                <h3 className="font-semibold mb-2">Tech Detection</h3>
                <p className="text-sm text-muted-foreground">
                  Identify CMS platforms, frameworks, and server technologies
                </p>
              </CardContent>
            </Card>

            <Card className="border-glow glass group hover:scale-105 transition-transform duration-300">
              <CardContent className="p-6 text-center">
                <div className="w-12 h-12 mx-auto mb-4 rounded-xl bg-critical/10 border border-critical/30 flex items-center justify-center group-hover:scale-110 transition-transform">
                  <AlertTriangle className="w-6 h-6 text-critical" />
                </div>
                <h3 className="font-semibold mb-2">Risk Scoring</h3>
                <p className="text-sm text-muted-foreground">
                  Get a clear risk assessment from Low to Critical based on findings
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section className="py-20 border-t border-border/50 bg-muted/20">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold mb-4">Simple Pricing</h2>
            <p className="text-muted-foreground">Start free, upgrade when you need more</p>
          </div>

          <div className="grid md:grid-cols-2 gap-8 max-w-4xl mx-auto">
            {/* Free Plan */}
            <Card className="border-border/50 relative">
              <CardContent className="p-8">
                <div className="flex items-center gap-2 mb-4">
                  <Zap className="w-5 h-5 text-muted-foreground" />
                  <h3 className="text-xl font-bold">Free</h3>
                </div>
                <div className="mb-6">
                  <span className="text-4xl font-bold">$0</span>
                  <span className="text-muted-foreground">/month</span>
                </div>
                <ul className="space-y-3 mb-8">
                  <li className="flex items-center gap-2 text-sm">
                    <CheckCircle className="w-4 h-4 text-success flex-shrink-0" />
                    3 scans per day
                  </li>
                  <li className="flex items-center gap-2 text-sm">
                    <CheckCircle className="w-4 h-4 text-success flex-shrink-0" />
                    Basic security checks
                  </li>
                  <li className="flex items-center gap-2 text-sm">
                    <CheckCircle className="w-4 h-4 text-success flex-shrink-0" />
                    Scan history
                  </li>
                  <li className="flex items-center gap-2 text-sm">
                    <CheckCircle className="w-4 h-4 text-success flex-shrink-0" />
                    Risk scoring
                  </li>
                </ul>
                <Link to="/auth" className="block">
                  <Button variant="outline" className="w-full">
                    Get Started Free
                  </Button>
                </Link>
              </CardContent>
            </Card>

            {/* Pro Plan */}
            <Card className="border-primary/50 relative card-glow">
              <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                <Badge className="bg-primary text-primary-foreground gap-1">
                  <Crown className="w-3 h-3" />
                  Most Popular
                </Badge>
              </div>
              <CardContent className="p-8">
                <div className="flex items-center gap-2 mb-4">
                  <Crown className="w-5 h-5 text-warning" />
                  <h3 className="text-xl font-bold">Pro</h3>
                </div>
                <div className="mb-6">
                  <span className="text-4xl font-bold">$19</span>
                  <span className="text-muted-foreground">/month</span>
                </div>
                <ul className="space-y-3 mb-8">
                  <li className="flex items-center gap-2 text-sm">
                    <CheckCircle className="w-4 h-4 text-success flex-shrink-0" />
                    <strong>Unlimited</strong> scans
                  </li>
                  <li className="flex items-center gap-2 text-sm">
                    <CheckCircle className="w-4 h-4 text-success flex-shrink-0" />
                    Advanced security checks
                  </li>
                  <li className="flex items-center gap-2 text-sm">
                    <CheckCircle className="w-4 h-4 text-success flex-shrink-0" />
                    Full scan history
                  </li>
                  <li className="flex items-center gap-2 text-sm">
                    <CheckCircle className="w-4 h-4 text-success flex-shrink-0" />
                    Priority support
                  </li>
                  <li className="flex items-center gap-2 text-sm">
                    <CheckCircle className="w-4 h-4 text-success flex-shrink-0" />
                    API access (coming soon)
                  </li>
                </ul>
                <Link to="/auth" className="block">
                  <Button className="w-full btn-glow bg-primary text-primary-foreground hover:bg-primary/90">
                    Upgrade to Pro
                  </Button>
                </Link>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border/50 py-12">
        <div className="container mx-auto px-4">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-primary" />
              <span className="font-semibold">SecureScan</span>
            </div>
            <p className="text-sm text-muted-foreground">
              © 2024 SecureScan. Passive security scanning only.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
