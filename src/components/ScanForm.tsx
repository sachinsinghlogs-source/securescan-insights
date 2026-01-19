/**
 * Scan Form Component
 * 
 * SECURITY CONTROLS:
 * - URL validation with SSRF protection (blocks internal IPs)
 * - Client-side rate limiting (reduces server load)
 * - Legal disclaimer requirement (compliance)
 * - Input sanitization before API call
 */

import { useState } from 'react';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Globe, Loader2, AlertTriangle, X, Shield } from 'lucide-react';
import { urlSchema, checkClientRateLimit, getSafeErrorMessage } from '@/lib/security';
import { useToast } from '@/hooks/use-toast';

interface ScanFormProps {
  onCancel: () => void;
  onComplete: () => void;
  canScan: boolean;
}

export default function ScanForm({ onCancel, onComplete, canScan }: ScanFormProps) {
  const { user } = useAuth();
  const { toast } = useToast();
  const [url, setUrl] = useState('');
  const [agreedToTerms, setAgreedToTerms] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    // Check if user can scan (quota)
    if (!canScan) {
      setError('You have reached your daily scan limit. Upgrade to Pro for unlimited scans.');
      return;
    }

    // Require legal agreement
    if (!agreedToTerms) {
      setError('You must agree to the legal disclaimer to proceed.');
      return;
    }

    // SECURITY: Client-side rate limiting
    // Reduces server load by blocking obvious abuse
    if (!checkClientRateLimit('scan', 5, 60000)) { // 5 scans per minute
      setError('Please wait before scanning again.');
      return;
    }

    // SECURITY: Validate URL with SSRF protection
    const validationResult = urlSchema.safeParse(url);
    if (!validationResult.success) {
      setError(validationResult.error.errors[0].message);
      return;
    }

    if (!user) {
      setError('You must be logged in to scan.');
      return;
    }

    // Normalize URL (add https:// if missing)
    const normalizedUrl = url.startsWith('http') ? url : `https://${url}`;

    setIsScanning(true);

    try {
      // Call the edge function to perform the scan
      const { data, error: fnError } = await supabase.functions.invoke('security-scan', {
        body: { url: normalizedUrl },
      });

      if (fnError) {
        throw new Error(fnError.message);
      }

      if (data?.error) {
        throw new Error(data.error);
      }

      toast({
        title: "Scan Complete",
        description: `Security analysis for ${new URL(normalizedUrl).hostname} finished.`,
      });

      onComplete();
    } catch (err) {
      console.error('Scan error:', err);
      setError(getSafeErrorMessage(err));
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <Card className="border-glow glass">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center">
              <Shield className="w-5 h-5 text-primary" />
            </div>
            <div>
              <CardTitle>New Security Scan</CardTitle>
              <CardDescription>Enter a URL to analyze</CardDescription>
            </div>
          </div>
          <Button variant="ghost" size="icon" onClick={onCancel}>
            <X className="w-4 h-4" />
          </Button>
        </div>
      </CardHeader>

      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="url">Website URL</Label>
            <div className="relative">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                id="url"
                type="text"
                placeholder="example.com or https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="pl-10 bg-background/50 font-mono"
                disabled={isScanning}
              />
            </div>
          </div>

          {/* Legal Disclaimer */}
          <div className="p-4 rounded-lg bg-warning/5 border border-warning/20">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-warning flex-shrink-0 mt-0.5" />
              <div className="space-y-2 text-sm">
                <p className="font-medium text-warning">Legal Disclaimer</p>
                <p className="text-muted-foreground leading-relaxed">
                  SecureScan performs <strong>passive, non-intrusive security checks only</strong>. 
                  By proceeding, you confirm that you are authorized to scan the submitted domain 
                  and agree not to use this service for any malicious purposes. We do not perform 
                  exploitation, brute force attacks, or any form of active penetration testing.
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <Checkbox
              id="terms"
              checked={agreedToTerms}
              onCheckedChange={(checked) => setAgreedToTerms(checked === true)}
              disabled={isScanning}
            />
            <Label htmlFor="terms" className="text-sm text-muted-foreground cursor-pointer">
              I have read and agree to the legal disclaimer above
            </Label>
          </div>

          {error && (
            <div className="flex items-center gap-2 text-critical text-sm p-3 rounded-lg bg-critical/10 border border-critical/20">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </CardContent>

        <CardFooter className="flex gap-3">
          <Button
            type="button"
            variant="ghost"
            onClick={onCancel}
            disabled={isScanning}
            className="flex-1"
          >
            Cancel
          </Button>
          <Button
            type="submit"
            className="flex-1 btn-glow bg-primary text-primary-foreground hover:bg-primary/90"
            disabled={isScanning || !agreedToTerms || !canScan}
          >
            {isScanning ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Scanning...
              </>
            ) : (
              'Start Scan'
            )}
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}
