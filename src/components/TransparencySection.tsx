import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { 
  CheckCircle, 
  XCircle, 
  Info,
  Shield,
  Lock,
  Server,
  Code,
  Eye,
  AlertTriangle
} from 'lucide-react';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion';

interface CheckItem {
  name: string;
  description: string;
  checked: boolean;
}

const SECURITY_CHECKS: { category: string; icon: React.ReactNode; items: CheckItem[] }[] = [
  {
    category: 'SSL/TLS Certificate',
    icon: <Lock className="w-4 h-4" />,
    items: [
      { name: 'HTTPS availability', description: 'Verifies your site is accessible via HTTPS', checked: true },
      { name: 'Certificate validity', description: 'Checks if the SSL certificate is valid and trusted', checked: true },
      { name: 'Certificate expiry', description: 'Monitors days until certificate expiration', checked: true },
      { name: 'Certificate chain', description: 'Full certificate chain validation', checked: false },
      { name: 'Cipher suite strength', description: 'Analysis of encryption algorithms used', checked: false },
      { name: 'TLS version', description: 'Checks for outdated TLS 1.0/1.1', checked: false },
    ],
  },
  {
    category: 'Security Headers',
    icon: <Shield className="w-4 h-4" />,
    items: [
      { name: 'Strict-Transport-Security (HSTS)', description: 'Forces HTTPS connections', checked: true },
      { name: 'Content-Security-Policy (CSP)', description: 'Prevents XSS and injection attacks', checked: true },
      { name: 'X-Frame-Options', description: 'Prevents clickjacking attacks', checked: true },
      { name: 'X-Content-Type-Options', description: 'Prevents MIME-sniffing', checked: true },
      { name: 'X-XSS-Protection', description: 'Legacy XSS filter', checked: true },
      { name: 'Referrer-Policy', description: 'Controls referrer information', checked: true },
      { name: 'Permissions-Policy', description: 'Controls browser features', checked: true },
      { name: 'CSP policy analysis', description: 'In-depth CSP directive validation', checked: false },
    ],
  },
  {
    category: 'Technology Detection',
    icon: <Code className="w-4 h-4" />,
    items: [
      { name: 'CMS detection', description: 'Identifies WordPress, Drupal, Joomla, etc.', checked: true },
      { name: 'Framework detection', description: 'Identifies React, Vue, Angular, etc.', checked: true },
      { name: 'Server identification', description: 'Detects web server software', checked: true },
      { name: 'CDN detection', description: 'Identifies Cloudflare and other CDNs', checked: true },
      { name: 'Version fingerprinting', description: 'Exact version detection for CVE matching', checked: false },
    ],
  },
  {
    category: 'Infrastructure',
    icon: <Server className="w-4 h-4" />,
    items: [
      { name: 'Server info exposure', description: 'Checks if server version is visible', checked: true },
      { name: 'Port scanning', description: 'Checks for open/vulnerable ports', checked: false },
      { name: 'DNS security (DNSSEC)', description: 'DNS security extension validation', checked: false },
      { name: 'IP reputation', description: 'Checks if IP is blacklisted', checked: false },
    ],
  },
  {
    category: 'Application Security',
    icon: <Eye className="w-4 h-4" />,
    items: [
      { name: 'Vulnerability scanning', description: 'Active vulnerability probing', checked: false },
      { name: 'SQL injection testing', description: 'Active SQL injection checks', checked: false },
      { name: 'XSS testing', description: 'Active cross-site scripting tests', checked: false },
      { name: 'Authentication testing', description: 'Login security analysis', checked: false },
    ],
  },
];

export default function TransparencySection() {
  const checkedCount = SECURITY_CHECKS.flatMap(c => c.items).filter(i => i.checked).length;
  const totalCount = SECURITY_CHECKS.flatMap(c => c.items).length;

  return (
    <Card className="border-border/50">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-lg">
            <Info className="w-5 h-5 text-primary" />
            What We Check
          </CardTitle>
          <Badge variant="outline">
            {checkedCount} of {totalCount} checks
          </Badge>
        </div>
        <p className="text-sm text-muted-foreground">
          SecureScan performs <strong>passive, non-intrusive</strong> security analysis. 
          We only examine publicly available information without attempting any exploitation.
        </p>
      </CardHeader>
      <CardContent>
        <div className="mb-4 p-3 rounded-lg bg-warning/10 border border-warning/20">
          <div className="flex gap-2">
            <AlertTriangle className="w-4 h-4 text-warning mt-0.5 flex-shrink-0" />
            <div className="text-sm">
              <strong className="text-warning">Important Limitation:</strong>
              <p className="text-muted-foreground mt-1">
                This is a passive scanner. We do NOT perform active vulnerability testing, 
                penetration testing, or exploitation attempts. For comprehensive security audits, 
                consult a professional security firm.
              </p>
            </div>
          </div>
        </div>

        <Accordion type="multiple" className="w-full">
          {SECURITY_CHECKS.map((category, idx) => {
            const categoryChecked = category.items.filter(i => i.checked).length;
            return (
              <AccordionItem key={idx} value={`category-${idx}`}>
                <AccordionTrigger className="hover:no-underline">
                  <div className="flex items-center gap-3">
                    <span className="p-1.5 rounded-md bg-primary/10 text-primary">
                      {category.icon}
                    </span>
                    <span>{category.category}</span>
                    <Badge variant="secondary" className="ml-2 text-xs">
                      {categoryChecked}/{category.items.length}
                    </Badge>
                  </div>
                </AccordionTrigger>
                <AccordionContent>
                  <div className="space-y-2 pl-10">
                    {category.items.map((item, itemIdx) => (
                      <div 
                        key={itemIdx} 
                        className={`flex items-start gap-2 p-2 rounded-md ${
                          item.checked ? 'bg-success/5' : 'bg-muted/30'
                        }`}
                      >
                        {item.checked ? (
                          <CheckCircle className="w-4 h-4 text-success mt-0.5 flex-shrink-0" />
                        ) : (
                          <XCircle className="w-4 h-4 text-muted-foreground mt-0.5 flex-shrink-0" />
                        )}
                        <div>
                          <span className={`text-sm font-medium ${!item.checked && 'text-muted-foreground'}`}>
                            {item.name}
                          </span>
                          {!item.checked && (
                            <Badge variant="outline" className="ml-2 text-xs">
                              Not included
                            </Badge>
                          )}
                          <p className="text-xs text-muted-foreground mt-0.5">
                            {item.description}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </AccordionContent>
              </AccordionItem>
            );
          })}
        </Accordion>

        <div className="mt-4 p-3 rounded-lg bg-muted/30 text-sm text-muted-foreground">
          <strong>Scan Type:</strong> Passive (OWASP Category: Information Gathering)<br />
          <strong>Legal Notice:</strong> Only user-authorized, publicly accessible endpoints are scanned.
        </div>
      </CardContent>
    </Card>
  );
}
