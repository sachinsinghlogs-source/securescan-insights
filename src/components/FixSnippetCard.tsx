import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Wrench, 
  ChevronDown, 
  ChevronUp, 
  Copy, 
  Check,
  ExternalLink,
  AlertTriangle,
  AlertCircle,
  Info
} from 'lucide-react';

export interface FixSnippet {
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  apache?: string;
  nginx?: string;
  iis?: string;
  cloudflare?: string;
  example?: string;
  reference?: string;
}

interface FixSnippetCardProps {
  fixes: FixSnippet[];
}

export default function FixSnippetCard({ fixes }: FixSnippetCardProps) {
  const [expandedFix, setExpandedFix] = useState<number | null>(null);
  const [copiedIndex, setCopiedIndex] = useState<string | null>(null);

  if (!fixes || fixes.length === 0) {
    return null;
  }

  const getSeverityBadge = (severity: FixSnippet['severity']) => {
    switch (severity) {
      case 'critical':
        return (
          <Badge className="bg-critical text-critical-foreground gap-1">
            <AlertCircle className="w-3 h-3" />
            Critical
          </Badge>
        );
      case 'high':
        return (
          <Badge className="bg-destructive text-destructive-foreground gap-1">
            <AlertTriangle className="w-3 h-3" />
            High
          </Badge>
        );
      case 'medium':
        return (
          <Badge className="bg-warning text-warning-foreground gap-1">
            <AlertTriangle className="w-3 h-3" />
            Medium
          </Badge>
        );
      case 'low':
        return (
          <Badge variant="secondary" className="gap-1">
            <Info className="w-3 h-3" />
            Low
          </Badge>
        );
    }
  };

  const copyToClipboard = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedIndex(id);
      setTimeout(() => setCopiedIndex(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const CodeBlock = ({ code, id }: { code: string; id: string }) => (
    <div className="relative group">
      <pre className="p-3 rounded-md bg-background/80 text-xs font-mono overflow-x-auto border border-border/50">
        <code>{code}</code>
      </pre>
      <Button
        variant="ghost"
        size="icon"
        className="absolute top-2 right-2 h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
        onClick={() => copyToClipboard(code, id)}
      >
        {copiedIndex === id ? (
          <Check className="w-3 h-3 text-success" />
        ) : (
          <Copy className="w-3 h-3" />
        )}
      </Button>
    </div>
  );

  return (
    <Card className="border-primary/20 bg-gradient-to-br from-primary/5 to-transparent">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-lg">
          <Wrench className="w-5 h-5 text-primary" />
          Recommended Fixes
          <Badge variant="outline" className="ml-auto">
            {fixes.length} issue{fixes.length !== 1 ? 's' : ''}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {fixes.map((fix, index) => (
          <div
            key={index}
            className="p-3 rounded-lg bg-muted/30 border border-border/30 transition-all"
          >
            <div
              className="flex items-start justify-between gap-2 cursor-pointer"
              onClick={() => setExpandedFix(expandedFix === index ? null : index)}
            >
              <div className="space-y-1 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  {getSeverityBadge(fix.severity)}
                  <h4 className="font-medium text-sm">{fix.title}</h4>
                </div>
                <p className="text-xs text-muted-foreground line-clamp-2">
                  {fix.description}
                </p>
              </div>
              <Button variant="ghost" size="icon" className="h-6 w-6 flex-shrink-0">
                {expandedFix === index ? (
                  <ChevronUp className="w-4 h-4" />
                ) : (
                  <ChevronDown className="w-4 h-4" />
                )}
              </Button>
            </div>

            {expandedFix === index && (
              <div className="mt-4 space-y-4 animate-fade-in">
                <p className="text-sm text-muted-foreground">
                  {fix.description}
                </p>

                {(fix.apache || fix.nginx || fix.iis || fix.cloudflare) && (
                  <Tabs defaultValue={fix.nginx ? 'nginx' : fix.apache ? 'apache' : 'example'} className="w-full">
                    <TabsList className="grid w-full grid-cols-4 h-8">
                      {fix.nginx && <TabsTrigger value="nginx" className="text-xs">Nginx</TabsTrigger>}
                      {fix.apache && <TabsTrigger value="apache" className="text-xs">Apache</TabsTrigger>}
                      {fix.iis && <TabsTrigger value="iis" className="text-xs">IIS</TabsTrigger>}
                      {fix.cloudflare && <TabsTrigger value="cloudflare" className="text-xs">Cloudflare</TabsTrigger>}
                    </TabsList>
                    {fix.nginx && (
                      <TabsContent value="nginx" className="mt-2">
                        <CodeBlock code={fix.nginx} id={`${index}-nginx`} />
                      </TabsContent>
                    )}
                    {fix.apache && (
                      <TabsContent value="apache" className="mt-2">
                        <CodeBlock code={fix.apache} id={`${index}-apache`} />
                      </TabsContent>
                    )}
                    {fix.iis && (
                      <TabsContent value="iis" className="mt-2">
                        <CodeBlock code={fix.iis} id={`${index}-iis`} />
                      </TabsContent>
                    )}
                    {fix.cloudflare && (
                      <TabsContent value="cloudflare" className="mt-2">
                        <p className="text-sm text-muted-foreground p-3 bg-background/80 rounded-md border border-border/50">
                          {fix.cloudflare}
                        </p>
                      </TabsContent>
                    )}
                  </Tabs>
                )}

                {fix.example && !fix.apache && !fix.nginx && (
                  <div className="space-y-2">
                    <span className="text-xs font-medium text-muted-foreground">Example:</span>
                    <CodeBlock code={fix.example} id={`${index}-example`} />
                  </div>
                )}

                {fix.reference && (
                  <a
                    href={fix.reference}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                  >
                    <ExternalLink className="w-3 h-3" />
                    Learn more
                  </a>
                )}
              </div>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
