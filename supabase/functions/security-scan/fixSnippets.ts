/**
 * SecureScan Fix Snippets - Remediation Guidance
 * 
 * SECURITY NOTES:
 * - Provides configuration-level remediation guidance
 * - Helps users reduce risk without exploitation
 * - Industry-standard recommendations
 */

export interface FixSnippet {
  title: string;
  description: string;
  whyItMatters: string; // NEW: Explains the risk if not fixed
  severity: "critical" | "high" | "medium" | "low";
  impactScore: number; // NEW: 1-10 impact rating
  apache?: string;
  nginx?: string;
  iis?: string;
  cloudflare?: string;
  example?: string;
  reference?: string;
}

export const FIX_SNIPPETS: Record<string, FixSnippet> = {
  "strict-transport-security": {
    title: "Enable HTTP Strict Transport Security (HSTS)",
    description:
      "HSTS forces browsers to always use HTTPS, preventing SSL stripping and downgrade attacks. This is critical for protecting user sessions and sensitive data.",
    whyItMatters: "Without HSTS, attackers on the same network can intercept the initial HTTP request and perform man-in-the-middle attacks. This exposes login credentials, session cookies, and all transmitted data to theft.",
    severity: "critical",
    impactScore: 10,
    apache: `# Add to .htaccess or Apache config
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`,
    nginx: `# Add to nginx.conf server block
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`,
    iis: `<!-- Add to web.config -->
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains; preload" />
    </customHeaders>
  </httpProtocol>
</system.webServer>`,
    cloudflare: "Enable HSTS in Cloudflare Dashboard → SSL/TLS → Edge Certificates → Enable HSTS",
    reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
  },

  "content-security-policy": {
    title: "Add Content Security Policy (CSP)",
    description:
      "CSP is a powerful defense against Cross-Site Scripting (XSS) attacks. It controls which resources the browser is allowed to load, reducing the attack surface significantly.",
    whyItMatters: "Without CSP, malicious scripts injected through XSS vulnerabilities can steal user data, hijack sessions, deface your site, or redirect users to phishing pages. CSP is your primary defense against the most common web attack vector.",
    severity: "high",
    impactScore: 9,
    apache: `# Add to .htaccess - Customize based on your needs
Header set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://trusted-scripts.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https://fonts.googleapis.com; connect-src 'self' https://api.yoursite.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"`,
    nginx: `# Add to nginx.conf server block - Customize based on your needs
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;`,
    example: `# Start with report-only mode to test
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-violation-report`,
    reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
  },

  "x-frame-options": {
    title: "Prevent Clickjacking with X-Frame-Options",
    description:
      "X-Frame-Options prevents your site from being embedded in malicious iframes, protecting against clickjacking attacks where users are tricked into clicking hidden elements.",
    whyItMatters: "Without this header, attackers can embed your login page in an invisible iframe on a malicious site. Users think they're clicking something harmless but actually click your hidden buttons—transferring money, changing settings, or granting permissions.",
    severity: "high",
    impactScore: 8,
    apache: `# Add to .htaccess
Header set X-Frame-Options "SAMEORIGIN"`,
    nginx: `# Add to nginx.conf
add_header X-Frame-Options "SAMEORIGIN" always;`,
    iis: `<!-- Add to web.config -->
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="X-Frame-Options" value="SAMEORIGIN" />
    </customHeaders>
  </httpProtocol>
</system.webServer>`,
    example: `# Options: DENY, SAMEORIGIN, or ALLOW-FROM uri
X-Frame-Options: DENY  # Completely blocks framing
X-Frame-Options: SAMEORIGIN  # Allows framing only by same origin`,
    reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
  },

  "x-content-type-options": {
    title: "Disable MIME Type Sniffing",
    description:
      "X-Content-Type-Options prevents browsers from MIME-sniffing responses away from the declared content-type, reducing the risk of drive-by download attacks.",
    whyItMatters: "Browsers may 'sniff' file types and execute malicious JavaScript hidden in uploaded images or documents. This one-line fix prevents attackers from disguising executable content as harmless files.",
    severity: "medium",
    impactScore: 6,
    apache: `# Add to .htaccess
Header set X-Content-Type-Options "nosniff"`,
    nginx: `# Add to nginx.conf
add_header X-Content-Type-Options "nosniff" always;`,
    iis: `<!-- Add to web.config -->
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="X-Content-Type-Options" value="nosniff" />
    </customHeaders>
  </httpProtocol>
</system.webServer>`,
    reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
  },

  "x-xss-protection": {
    title: "Enable XSS Filter",
    description:
      "While modern browsers have deprecated this header in favor of CSP, it still provides a defense layer for older browsers against reflected XSS attacks.",
    whyItMatters: "Although deprecated in modern browsers, this header still protects users on older browsers (IE, older Edge). It's a simple addition that provides backward compatibility for your security posture.",
    severity: "low",
    impactScore: 3,
    apache: `# Add to .htaccess
Header set X-XSS-Protection "1; mode=block"`,
    nginx: `# Add to nginx.conf
add_header X-XSS-Protection "1; mode=block" always;`,
    example: `X-XSS-Protection: 1; mode=block
# Note: This is deprecated in favor of Content-Security-Policy`,
    reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
  },

  "referrer-policy": {
    title: "Configure Referrer Policy",
    description:
      "Referrer-Policy controls how much referrer information is sent with requests. This protects user privacy and prevents sensitive URL parameters from leaking to external sites.",
    whyItMatters: "URLs often contain sensitive data: session tokens, search queries, user IDs. Without this header, this information leaks to every external resource your page loads—analytics, CDNs, ads—creating privacy and security risks.",
    severity: "medium",
    impactScore: 5,
    apache: `# Add to .htaccess
Header set Referrer-Policy "strict-origin-when-cross-origin"`,
    nginx: `# Add to nginx.conf
add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
    example: `# Recommended options:
Referrer-Policy: no-referrer  # Never send referrer
Referrer-Policy: strict-origin-when-cross-origin  # Balanced approach
Referrer-Policy: same-origin  # Only send to same origin`,
    reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
  },

  "permissions-policy": {
    title: "Set Permissions Policy",
    description:
      "Permissions-Policy (formerly Feature-Policy) allows you to control which browser features can be used on your site, reducing the attack surface.",
    whyItMatters: "Third-party scripts embedded on your page could silently access the camera, microphone, or location. This header explicitly disables sensitive browser APIs you don't need, preventing malicious scripts from abusing them.",
    severity: "medium",
    impactScore: 5,
    apache: `# Add to .htaccess
Header set Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"`,
    nginx: `# Add to nginx.conf
add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()" always;`,
    example: `# Customize based on features you need:
Permissions-Policy: camera=(), microphone=(), geolocation=(self)
# Only allow geolocation for same origin, disable camera/mic`,
    reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
  },

  "ssl-expiring-soon": {
    title: "Renew SSL Certificate",
    description:
      "Your SSL certificate is expiring soon. An expired certificate will cause browser warnings and loss of user trust. Renew immediately to maintain secure connections.",
    whyItMatters: "When your certificate expires, browsers show full-page security warnings that block users from accessing your site. This destroys user trust and can cause immediate revenue loss. Many users will never return.",
    severity: "critical",
    impactScore: 10,
    example: `# Using certbot (Let's Encrypt):
sudo certbot renew

# Check expiry:
openssl x509 -enddate -noout -in /path/to/certificate.crt

# Auto-renew cron job:
0 0 1 * * /usr/bin/certbot renew --quiet`,
    reference: "https://letsencrypt.org/docs/",
  },

  "ssl-invalid": {
    title: "Fix SSL/TLS Configuration",
    description:
      "Your site is not using HTTPS or has an invalid SSL certificate. This exposes all traffic to interception and severely damages user trust.",
    whyItMatters: "Without HTTPS, everything users send—passwords, credit cards, personal data—is transmitted in plain text. Anyone on the same network (coffee shop WiFi, hotel, airport) can intercept and steal this data. Modern browsers also penalize HTTP sites in search rankings.",
    severity: "critical",
    impactScore: 10,
    example: `# Install free SSL with Let's Encrypt:
sudo apt install certbot
sudo certbot --nginx  # or --apache

# Verify installation:
curl -vI https://yoursite.com 2>&1 | grep -i "ssl certificate"`,
    reference: "https://letsencrypt.org/getting-started/",
  },

  "outdated-cms": {
    title: "Update CMS to Latest Version",
    description:
      "Running an outdated CMS is a major security risk. Attackers actively exploit known vulnerabilities in older versions. Update immediately.",
    whyItMatters: "CMS platforms like WordPress are targeted by automated botnets scanning for known vulnerabilities. Thousands of sites are compromised daily. Attackers can inject malware, steal data, or use your server for further attacks—often without you knowing.",
    severity: "high",
    impactScore: 8,
    example: `# WordPress update:
wp core update
wp plugin update --all
wp theme update --all

# Drupal update:
composer update drupal/core --with-dependencies
drush updatedb

# Joomla update:
Use the Joomla Update component in admin panel`,
    reference: "https://owasp.org/www-project-web-security-testing-guide/",
  },
};

/**
 * Build fix recommendations based on scan findings
 */
export function buildFixes(
  missingHeaders: string[],
  sslValid: boolean,
  sslDaysLeft: number | null,
  detectedCms: string | null
): FixSnippet[] {
  const fixes: FixSnippet[] = [];

  // Add fixes for missing headers
  for (const header of missingHeaders) {
    const headerLower = header.toLowerCase();
    if (FIX_SNIPPETS[headerLower]) {
      fixes.push(FIX_SNIPPETS[headerLower]);
    }
  }

  // Add SSL-related fixes
  if (!sslValid) {
    fixes.unshift(FIX_SNIPPETS["ssl-invalid"]);
  } else if (sslDaysLeft !== null && sslDaysLeft < 30) {
    fixes.unshift(FIX_SNIPPETS["ssl-expiring-soon"]);
  }

  // Add CMS-related fixes
  if (detectedCms && ["WordPress", "Drupal", "Joomla"].includes(detectedCms)) {
    fixes.push({
      ...FIX_SNIPPETS["outdated-cms"],
      title: `Keep ${detectedCms} Updated`,
      description: `${detectedCms} sites are frequently targeted by attackers. Ensure you're running the latest version with all security patches applied.`,
      whyItMatters: `${detectedCms} is one of the most targeted platforms by hackers. Automated bots continuously scan for known vulnerabilities in outdated installations. A compromised CMS can lead to data theft, malware distribution, and SEO spam injection.`,
    });
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  fixes.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return fixes;
}
