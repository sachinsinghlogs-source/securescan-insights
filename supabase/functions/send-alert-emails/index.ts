/**
 * Send Alert Emails - Preference-Aware Email Notification Service
 * 
 * Checks per-alert-type preferences before sending.
 * Batches multiple alerts for the same domain into a single digest email.
 * Includes improvement alerts in a separate section.
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { Resend } from "https://esm.sh/resend@2.0.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
  "Content-Type": "application/json",
};

interface SecurityAlert {
  id: string;
  user_id: string;
  alert_type: string;
  severity: string;
  title: string;
  description: string | null;
  previous_value: string | null;
  current_value: string | null;
  target_url: string | null;
  created_at: string;
}

interface AlertPreference {
  alert_type: string;
  enabled: boolean;
  min_severity: string;
  cooldown_hours: number;
}

interface UserProfile {
  id: string;
  email: string;
  full_name: string | null;
  email_notifications: boolean;
}

const IMPROVEMENT_TYPES = ['risk_decreased', 'ssl_restored', 'headers_improved'];

const SEVERITY_RANK: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };

function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical': return '#dc2626';
    case 'high': return '#ea580c';
    case 'medium': return '#ca8a04';
    default: return '#2563eb';
  }
}

function getSeverityEmoji(severity: string): string {
  switch (severity) {
    case 'critical': return '🚨';
    case 'high': return '⚠️';
    case 'medium': return '⚡';
    default: return 'ℹ️';
  }
}

function buildAlertRow(alert: SecurityAlert): string {
  const isImprovement = IMPROVEMENT_TYPES.includes(alert.alert_type);
  const color = isImprovement ? '#22c55e' : getSeverityColor(alert.severity);
  const emoji = isImprovement ? '✅' : getSeverityEmoji(alert.severity);

  return `
    <tr>
      <td style="padding: 12px; border-bottom: 1px solid #333;">
        <span style="color: ${color}; font-weight: 600;">${emoji} ${alert.title}</span>
        ${alert.description ? `<br><span style="color: #a1a1aa; font-size: 13px;">${alert.description}</span>` : ''}
        ${alert.previous_value && alert.current_value ? `
          <br><span style="color: #71717a; font-size: 12px; font-family: monospace;">${alert.previous_value} → <span style="color: ${color};">${alert.current_value}</span></span>
        ` : ''}
      </td>
      <td style="padding: 12px; border-bottom: 1px solid #333; text-align: right; vertical-align: top;">
        <span style="display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; background: ${color}20; color: ${color}; border: 1px solid ${color}40;">
          ${isImprovement ? 'improvement' : alert.severity}
        </span>
      </td>
    </tr>
  `;
}

function buildDigestEmail(
  userName: string,
  domainAlerts: Map<string, SecurityAlert[]>,
): string {
  let domainSections = '';

  for (const [domain, alerts] of domainAlerts) {
    const regressions = alerts.filter(a => !IMPROVEMENT_TYPES.includes(a.alert_type));
    const improvements = alerts.filter(a => IMPROVEMENT_TYPES.includes(a.alert_type));

    let rows = '';
    if (regressions.length > 0) {
      rows += regressions.map(buildAlertRow).join('');
    }
    if (improvements.length > 0) {
      rows += `
        <tr><td colspan="2" style="padding: 8px 12px; background: #0d2818; color: #22c55e; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">
          Improvements
        </td></tr>
      `;
      rows += improvements.map(buildAlertRow).join('');
    }

    domainSections += `
      <div style="margin-bottom: 24px;">
        <h3 style="margin: 0 0 8px 0; font-size: 16px; color: #fafafa;">🌐 ${domain}</h3>
        <table style="width: 100%; border-collapse: collapse; background: #1a1a1a; border-radius: 8px; overflow: hidden; border: 1px solid #333;">
          ${rows}
        </table>
      </div>
    `;
  }

  return `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0a0a0a; color: #ffffff;">
  <div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
    <div style="text-align: center; margin-bottom: 40px;">
      <div style="display: inline-flex; align-items: center; gap: 10px;">
        <span style="font-size: 24px; font-weight: bold; background: linear-gradient(90deg, #6366f1, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">SecureScan Digest</span>
      </div>
      <p style="color: #71717a; font-size: 14px; margin-top: 8px;">Hi ${userName}, here are your latest security alerts.</p>
    </div>

    ${domainSections}

    <div style="text-align: center; margin-top: 32px;">
      <a href="https://securescan.app/dashboard" style="display: inline-block; padding: 14px 28px; background: linear-gradient(135deg, #6366f1, #8b5cf6); color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 14px;">
        View Dashboard
      </a>
    </div>

    <div style="margin-top: 48px; text-align: center; color: #71717a; font-size: 12px;">
      <p>You're receiving this because you have email notifications enabled.</p>
      <p>Manage preferences in your dashboard settings.</p>
    </div>
  </div>
</body>
</html>
  `;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers: corsHeaders });
  }

  const resendApiKey = Deno.env.get("RESEND_API_KEY");
  if (!resendApiKey) {
    console.log("[EMAIL] RESEND_API_KEY not configured, skipping");
    return new Response(JSON.stringify({ success: false, message: "Email service not configured", emails_sent: 0 }), {
      status: 200, headers: corsHeaders,
    });
  }

  const resend = new Resend(resendApiKey);
  const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
  const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const serviceClient = createClient(supabaseUrl, supabaseServiceKey);

  console.log("[EMAIL] Starting preference-aware alert email processor...");

  try {
    // Fetch unsent alerts (include all severities now — preferences decide)
    const { data: pendingAlerts, error: alertError } = await serviceClient
      .from("security_alerts")
      .select("*")
      .eq("email_sent", false)
      .eq("is_dismissed", false)
      .order("created_at", { ascending: false })
      .limit(100);

    if (alertError) {
      console.error("[EMAIL] Error fetching alerts:", alertError.message);
      return new Response(JSON.stringify({ error: "Failed to fetch alerts" }), { status: 500, headers: corsHeaders });
    }

    if (!pendingAlerts || pendingAlerts.length === 0) {
      console.log("[EMAIL] No pending alerts");
      return new Response(JSON.stringify({ success: true, message: "No pending alerts", emails_sent: 0 }), {
        status: 200, headers: corsHeaders,
      });
    }

    console.log(`[EMAIL] Found ${pendingAlerts.length} alerts to process`);

    // Group by user
    const alertsByUser = new Map<string, SecurityAlert[]>();
    for (const alert of pendingAlerts as SecurityAlert[]) {
      const existing = alertsByUser.get(alert.user_id) || [];
      existing.push(alert);
      alertsByUser.set(alert.user_id, existing);
    }

    let emailsSent = 0;

    for (const [userId, userAlerts] of alertsByUser) {
      try {
        // Fetch profile + preferences
        const [profileRes, prefsRes] = await Promise.all([
          serviceClient.from("profiles").select("id, email, full_name, email_notifications").eq("id", userId).single(),
          serviceClient.from("alert_preferences").select("*").eq("user_id", userId),
        ]);

        if (profileRes.error || !profileRes.data) {
          console.log(`[EMAIL] Profile not found for ${userId}`);
          continue;
        }

        const profile = profileRes.data as UserProfile;
        if (!profile.email_notifications) {
          console.log(`[EMAIL] Notifications disabled for ${userId}`);
          await serviceClient.from("security_alerts").update({ email_sent: true, email_sent_at: new Date().toISOString() })
            .in("id", userAlerts.map(a => a.id));
          continue;
        }

        // Build preference map
        const prefsMap = new Map<string, AlertPreference>();
        if (!prefsRes.error && prefsRes.data) {
          for (const p of prefsRes.data as AlertPreference[]) {
            prefsMap.set(p.alert_type, p);
          }
        }

        // Filter alerts based on per-type preferences
        const allowedAlerts: SecurityAlert[] = [];
        const skippedIds: string[] = [];

        for (const alert of userAlerts) {
          const pref = prefsMap.get(alert.alert_type);
          const enabled = pref?.enabled ?? true;
          const minSev = pref?.min_severity ?? 'medium';

          if (!enabled) { skippedIds.push(alert.id); continue; }

          // Improvements always pass severity check
          if (!IMPROVEMENT_TYPES.includes(alert.alert_type)) {
            const alertRank = SEVERITY_RANK[alert.severity] ?? 1;
            const minRank = SEVERITY_RANK[minSev] ?? 2;
            if (alertRank < minRank) { skippedIds.push(alert.id); continue; }
          }

          allowedAlerts.push(alert);
        }

        // Mark skipped alerts as sent
        if (skippedIds.length > 0) {
          await serviceClient.from("security_alerts").update({ email_sent: true, email_sent_at: new Date().toISOString() })
            .in("id", skippedIds);
        }

        if (allowedAlerts.length === 0) continue;

        // Group by domain for digest
        const domainAlerts = new Map<string, SecurityAlert[]>();
        for (const alert of allowedAlerts) {
          const domain = alert.target_url || 'Unknown';
          const existing = domainAlerts.get(domain) || [];
          existing.push(alert);
          domainAlerts.set(domain, existing);
        }

        const userName = profile.full_name || "there";
        const emailHtml = buildDigestEmail(userName, domainAlerts);

        const highestSeverity = allowedAlerts.reduce((max, a) => {
          return (SEVERITY_RANK[a.severity] ?? 0) > (SEVERITY_RANK[max] ?? 0) ? a.severity : max;
        }, 'low');

        const subject = allowedAlerts.length === 1
          ? `${getSeverityEmoji(allowedAlerts[0].severity)} ${allowedAlerts[0].title}`
          : `${getSeverityEmoji(highestSeverity)} ${allowedAlerts.length} security alerts for your domains`;

        const { error: emailError } = await resend.emails.send({
          from: "SecureScan Alerts <alerts@securescan.app>",
          to: [profile.email],
          subject,
          html: emailHtml,
        });

        if (emailError) {
          console.error(`[EMAIL] Failed to send to ${profile.email}:`, emailError);
          continue;
        }

        console.log(`[EMAIL] Sent digest email to ${profile.email} (${allowedAlerts.length} alerts)`);
        await serviceClient.from("security_alerts").update({ email_sent: true, email_sent_at: new Date().toISOString() })
          .in("id", allowedAlerts.map(a => a.id));
        emailsSent++;

      } catch (userError) {
        console.error(`[EMAIL] Error for user ${userId}:`, userError instanceof Error ? userError.message : userError);
      }
    }

    console.log(`[EMAIL] Done. Sent ${emailsSent} digest emails`);
    return new Response(JSON.stringify({ success: true, emails_sent: emailsSent }), { status: 200, headers: corsHeaders });

  } catch (error) {
    console.error("[EMAIL] Fatal error:", error instanceof Error ? error.message : error);
    return new Response(JSON.stringify({ error: "Email processor failed" }), { status: 500, headers: corsHeaders });
  }
});
