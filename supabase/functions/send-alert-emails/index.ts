/**
 * Send Alert Emails - Email Notification Service
 * 
 * This edge function sends email notifications for critical security alerts.
 * It's triggered by the scheduled-scan-runner or can be called directly.
 * 
 * Requires RESEND_API_KEY secret to be configured.
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { Resend } from "https://esm.sh/resend@2.0.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
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
  created_at: string;
}

interface UserProfile {
  id: string;
  email: string;
  full_name: string | null;
  email_notifications: boolean;
}

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

function buildEmailHtml(alert: SecurityAlert, userName: string): string {
  const severityColor = getSeverityColor(alert.severity);
  const severityEmoji = getSeverityEmoji(alert.severity);
  
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Alert - SecureScan</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0a0a0a; color: #ffffff;">
  <div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
    <!-- Header -->
    <div style="text-align: center; margin-bottom: 40px;">
      <div style="display: inline-flex; align-items: center; gap: 10px;">
        <div style="width: 40px; height: 40px; background: linear-gradient(135deg, #6366f1, #8b5cf6); border-radius: 12px; display: flex; align-items: center; justify-content: center;">
          <span style="font-size: 20px;">🛡️</span>
        </div>
        <span style="font-size: 24px; font-weight: bold; background: linear-gradient(90deg, #6366f1, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">SecureScan</span>
      </div>
    </div>
    
    <!-- Alert Card -->
    <div style="background: #1a1a1a; border: 1px solid #333; border-radius: 12px; padding: 24px; border-left: 4px solid ${severityColor};">
      <div style="margin-bottom: 16px;">
        <span style="display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; background: ${severityColor}20; color: ${severityColor}; border: 1px solid ${severityColor}40;">
          ${severityEmoji} ${alert.severity}
        </span>
      </div>
      
      <h2 style="margin: 0 0 12px 0; font-size: 20px; color: #ffffff;">${alert.title}</h2>
      
      ${alert.description ? `<p style="margin: 0 0 20px 0; color: #a1a1aa; font-size: 14px; line-height: 1.6;">${alert.description}</p>` : ''}
      
      ${alert.previous_value || alert.current_value ? `
      <div style="background: #0a0a0a; border-radius: 8px; padding: 16px; margin-top: 16px;">
        <table style="width: 100%; border-collapse: collapse;">
          ${alert.previous_value ? `
          <tr>
            <td style="padding: 8px 0; color: #71717a; font-size: 13px; width: 100px;">Previous:</td>
            <td style="padding: 8px 0; color: #fafafa; font-size: 13px; font-family: monospace;">${alert.previous_value}</td>
          </tr>
          ` : ''}
          ${alert.current_value ? `
          <tr>
            <td style="padding: 8px 0; color: #71717a; font-size: 13px; width: 100px;">Current:</td>
            <td style="padding: 8px 0; color: ${severityColor}; font-size: 13px; font-family: monospace;">${alert.current_value}</td>
          </tr>
          ` : ''}
        </table>
      </div>
      ` : ''}
    </div>
    
    <!-- CTA Button -->
    <div style="text-align: center; margin-top: 32px;">
      <a href="https://securescan.app/dashboard" 
         style="display: inline-block; padding: 14px 28px; background: linear-gradient(135deg, #6366f1, #8b5cf6); color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 14px;">
        View Dashboard
      </a>
    </div>
    
    <!-- Footer -->
    <div style="margin-top: 48px; text-align: center; color: #71717a; font-size: 12px;">
      <p style="margin: 0 0 8px 0;">You're receiving this because you have email notifications enabled for SecureScan.</p>
      <p style="margin: 0;">To manage your notification preferences, visit your dashboard settings.</p>
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
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: corsHeaders,
    });
  }

  // Check for Resend API key
  const resendApiKey = Deno.env.get("RESEND_API_KEY");
  if (!resendApiKey) {
    console.log("[EMAIL] RESEND_API_KEY not configured, skipping email notifications");
    return new Response(JSON.stringify({ 
      success: false, 
      message: "Email service not configured",
      emails_sent: 0 
    }), {
      status: 200,
      headers: corsHeaders,
    });
  }

  const resend = new Resend(resendApiKey);
  const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
  const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const serviceClient = createClient(supabaseUrl, supabaseServiceKey);

  console.log("[EMAIL] Starting alert email processor...");

  try {
    // Find alerts that need to be emailed (critical/high severity, not yet sent)
    const { data: pendingAlerts, error: alertError } = await serviceClient
      .from("security_alerts")
      .select("*")
      .in("severity", ["critical", "high"])
      .eq("email_sent", false)
      .eq("is_dismissed", false)
      .order("created_at", { ascending: false })
      .limit(50);

    if (alertError) {
      console.error("[EMAIL] Error fetching alerts:", alertError.message);
      return new Response(JSON.stringify({ error: "Failed to fetch alerts" }), {
        status: 500,
        headers: corsHeaders,
      });
    }

    if (!pendingAlerts || pendingAlerts.length === 0) {
      console.log("[EMAIL] No pending alerts to send");
      return new Response(JSON.stringify({ 
        success: true, 
        message: "No pending alerts",
        emails_sent: 0 
      }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    console.log(`[EMAIL] Found ${pendingAlerts.length} alerts to process`);

    // Group alerts by user
    const alertsByUser = new Map<string, SecurityAlert[]>();
    for (const alert of pendingAlerts as SecurityAlert[]) {
      const existing = alertsByUser.get(alert.user_id) || [];
      existing.push(alert);
      alertsByUser.set(alert.user_id, existing);
    }

    let emailsSent = 0;
    const results: { userId: string; success: boolean; error?: string }[] = [];

    // Process each user's alerts
    for (const [userId, userAlerts] of alertsByUser) {
      try {
        // Get user profile with email preferences
        const { data: profile, error: profileError } = await serviceClient
          .from("profiles")
          .select("id, email, full_name, email_notifications")
          .eq("id", userId)
          .single();

        if (profileError || !profile) {
          console.log(`[EMAIL] Could not find profile for user ${userId}`);
          results.push({ userId, success: false, error: "Profile not found" });
          continue;
        }

        const userProfile = profile as UserProfile;

        // Check if user has email notifications enabled
        if (!userProfile.email_notifications) {
          console.log(`[EMAIL] User ${userId} has notifications disabled`);
          // Mark alerts as "sent" to avoid retrying
          await serviceClient
            .from("security_alerts")
            .update({ email_sent: true, email_sent_at: new Date().toISOString() })
            .in("id", userAlerts.map(a => a.id));
          results.push({ userId, success: true, error: "Notifications disabled" });
          continue;
        }

        // Send one email per critical alert, batch medium alerts
        for (const alert of userAlerts) {
          const userName = userProfile.full_name || "there";
          const emailHtml = buildEmailHtml(alert, userName);

          const { data: emailData, error: emailError } = await resend.emails.send({
            from: "SecureScan Alerts <alerts@securescan.app>",
            to: [userProfile.email],
            subject: `${getSeverityEmoji(alert.severity)} ${alert.title}`,
            html: emailHtml,
          });

          if (emailError) {
            console.error(`[EMAIL] Failed to send email to ${userProfile.email}:`, emailError);
            results.push({ userId, success: false, error: emailError.message });
            continue;
          }

          console.log(`[EMAIL] Sent alert email to ${userProfile.email}`);

          // Mark alert as sent
          await serviceClient
            .from("security_alerts")
            .update({ email_sent: true, email_sent_at: new Date().toISOString() })
            .eq("id", alert.id);

          emailsSent++;
        }

        results.push({ userId, success: true });

      } catch (userError) {
        const errorMessage = userError instanceof Error ? userError.message : "Unknown error";
        console.error(`[EMAIL] Error processing user ${userId}:`, errorMessage);
        results.push({ userId, success: false, error: errorMessage });
      }
    }

    console.log(`[EMAIL] Completed. Sent ${emailsSent} emails`);

    return new Response(JSON.stringify({
      success: true,
      message: `Processed ${pendingAlerts.length} alerts`,
      emails_sent: emailsSent,
      results,
    }), {
      status: 200,
      headers: corsHeaders,
    });

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error("[EMAIL] Fatal error:", errorMessage);
    return new Response(JSON.stringify({ error: "Email processor failed", details: errorMessage }), {
      status: 500,
      headers: corsHeaders,
    });
  }
});
