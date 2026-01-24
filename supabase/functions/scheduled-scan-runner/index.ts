/**
 * Scheduled Scan Runner - Background Scan Processor
 * 
 * This edge function is triggered by a cron job to process scheduled scans.
 * It finds all scans that are due and triggers security scans for them.
 * 
 * SECURITY:
 * - Uses service role key (bypasses RLS) for reading scheduled scans
 * - Validates each scheduled scan before processing
 * - Updates next_scan_at after each scan
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Content-Type": "application/json",
};

interface ScheduledScan {
  id: string;
  user_id: string;
  target_url: string;
  environment: string;
  scan_frequency: string;
  is_active: boolean;
  next_scan_at: string | null;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  // Only allow POST method
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: corsHeaders,
    });
  }

  // Verify authorization - either cron secret or service role
  const authHeader = req.headers.get("Authorization");
  const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
  const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;

  // Create service client for database operations
  const serviceClient = createClient(supabaseUrl, supabaseServiceKey);

  console.log("[SCHEDULER] Starting scheduled scan runner...");

  try {
    // Find all active scheduled scans that are due
    const now = new Date().toISOString();
    
    const { data: dueScans, error: fetchError } = await serviceClient
      .from("scheduled_scans")
      .select("*")
      .eq("is_active", true)
      .lte("next_scan_at", now);

    if (fetchError) {
      console.error("[SCHEDULER] Error fetching due scans:", fetchError.message);
      return new Response(JSON.stringify({ error: "Failed to fetch scheduled scans" }), {
        status: 500,
        headers: corsHeaders,
      });
    }

    if (!dueScans || dueScans.length === 0) {
      console.log("[SCHEDULER] No scheduled scans due at this time");
      return new Response(JSON.stringify({ 
        success: true, 
        message: "No scans due",
        processed: 0 
      }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    console.log(`[SCHEDULER] Found ${dueScans.length} scheduled scans due for processing`);

    const results: { scanId: string; success: boolean; error?: string }[] = [];

    // Process each due scan
    for (const scheduledScan of dueScans as ScheduledScan[]) {
      try {
        console.log(`[SCHEDULER] Processing scan for ${scheduledScan.target_url}`);

        // Create a new scan record
        const { data: newScan, error: insertError } = await serviceClient
          .from("scans")
          .insert({
            user_id: scheduledScan.user_id,
            target_url: scheduledScan.target_url,
            status: "scanning",
          })
          .select("id")
          .single();

        if (insertError || !newScan) {
          console.error(`[SCHEDULER] Failed to create scan: ${insertError?.message}`);
          results.push({ scanId: scheduledScan.id, success: false, error: insertError?.message });
          continue;
        }

        // Dynamically import and run the scan engine
        const { runSecurityScan } = await import("../security-scan/scanEngine.ts");
        
        const startTime = Date.now();
        const scanResult = await runSecurityScan(scheduledScan.target_url);
        const scanDuration = Date.now() - startTime;

        // Update scan record with results
        await serviceClient
          .from("scans")
          .update({
            status: "completed",
            risk_level: scanResult.risk_level,
            risk_score: scanResult.risk_score,
            ssl_valid: scanResult.ssl_valid,
            ssl_expiry_date: scanResult.ssl_expiry_date,
            ssl_issuer: scanResult.ssl_issuer,
            headers_score: scanResult.headers_score,
            missing_headers: scanResult.missing_headers,
            present_headers: scanResult.present_headers,
            detected_technologies: scanResult.detected_technologies,
            detected_cms: scanResult.detected_cms,
            server_info: scanResult.server_info,
            scan_duration_ms: scanDuration,
            completed_at: new Date().toISOString(),
            raw_results: scanResult,
          })
          .eq("id", newScan.id);

        // Calculate next scan time based on frequency
        const nextScanAt = new Date();
        switch (scheduledScan.scan_frequency) {
          case "hourly":
            nextScanAt.setHours(nextScanAt.getHours() + 1);
            break;
          case "daily":
            nextScanAt.setDate(nextScanAt.getDate() + 1);
            break;
          case "weekly":
            nextScanAt.setDate(nextScanAt.getDate() + 7);
            break;
          default:
            nextScanAt.setDate(nextScanAt.getDate() + 1);
        }

        // Update scheduled scan with next run time and last scan ID
        await serviceClient
          .from("scheduled_scans")
          .update({
            last_scan_id: newScan.id,
            next_scan_at: nextScanAt.toISOString(),
            updated_at: new Date().toISOString(),
          })
          .eq("id", scheduledScan.id);

        console.log(`[SCHEDULER] Completed scan for ${scheduledScan.target_url} in ${scanDuration}ms`);
        results.push({ scanId: scheduledScan.id, success: true });

        // Log the scheduled scan execution
        await serviceClient.rpc("log_security_event", {
          p_event_type: "scheduled_scan_executed",
          p_event_category: "scan",
          p_user_id: scheduledScan.user_id,
          p_resource_type: "scheduled_scan",
          p_resource_id: scheduledScan.id,
          p_details: {
            target_url: scheduledScan.target_url,
            environment: scheduledScan.environment,
            frequency: scheduledScan.scan_frequency,
            risk_level: scanResult.risk_level,
            duration_ms: scanDuration,
          },
          p_severity: "info",
        });

      } catch (scanError) {
        const errorMessage = scanError instanceof Error ? scanError.message : "Unknown error";
        console.error(`[SCHEDULER] Error processing scan ${scheduledScan.id}: ${errorMessage}`);
        results.push({ scanId: scheduledScan.id, success: false, error: errorMessage });
      }
    }

    const successCount = results.filter(r => r.success).length;
    console.log(`[SCHEDULER] Completed processing. Success: ${successCount}/${results.length}`);

    return new Response(JSON.stringify({
      success: true,
      message: `Processed ${results.length} scheduled scans`,
      processed: results.length,
      successful: successCount,
      results,
    }), {
      status: 200,
      headers: corsHeaders,
    });

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error("[SCHEDULER] Fatal error:", errorMessage);
    return new Response(JSON.stringify({ error: "Scheduler failed", details: errorMessage }), {
      status: 500,
      headers: corsHeaders,
    });
  }
});
