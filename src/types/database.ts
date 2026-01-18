export interface Profile {
  id: string;
  email: string;
  full_name: string | null;
  plan_type: 'free' | 'pro';
  daily_scans_used: number;
  last_scan_date: string | null;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: string;
  user_id: string;
  target_url: string;
  status: 'pending' | 'scanning' | 'completed' | 'failed';
  risk_level: 'low' | 'medium' | 'high' | 'critical' | null;
  risk_score: number | null;
  ssl_valid: boolean | null;
  ssl_expiry_date: string | null;
  ssl_issuer: string | null;
  headers_score: number | null;
  missing_headers: string[] | null;
  present_headers: string[] | null;
  detected_technologies: string[] | null;
  detected_cms: string | null;
  server_info: string | null;
  scan_duration_ms: number | null;
  raw_results: Record<string, unknown> | null;
  created_at: string;
  completed_at: string | null;
}
