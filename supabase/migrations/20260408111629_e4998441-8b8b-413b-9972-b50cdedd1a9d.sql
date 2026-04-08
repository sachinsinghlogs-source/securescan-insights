
-- Create vapt_reports table
CREATE TABLE public.vapt_reports (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  pipeline_id UUID REFERENCES public.cloud_scan_pipelines(id) ON DELETE CASCADE NOT NULL,
  user_id UUID NOT NULL,
  target_url TEXT NOT NULL,
  executive_summary TEXT,
  owasp_mapping JSONB DEFAULT '{}'::jsonb,
  attack_surface_score INTEGER DEFAULT 0,
  compliance_flags JSONB DEFAULT '{}'::jsonb,
  remediation_priority JSONB DEFAULT '[]'::jsonb,
  total_findings INTEGER DEFAULT 0,
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  low_count INTEGER DEFAULT 0,
  info_count INTEGER DEFAULT 0,
  overall_risk_score INTEGER DEFAULT 0,
  overall_risk_level TEXT,
  scan_duration_ms INTEGER,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Update cloud_scan_pipelines default total_stages to 10
ALTER TABLE public.cloud_scan_pipelines ALTER COLUMN total_stages SET DEFAULT 10;

-- Enable RLS
ALTER TABLE public.vapt_reports ENABLE ROW LEVEL SECURITY;

-- RLS policies
CREATE POLICY "Users can view own VAPT reports" ON public.vapt_reports FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "Users can create own VAPT reports" ON public.vapt_reports FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can delete own VAPT reports" ON public.vapt_reports FOR DELETE TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "Owner can view all VAPT reports" ON public.vapt_reports FOR SELECT TO authenticated USING (has_role(auth.uid(), 'owner'::app_role));
