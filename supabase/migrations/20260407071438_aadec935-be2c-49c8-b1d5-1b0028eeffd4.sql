
-- Cloud scan pipelines table - tracks full pipeline runs across all 4 scan types
CREATE TABLE public.cloud_scan_pipelines (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  target_url TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  overall_risk_level TEXT,
  overall_risk_score INTEGER,
  total_findings INTEGER DEFAULT 0,
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  low_count INTEGER DEFAULT 0,
  info_count INTEGER DEFAULT 0,
  completed_stages TEXT[] DEFAULT '{}',
  total_stages INTEGER DEFAULT 4,
  scan_duration_ms INTEGER,
  webhook_trigger BOOLEAN DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  completed_at TIMESTAMP WITH TIME ZONE
);

-- Add pipeline_id to cloud_scans
ALTER TABLE public.cloud_scans ADD COLUMN pipeline_id UUID REFERENCES public.cloud_scan_pipelines(id) ON DELETE CASCADE;

-- Scheduled cloud scans table
CREATE TABLE public.scheduled_cloud_scans (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  target_url TEXT NOT NULL,
  scan_frequency TEXT NOT NULL DEFAULT 'daily',
  is_active BOOLEAN NOT NULL DEFAULT true,
  last_pipeline_id UUID REFERENCES public.cloud_scan_pipelines(id),
  next_scan_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- RLS for cloud_scan_pipelines
ALTER TABLE public.cloud_scan_pipelines ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own pipelines" ON public.cloud_scan_pipelines FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "Users can create own pipelines" ON public.cloud_scan_pipelines FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update own pipelines" ON public.cloud_scan_pipelines FOR UPDATE TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "Users can delete own pipelines" ON public.cloud_scan_pipelines FOR DELETE TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "Owner can view all pipelines" ON public.cloud_scan_pipelines FOR SELECT TO authenticated USING (has_role(auth.uid(), 'owner'::app_role));

-- RLS for scheduled_cloud_scans
ALTER TABLE public.scheduled_cloud_scans ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own scheduled cloud scans" ON public.scheduled_cloud_scans FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "Users can create own scheduled cloud scans" ON public.scheduled_cloud_scans FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update own scheduled cloud scans" ON public.scheduled_cloud_scans FOR UPDATE TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "Users can delete own scheduled cloud scans" ON public.scheduled_cloud_scans FOR DELETE TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "Owner can view all scheduled cloud scans" ON public.scheduled_cloud_scans FOR SELECT TO authenticated USING (has_role(auth.uid(), 'owner'::app_role));
