
-- Cloud security scans table
CREATE TABLE public.cloud_scans (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  scan_type TEXT NOT NULL, -- 'infrastructure', 'storage', 'api', 'deployment'
  target_url TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  risk_level TEXT,
  risk_score INTEGER,
  findings JSONB DEFAULT '[]'::jsonb,
  summary JSONB DEFAULT '{}'::jsonb,
  scan_duration_ms INTEGER,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.cloud_scans ENABLE ROW LEVEL SECURITY;

-- Users can view own cloud scans
CREATE POLICY "Users can view own cloud scans"
ON public.cloud_scans FOR SELECT
TO authenticated
USING (auth.uid() = user_id);

-- Users can create own cloud scans
CREATE POLICY "Users can create own cloud scans"
ON public.cloud_scans FOR INSERT
TO authenticated
WITH CHECK (auth.uid() = user_id);

-- Users can update own cloud scans
CREATE POLICY "Users can update own cloud scans"
ON public.cloud_scans FOR UPDATE
TO authenticated
USING (auth.uid() = user_id);

-- Users can delete own cloud scans
CREATE POLICY "Users can delete own cloud scans"
ON public.cloud_scans FOR DELETE
TO authenticated
USING (auth.uid() = user_id);

-- Owner can view all cloud scans
CREATE POLICY "Owner can view all cloud scans"
ON public.cloud_scans FOR SELECT
TO authenticated
USING (public.has_role(auth.uid(), 'owner'::app_role));
