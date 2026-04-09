ALTER TABLE public.cloud_scan_pipelines ALTER COLUMN total_stages SET DEFAULT 14;

ALTER TABLE public.vapt_reports ADD COLUMN IF NOT EXISTS finding_chains jsonb DEFAULT '[]'::jsonb;