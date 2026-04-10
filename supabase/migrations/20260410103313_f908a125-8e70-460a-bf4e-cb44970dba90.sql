ALTER TABLE public.vapt_reports ADD COLUMN IF NOT EXISTS mitre_mapping jsonb DEFAULT '{}'::jsonb;
ALTER TABLE public.vapt_reports ADD COLUMN IF NOT EXISTS attack_paths jsonb DEFAULT '[]'::jsonb;
ALTER TABLE public.vapt_reports ADD COLUMN IF NOT EXISTS business_risk jsonb DEFAULT '{}'::jsonb;