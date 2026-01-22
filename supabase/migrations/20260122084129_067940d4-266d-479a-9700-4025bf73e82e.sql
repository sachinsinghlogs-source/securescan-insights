-- Create environment type enum
CREATE TYPE public.scan_environment AS ENUM ('production', 'staging', 'development');

-- Create scheduled scans table for continuous monitoring
CREATE TABLE public.scheduled_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    target_url TEXT NOT NULL,
    environment scan_environment NOT NULL DEFAULT 'production',
    scan_frequency TEXT NOT NULL DEFAULT 'daily', -- daily, weekly, hourly
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_scan_id UUID REFERENCES public.scans(id),
    next_scan_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create security alerts table
CREATE TABLE public.security_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    scan_id UUID REFERENCES public.scans(id),
    scheduled_scan_id UUID REFERENCES public.scheduled_scans(id),
    alert_type TEXT NOT NULL, -- risk_increased, ssl_expiring, header_removed, config_drift
    severity TEXT NOT NULL DEFAULT 'medium', -- low, medium, high, critical
    title TEXT NOT NULL,
    description TEXT,
    previous_value TEXT,
    current_value TEXT,
    is_read BOOLEAN NOT NULL DEFAULT false,
    is_dismissed BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create risk trends table for tracking score history
CREATE TABLE public.risk_trends (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scheduled_scan_id UUID REFERENCES public.scheduled_scans(id),
    scan_id UUID REFERENCES public.scans(id) NOT NULL,
    user_id UUID NOT NULL,
    target_url TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    ssl_valid BOOLEAN,
    missing_headers_count INTEGER,
    present_headers_count INTEGER,
    recorded_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS on all new tables
ALTER TABLE public.scheduled_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.risk_trends ENABLE ROW LEVEL SECURITY;

-- RLS policies for scheduled_scans
CREATE POLICY "Users can view own scheduled scans"
ON public.scheduled_scans FOR SELECT
USING (auth.uid() = user_id);

CREATE POLICY "Users can create own scheduled scans"
ON public.scheduled_scans FOR INSERT
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own scheduled scans"
ON public.scheduled_scans FOR UPDATE
USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own scheduled scans"
ON public.scheduled_scans FOR DELETE
USING (auth.uid() = user_id);

-- RLS policies for security_alerts
CREATE POLICY "Users can view own alerts"
ON public.security_alerts FOR SELECT
USING (auth.uid() = user_id);

CREATE POLICY "Users can update own alerts"
ON public.security_alerts FOR UPDATE
USING (auth.uid() = user_id);

-- RLS policies for risk_trends
CREATE POLICY "Users can view own risk trends"
ON public.risk_trends FOR SELECT
USING (auth.uid() = user_id);

-- Create indexes for performance
CREATE INDEX idx_scheduled_scans_user_id ON public.scheduled_scans(user_id);
CREATE INDEX idx_scheduled_scans_next_scan ON public.scheduled_scans(next_scan_at) WHERE is_active = true;
CREATE INDEX idx_security_alerts_user_unread ON public.security_alerts(user_id, is_read) WHERE is_dismissed = false;
CREATE INDEX idx_risk_trends_url ON public.risk_trends(target_url, recorded_at);

-- Function to detect security changes and create alerts
CREATE OR REPLACE FUNCTION public.detect_security_changes()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_previous_scan RECORD;
    v_scheduled_scan_id UUID;
BEGIN
    -- Only process completed scans
    IF NEW.status != 'completed' THEN
        RETURN NEW;
    END IF;

    -- Find previous scan for same URL and user
    SELECT * INTO v_previous_scan
    FROM public.scans
    WHERE user_id = NEW.user_id
      AND target_url = NEW.target_url
      AND id != NEW.id
      AND status = 'completed'
    ORDER BY completed_at DESC
    LIMIT 1;

    -- Get scheduled scan if exists
    SELECT id INTO v_scheduled_scan_id
    FROM public.scheduled_scans
    WHERE user_id = NEW.user_id
      AND target_url = NEW.target_url
      AND is_active = true
    LIMIT 1;

    -- Record risk trend
    INSERT INTO public.risk_trends (
        scheduled_scan_id, scan_id, user_id, target_url,
        risk_score, risk_level, ssl_valid,
        missing_headers_count, present_headers_count
    ) VALUES (
        v_scheduled_scan_id, NEW.id, NEW.user_id, NEW.target_url,
        COALESCE(NEW.risk_score, 0), COALESCE(NEW.risk_level, 'unknown'),
        NEW.ssl_valid,
        COALESCE(array_length(NEW.missing_headers, 1), 0),
        COALESCE(array_length(NEW.present_headers, 1), 0)
    );

    -- If no previous scan, no comparison needed
    IF v_previous_scan.id IS NULL THEN
        RETURN NEW;
    END IF;

    -- Alert: Risk level increased
    IF NEW.risk_level != v_previous_scan.risk_level AND
       (NEW.risk_level = 'high' OR NEW.risk_level = 'critical' OR
        (NEW.risk_level = 'medium' AND v_previous_scan.risk_level = 'low')) THEN
        INSERT INTO public.security_alerts (
            user_id, scan_id, scheduled_scan_id, alert_type, severity,
            title, description, previous_value, current_value
        ) VALUES (
            NEW.user_id, NEW.id, v_scheduled_scan_id, 'risk_increased',
            CASE WHEN NEW.risk_level = 'critical' THEN 'critical'
                 WHEN NEW.risk_level = 'high' THEN 'high'
                 ELSE 'medium' END,
            'Risk Level Increased',
            'Security risk level has increased for ' || NEW.target_url,
            v_previous_scan.risk_level,
            NEW.risk_level
        );
    END IF;

    -- Alert: SSL became invalid
    IF v_previous_scan.ssl_valid = true AND NEW.ssl_valid = false THEN
        INSERT INTO public.security_alerts (
            user_id, scan_id, scheduled_scan_id, alert_type, severity,
            title, description, previous_value, current_value
        ) VALUES (
            NEW.user_id, NEW.id, v_scheduled_scan_id, 'ssl_invalid', 'critical',
            'SSL Certificate Invalid',
            'SSL certificate is no longer valid for ' || NEW.target_url,
            'valid',
            'invalid'
        );
    END IF;

    -- Alert: Security headers removed (config drift)
    IF array_length(NEW.missing_headers, 1) > array_length(v_previous_scan.missing_headers, 1) THEN
        INSERT INTO public.security_alerts (
            user_id, scan_id, scheduled_scan_id, alert_type, severity,
            title, description, previous_value, current_value
        ) VALUES (
            NEW.user_id, NEW.id, v_scheduled_scan_id, 'config_drift', 'high',
            'Configuration Drift Detected',
            'Security headers were removed from ' || NEW.target_url || '. This may indicate a server misconfiguration.',
            array_length(v_previous_scan.missing_headers, 1)::text || ' missing headers',
            array_length(NEW.missing_headers, 1)::text || ' missing headers'
        );
    END IF;

    RETURN NEW;
END;
$$;

-- Create trigger for change detection
CREATE TRIGGER on_scan_completed
    AFTER INSERT OR UPDATE ON public.scans
    FOR EACH ROW
    EXECUTE FUNCTION public.detect_security_changes();

-- Trigger for updated_at on scheduled_scans
CREATE TRIGGER update_scheduled_scans_updated_at
    BEFORE UPDATE ON public.scheduled_scans
    FOR EACH ROW
    EXECUTE FUNCTION public.update_updated_at_column();