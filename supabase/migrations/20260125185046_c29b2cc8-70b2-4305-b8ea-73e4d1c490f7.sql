-- Update detect_security_changes function to add SSL expiry monitoring
CREATE OR REPLACE FUNCTION public.detect_security_changes()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_previous_scan RECORD;
    v_scheduled_scan_id UUID;
    v_ssl_days_left INTEGER;
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

    -- Calculate SSL days left from raw_results if available
    v_ssl_days_left := (NEW.raw_results->>'ssl_days_left')::INTEGER;

    -- Alert: SSL certificate expiring soon (within 30 days)
    IF NEW.ssl_valid = true AND v_ssl_days_left IS NOT NULL AND v_ssl_days_left <= 30 THEN
        -- Check if we already have an active alert for this
        IF NOT EXISTS (
            SELECT 1 FROM public.security_alerts
            WHERE user_id = NEW.user_id
              AND alert_type = 'ssl_expiring'
              AND is_dismissed = false
              AND created_at > NOW() - INTERVAL '24 hours'
              AND description LIKE '%' || NEW.target_url || '%'
        ) THEN
            INSERT INTO public.security_alerts (
                user_id, scan_id, scheduled_scan_id, alert_type, severity,
                title, description, previous_value, current_value
            ) VALUES (
                NEW.user_id, NEW.id, v_scheduled_scan_id, 'ssl_expiring',
                CASE 
                    WHEN v_ssl_days_left <= 7 THEN 'critical'
                    WHEN v_ssl_days_left <= 14 THEN 'high'
                    ELSE 'medium'
                END,
                'SSL Certificate Expiring Soon',
                'SSL certificate for ' || NEW.target_url || ' expires in ' || v_ssl_days_left || ' days',
                NULL,
                v_ssl_days_left::TEXT || ' days remaining'
            );
        END IF;
    END IF;

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
    IF array_length(NEW.missing_headers, 1) > COALESCE(array_length(v_previous_scan.missing_headers, 1), 0) THEN
        INSERT INTO public.security_alerts (
            user_id, scan_id, scheduled_scan_id, alert_type, severity,
            title, description, previous_value, current_value
        ) VALUES (
            NEW.user_id, NEW.id, v_scheduled_scan_id, 'config_drift', 'high',
            'Configuration Drift Detected',
            'Security headers were removed from ' || NEW.target_url || '. This may indicate a server misconfiguration.',
            COALESCE(array_length(v_previous_scan.missing_headers, 1), 0)::text || ' missing headers',
            array_length(NEW.missing_headers, 1)::text || ' missing headers'
        );
    END IF;

    RETURN NEW;
END;
$$;

-- Add email_notifications column to profiles if not exists
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_schema = 'public' 
                   AND table_name = 'profiles' 
                   AND column_name = 'email_notifications') THEN
        ALTER TABLE public.profiles ADD COLUMN email_notifications BOOLEAN NOT NULL DEFAULT true;
    END IF;
END $$;

-- Add email_sent column to security_alerts to track which alerts have been emailed
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_schema = 'public' 
                   AND table_name = 'security_alerts' 
                   AND column_name = 'email_sent') THEN
        ALTER TABLE public.security_alerts ADD COLUMN email_sent BOOLEAN NOT NULL DEFAULT false;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_schema = 'public' 
                   AND table_name = 'security_alerts' 
                   AND column_name = 'email_sent_at') THEN
        ALTER TABLE public.security_alerts ADD COLUMN email_sent_at TIMESTAMP WITH TIME ZONE;
    END IF;
END $$;