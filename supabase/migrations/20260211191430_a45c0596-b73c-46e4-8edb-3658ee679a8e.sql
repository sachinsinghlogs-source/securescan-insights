
-- 1. Create alert_preferences table
CREATE TABLE public.alert_preferences (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  alert_type TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  min_severity TEXT NOT NULL DEFAULT 'medium',
  cooldown_hours INTEGER NOT NULL DEFAULT 24,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id, alert_type)
);

ALTER TABLE public.alert_preferences ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own alert preferences"
  ON public.alert_preferences FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own alert preferences"
  ON public.alert_preferences FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own alert preferences"
  ON public.alert_preferences FOR UPDATE
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own alert preferences"
  ON public.alert_preferences FOR DELETE
  USING (auth.uid() = user_id);

CREATE TRIGGER update_alert_preferences_updated_at
  BEFORE UPDATE ON public.alert_preferences
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- 2. Add target_url to security_alerts
ALTER TABLE public.security_alerts ADD COLUMN target_url TEXT;

-- Backfill target_url from scans
UPDATE public.security_alerts sa
SET target_url = s.target_url
FROM public.scans s
WHERE sa.scan_id = s.id AND sa.target_url IS NULL;

-- 3. Replace detect_security_changes trigger function with smart alerting
CREATE OR REPLACE FUNCTION public.detect_security_changes()
  RETURNS trigger
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public'
AS $function$
DECLARE
    v_previous_scan RECORD;
    v_scheduled_scan_id UUID;
    v_ssl_days_left INTEGER;
    v_pref RECORD;
    v_cooldown_hours INTEGER;
    v_min_severity TEXT;
    v_alert_enabled BOOLEAN;
    v_severity_rank INTEGER;
    v_min_severity_rank INTEGER;
BEGIN
    IF NEW.status != 'completed' THEN
        RETURN NEW;
    END IF;

    -- Find previous completed scan for same URL/user
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

    v_ssl_days_left := (NEW.raw_results->>'ssl_days_left')::INTEGER;

    -- Helper: check if alert should be created based on preferences and cooldown
    -- For each alert type we check:
    -- 1. Is it enabled? (default yes)
    -- 2. Is severity >= min_severity? 
    -- 3. Was a similar alert created within cooldown window?

    -- === SSL EXPIRING ===
    IF NEW.ssl_valid = true AND v_ssl_days_left IS NOT NULL AND v_ssl_days_left <= 30 THEN
        DECLARE
            v_sev TEXT;
        BEGIN
            v_sev := CASE 
                WHEN v_ssl_days_left <= 7 THEN 'critical'
                WHEN v_ssl_days_left <= 14 THEN 'high'
                ELSE 'medium'
            END;

            SELECT enabled, min_severity, cooldown_hours INTO v_alert_enabled, v_min_severity, v_cooldown_hours
            FROM public.alert_preferences
            WHERE user_id = NEW.user_id AND alert_type = 'ssl_expiring';

            -- Defaults if no preference row
            v_alert_enabled := COALESCE(v_alert_enabled, true);
            v_min_severity := COALESCE(v_min_severity, 'medium');
            v_cooldown_hours := COALESCE(v_cooldown_hours, 24);

            IF v_alert_enabled AND
               (CASE v_sev WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) >=
               (CASE v_min_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) AND
               NOT EXISTS (
                   SELECT 1 FROM public.security_alerts
                   WHERE user_id = NEW.user_id AND alert_type = 'ssl_expiring'
                     AND target_url = NEW.target_url AND is_dismissed = false
                     AND created_at > NOW() - (v_cooldown_hours || ' hours')::INTERVAL
               )
            THEN
                INSERT INTO public.security_alerts (
                    user_id, scan_id, scheduled_scan_id, alert_type, severity,
                    title, description, previous_value, current_value, target_url
                ) VALUES (
                    NEW.user_id, NEW.id, v_scheduled_scan_id, 'ssl_expiring', v_sev,
                    'SSL Certificate Expiring Soon',
                    'SSL certificate for ' || NEW.target_url || ' expires in ' || v_ssl_days_left || ' days',
                    NULL, v_ssl_days_left::TEXT || ' days remaining', NEW.target_url
                );
            END IF;
        END;
    END IF;

    -- If no previous scan, skip comparisons but still check for new tech
    IF v_previous_scan.id IS NULL THEN
        -- New technology detection on first scan (skip, nothing to compare)
        RETURN NEW;
    END IF;

    -- === RISK INCREASED ===
    IF NEW.risk_level != v_previous_scan.risk_level AND
       (NEW.risk_level = 'high' OR NEW.risk_level = 'critical' OR
        (NEW.risk_level = 'medium' AND v_previous_scan.risk_level = 'low')) THEN
        DECLARE
            v_sev TEXT;
        BEGIN
            v_sev := CASE WHEN NEW.risk_level = 'critical' THEN 'critical'
                         WHEN NEW.risk_level = 'high' THEN 'high'
                         ELSE 'medium' END;

            SELECT enabled, min_severity, cooldown_hours INTO v_alert_enabled, v_min_severity, v_cooldown_hours
            FROM public.alert_preferences
            WHERE user_id = NEW.user_id AND alert_type = 'risk_increased';

            v_alert_enabled := COALESCE(v_alert_enabled, true);
            v_min_severity := COALESCE(v_min_severity, 'medium');
            v_cooldown_hours := COALESCE(v_cooldown_hours, 24);

            IF v_alert_enabled AND
               (CASE v_sev WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) >=
               (CASE v_min_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) AND
               NOT EXISTS (
                   SELECT 1 FROM public.security_alerts
                   WHERE user_id = NEW.user_id AND alert_type = 'risk_increased'
                     AND target_url = NEW.target_url AND is_dismissed = false
                     AND created_at > NOW() - (v_cooldown_hours || ' hours')::INTERVAL
               )
            THEN
                INSERT INTO public.security_alerts (
                    user_id, scan_id, scheduled_scan_id, alert_type, severity,
                    title, description, previous_value, current_value, target_url
                ) VALUES (
                    NEW.user_id, NEW.id, v_scheduled_scan_id, 'risk_increased', v_sev,
                    'Risk Level Increased',
                    'Security risk level has increased for ' || NEW.target_url,
                    v_previous_scan.risk_level, NEW.risk_level, NEW.target_url
                );
            END IF;
        END;
    END IF;

    -- === RISK DECREASED (improvement) ===
    IF v_previous_scan.risk_level IS NOT NULL AND NEW.risk_level IS NOT NULL AND
       NEW.risk_level != v_previous_scan.risk_level AND
       (v_previous_scan.risk_level = 'high' OR v_previous_scan.risk_level = 'critical' OR
        (v_previous_scan.risk_level = 'medium' AND NEW.risk_level = 'low')) THEN
        INSERT INTO public.security_alerts (
            user_id, scan_id, scheduled_scan_id, alert_type, severity,
            title, description, previous_value, current_value, target_url
        ) VALUES (
            NEW.user_id, NEW.id, v_scheduled_scan_id, 'risk_decreased', 'low',
            'Risk Level Decreased',
            'Security risk level has improved for ' || NEW.target_url,
            v_previous_scan.risk_level, NEW.risk_level, NEW.target_url
        );
    END IF;

    -- === SSL INVALID ===
    IF v_previous_scan.ssl_valid = true AND NEW.ssl_valid = false THEN
        SELECT enabled, min_severity, cooldown_hours INTO v_alert_enabled, v_min_severity, v_cooldown_hours
        FROM public.alert_preferences
        WHERE user_id = NEW.user_id AND alert_type = 'ssl_invalid';

        v_alert_enabled := COALESCE(v_alert_enabled, true);
        v_min_severity := COALESCE(v_min_severity, 'medium');
        v_cooldown_hours := COALESCE(v_cooldown_hours, 24);

        IF v_alert_enabled AND
           4 >= (CASE v_min_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) AND
           NOT EXISTS (
               SELECT 1 FROM public.security_alerts
               WHERE user_id = NEW.user_id AND alert_type = 'ssl_invalid'
                 AND target_url = NEW.target_url AND is_dismissed = false
                 AND created_at > NOW() - (v_cooldown_hours || ' hours')::INTERVAL
           )
        THEN
            INSERT INTO public.security_alerts (
                user_id, scan_id, scheduled_scan_id, alert_type, severity,
                title, description, previous_value, current_value, target_url
            ) VALUES (
                NEW.user_id, NEW.id, v_scheduled_scan_id, 'ssl_invalid', 'critical',
                'SSL Certificate Invalid',
                'SSL certificate is no longer valid for ' || NEW.target_url,
                'valid', 'invalid', NEW.target_url
            );
        END IF;
    END IF;

    -- === SSL RESTORED (improvement) ===
    IF v_previous_scan.ssl_valid = false AND NEW.ssl_valid = true THEN
        INSERT INTO public.security_alerts (
            user_id, scan_id, scheduled_scan_id, alert_type, severity,
            title, description, previous_value, current_value, target_url
        ) VALUES (
            NEW.user_id, NEW.id, v_scheduled_scan_id, 'ssl_restored', 'low',
            'SSL Certificate Restored',
            'SSL certificate has been restored for ' || NEW.target_url,
            'invalid', 'valid', NEW.target_url
        );
    END IF;

    -- === CONFIG DRIFT ===
    IF array_length(NEW.missing_headers, 1) > COALESCE(array_length(v_previous_scan.missing_headers, 1), 0) THEN
        SELECT enabled, min_severity, cooldown_hours INTO v_alert_enabled, v_min_severity, v_cooldown_hours
        FROM public.alert_preferences
        WHERE user_id = NEW.user_id AND alert_type = 'config_drift';

        v_alert_enabled := COALESCE(v_alert_enabled, true);
        v_min_severity := COALESCE(v_min_severity, 'medium');
        v_cooldown_hours := COALESCE(v_cooldown_hours, 24);

        IF v_alert_enabled AND
           3 >= (CASE v_min_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) AND
           NOT EXISTS (
               SELECT 1 FROM public.security_alerts
               WHERE user_id = NEW.user_id AND alert_type = 'config_drift'
                 AND target_url = NEW.target_url AND is_dismissed = false
                 AND created_at > NOW() - (v_cooldown_hours || ' hours')::INTERVAL
           )
        THEN
            INSERT INTO public.security_alerts (
                user_id, scan_id, scheduled_scan_id, alert_type, severity,
                title, description, previous_value, current_value, target_url
            ) VALUES (
                NEW.user_id, NEW.id, v_scheduled_scan_id, 'config_drift', 'high',
                'Configuration Drift Detected',
                'Security headers were removed from ' || NEW.target_url || '. This may indicate a server misconfiguration.',
                COALESCE(array_length(v_previous_scan.missing_headers, 1), 0)::text || ' missing headers',
                array_length(NEW.missing_headers, 1)::text || ' missing headers',
                NEW.target_url
            );
        END IF;
    END IF;

    -- === HEADERS IMPROVED (improvement) ===
    IF COALESCE(array_length(NEW.missing_headers, 1), 0) < COALESCE(array_length(v_previous_scan.missing_headers, 1), 0) THEN
        INSERT INTO public.security_alerts (
            user_id, scan_id, scheduled_scan_id, alert_type, severity,
            title, description, previous_value, current_value, target_url
        ) VALUES (
            NEW.user_id, NEW.id, v_scheduled_scan_id, 'headers_improved', 'low',
            'Security Headers Improved',
            'Security headers have been added to ' || NEW.target_url,
            COALESCE(array_length(v_previous_scan.missing_headers, 1), 0)::text || ' missing headers',
            COALESCE(array_length(NEW.missing_headers, 1), 0)::text || ' missing headers',
            NEW.target_url
        );
    END IF;

    -- === NEW TECHNOLOGY DETECTED ===
    IF NEW.detected_technologies IS NOT NULL AND array_length(NEW.detected_technologies, 1) > 0 THEN
        DECLARE
            v_new_techs TEXT[];
            v_tech TEXT;
        BEGIN
            IF v_previous_scan.detected_technologies IS NULL THEN
                v_new_techs := NEW.detected_technologies;
            ELSE
                SELECT array_agg(t) INTO v_new_techs
                FROM unnest(NEW.detected_technologies) AS t
                WHERE t != ALL(v_previous_scan.detected_technologies);
            END IF;

            IF v_new_techs IS NOT NULL AND array_length(v_new_techs, 1) > 0 THEN
                SELECT enabled, min_severity, cooldown_hours INTO v_alert_enabled, v_min_severity, v_cooldown_hours
                FROM public.alert_preferences
                WHERE user_id = NEW.user_id AND alert_type = 'new_technology';

                v_alert_enabled := COALESCE(v_alert_enabled, true);
                v_cooldown_hours := COALESCE(v_cooldown_hours, 24);

                IF v_alert_enabled AND
                   NOT EXISTS (
                       SELECT 1 FROM public.security_alerts
                       WHERE user_id = NEW.user_id AND alert_type = 'new_technology'
                         AND target_url = NEW.target_url AND is_dismissed = false
                         AND created_at > NOW() - (v_cooldown_hours || ' hours')::INTERVAL
                   )
                THEN
                    INSERT INTO public.security_alerts (
                        user_id, scan_id, scheduled_scan_id, alert_type, severity,
                        title, description, previous_value, current_value, target_url
                    ) VALUES (
                        NEW.user_id, NEW.id, v_scheduled_scan_id, 'new_technology', 'low',
                        'New Technology Detected',
                        'New technologies detected on ' || NEW.target_url || ': ' || array_to_string(v_new_techs, ', '),
                        COALESCE(array_to_string(v_previous_scan.detected_technologies, ', '), 'none'),
                        array_to_string(NEW.detected_technologies, ', '),
                        NEW.target_url
                    );
                END IF;
            END IF;
        END;
    END IF;

    RETURN NEW;
END;
$function$;
