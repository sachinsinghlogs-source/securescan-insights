-- ============================================
-- SECURITY HARDENING MIGRATION
-- Implements RBAC, Rate Limiting, Audit Logging
-- Following OWASP, NIST guidelines
-- ============================================

-- 1. CREATE ROLE ENUM FOR TYPE-SAFE RBAC
-- This prevents invalid role assignments and provides compile-time safety
CREATE TYPE public.app_role AS ENUM ('admin', 'moderator', 'user');

-- 2. CREATE USER ROLES TABLE (RBAC)
-- Stores role assignments separately from profiles to prevent privilege escalation
-- Foreign key to auth.users ensures referential integrity
CREATE TABLE public.user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    role app_role NOT NULL DEFAULT 'user',
    granted_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    granted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    UNIQUE (user_id, role)
);

-- Enable RLS on user_roles - critical for preventing unauthorized role modifications
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_roles FORCE ROW LEVEL SECURITY;

-- 3. CREATE SECURITY DEFINER FUNCTION FOR ROLE CHECKS
-- Using SECURITY DEFINER prevents infinite recursion in RLS policies
-- search_path is explicitly set to prevent search path attacks
CREATE OR REPLACE FUNCTION public.has_role(_user_id UUID, _role app_role)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.user_roles
    WHERE user_id = _user_id
      AND role = _role
  )
$$;

-- 4. CREATE FUNCTION TO GET USER'S HIGHEST ROLE
CREATE OR REPLACE FUNCTION public.get_user_role(_user_id UUID)
RETURNS app_role
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT COALESCE(
    (SELECT role FROM public.user_roles 
     WHERE user_id = _user_id 
     ORDER BY CASE role 
       WHEN 'admin' THEN 1 
       WHEN 'moderator' THEN 2 
       WHEN 'user' THEN 3 
     END 
     LIMIT 1),
    'user'::app_role
  )
$$;

-- 5. RLS POLICIES FOR USER_ROLES TABLE
-- Users can view their own roles
CREATE POLICY "Users can view own roles"
ON public.user_roles
FOR SELECT
USING (auth.uid() = user_id);

-- Only admins can insert/update/delete roles
CREATE POLICY "Admins can manage roles"
ON public.user_roles
FOR ALL
USING (public.has_role(auth.uid(), 'admin'));

-- 6. CREATE AUDIT LOG TABLE FOR SECURITY MONITORING
-- Captures all security-relevant events for forensics and compliance
CREATE TABLE public.security_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    event_category TEXT NOT NULL, -- 'auth', 'scan', 'admin', 'error'
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    ip_address INET,
    user_agent TEXT,
    resource_type TEXT,
    resource_id UUID,
    details JSONB DEFAULT '{}',
    severity TEXT NOT NULL DEFAULT 'info', -- 'info', 'warning', 'error', 'critical'
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS on audit log
ALTER TABLE public.security_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_audit_log FORCE ROW LEVEL SECURITY;

-- Only admins can read audit logs (users cannot see or modify)
CREATE POLICY "Admins can view audit logs"
ON public.security_audit_log
FOR SELECT
USING (public.has_role(auth.uid(), 'admin'));

-- 7. CREATE RATE LIMITING TABLE
-- Tracks API calls per user for rate limiting enforcement
CREATE TABLE public.rate_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    endpoint TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 1,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    UNIQUE (user_id, endpoint, window_start)
);

-- Enable RLS
ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rate_limits FORCE ROW LEVEL SECURITY;

-- Users can only see their own rate limit data
CREATE POLICY "Users can view own rate limits"
ON public.rate_limits
FOR SELECT
USING (auth.uid() = user_id);

-- 8. CREATE FAILED LOGIN ATTEMPTS TABLE (Brute Force Protection)
CREATE TABLE public.failed_login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    ip_address INET,
    attempt_count INTEGER NOT NULL DEFAULT 1,
    first_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    last_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    locked_until TIMESTAMP WITH TIME ZONE,
    UNIQUE (email)
);

-- Enable RLS - only service role can access this
ALTER TABLE public.failed_login_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.failed_login_attempts FORCE ROW LEVEL SECURITY;

-- No public access - only accessible via service role in edge functions
CREATE POLICY "No public access to failed logins"
ON public.failed_login_attempts
FOR ALL
USING (false);

-- 9. CREATE SECURITY DEFINER FUNCTION FOR AUDIT LOGGING
-- Allows edge functions to insert audit logs regardless of RLS
CREATE OR REPLACE FUNCTION public.log_security_event(
    p_event_type TEXT,
    p_event_category TEXT,
    p_user_id UUID DEFAULT NULL,
    p_ip_address INET DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL,
    p_resource_type TEXT DEFAULT NULL,
    p_resource_id UUID DEFAULT NULL,
    p_details JSONB DEFAULT '{}',
    p_severity TEXT DEFAULT 'info'
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_log_id UUID;
BEGIN
    INSERT INTO public.security_audit_log (
        event_type, event_category, user_id, ip_address, 
        user_agent, resource_type, resource_id, details, severity
    ) VALUES (
        p_event_type, p_event_category, p_user_id, p_ip_address,
        p_user_agent, p_resource_type, p_resource_id, p_details, p_severity
    )
    RETURNING id INTO v_log_id;
    
    RETURN v_log_id;
END;
$$;

-- 10. CREATE RATE LIMIT CHECK FUNCTION
-- Returns true if request should be allowed, false if rate limited
CREATE OR REPLACE FUNCTION public.check_rate_limit(
    p_user_id UUID,
    p_endpoint TEXT,
    p_max_requests INTEGER DEFAULT 100,
    p_window_minutes INTEGER DEFAULT 15
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_window_start TIMESTAMP WITH TIME ZONE;
    v_request_count INTEGER;
BEGIN
    -- Calculate the start of the current window
    v_window_start := date_trunc('minute', now()) - 
        ((EXTRACT(MINUTE FROM now())::INTEGER % p_window_minutes) * INTERVAL '1 minute');
    
    -- Get current request count for this window
    SELECT COALESCE(SUM(request_count), 0) INTO v_request_count
    FROM public.rate_limits
    WHERE user_id = p_user_id
      AND endpoint = p_endpoint
      AND window_start >= v_window_start;
    
    -- Check if over limit
    IF v_request_count >= p_max_requests THEN
        -- Log rate limit exceeded
        PERFORM public.log_security_event(
            'rate_limit_exceeded',
            'security',
            p_user_id,
            NULL,
            NULL,
            'endpoint',
            NULL,
            jsonb_build_object('endpoint', p_endpoint, 'count', v_request_count),
            'warning'
        );
        RETURN FALSE;
    END IF;
    
    -- Upsert rate limit record
    INSERT INTO public.rate_limits (user_id, endpoint, request_count, window_start)
    VALUES (p_user_id, p_endpoint, 1, v_window_start)
    ON CONFLICT (user_id, endpoint, window_start)
    DO UPDATE SET request_count = public.rate_limits.request_count + 1;
    
    RETURN TRUE;
END;
$$;

-- 11. AUTO-ASSIGN DEFAULT ROLE ON USER CREATION
CREATE OR REPLACE FUNCTION public.handle_new_user_role()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    -- Assign default 'user' role to new users
    INSERT INTO public.user_roles (user_id, role)
    VALUES (NEW.id, 'user');
    
    -- Log the new user creation
    PERFORM public.log_security_event(
        'user_created',
        'auth',
        NEW.id,
        NULL,
        NULL,
        'user',
        NEW.id,
        jsonb_build_object('email', NEW.email),
        'info'
    );
    
    RETURN NEW;
END;
$$;

-- Create trigger for auto-role assignment
CREATE TRIGGER on_auth_user_created_assign_role
    AFTER INSERT ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_new_user_role();

-- 12. CREATE INDEX FOR PERFORMANCE
CREATE INDEX idx_audit_log_user_id ON public.security_audit_log(user_id);
CREATE INDEX idx_audit_log_created_at ON public.security_audit_log(created_at DESC);
CREATE INDEX idx_audit_log_event_type ON public.security_audit_log(event_type);
CREATE INDEX idx_rate_limits_lookup ON public.rate_limits(user_id, endpoint, window_start);
CREATE INDEX idx_user_roles_user_id ON public.user_roles(user_id);

-- 13. CLEANUP OLD RATE LIMIT RECORDS (scheduled via cron job or manual)
CREATE OR REPLACE FUNCTION public.cleanup_old_rate_limits()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_deleted_count INTEGER;
BEGIN
    DELETE FROM public.rate_limits
    WHERE window_start < now() - INTERVAL '1 hour';
    
    GET DIAGNOSTICS v_deleted_count = ROW_COUNT;
    RETURN v_deleted_count;
END;
$$;