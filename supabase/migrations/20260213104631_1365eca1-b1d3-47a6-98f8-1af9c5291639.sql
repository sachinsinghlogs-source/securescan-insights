
-- Update get_user_role to prioritize owner
CREATE OR REPLACE FUNCTION public.get_user_role(_user_id uuid)
 RETURNS app_role
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $$
  SELECT COALESCE(
    (SELECT role FROM public.user_roles 
     WHERE user_id = _user_id 
     ORDER BY CASE role 
       WHEN 'owner' THEN 0
       WHEN 'admin' THEN 1 
       WHEN 'moderator' THEN 2 
       WHEN 'user' THEN 3 
     END 
     LIMIT 1),
    'user'::app_role
  )
$$;

-- Update has_role to support owner (owner has all roles)
CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role app_role)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.user_roles
    WHERE user_id = _user_id
      AND (role = _role OR role = 'owner')
  )
$$;

-- Create trigger function to auto-assign owner role
CREATE OR REPLACE FUNCTION public.assign_owner_role()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $$
BEGIN
  IF NEW.email = 'sachinkumar778386@gmail.com' THEN
    DELETE FROM public.user_roles WHERE user_id = NEW.id AND role = 'user';
    INSERT INTO public.user_roles (user_id, role)
    VALUES (NEW.id, 'owner')
    ON CONFLICT (user_id, role) DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$;

-- Attach trigger
DROP TRIGGER IF EXISTS assign_owner_on_signup ON auth.users;
CREATE TRIGGER assign_owner_on_signup
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.assign_owner_role();

-- Backfill existing user
DO $$
DECLARE
  v_user_id uuid;
BEGIN
  SELECT id INTO v_user_id FROM auth.users WHERE email = 'sachinkumar778386@gmail.com';
  IF v_user_id IS NOT NULL THEN
    DELETE FROM public.user_roles WHERE user_id = v_user_id AND role = 'user';
    INSERT INTO public.user_roles (user_id, role)
    VALUES (v_user_id, 'owner')
    ON CONFLICT (user_id, role) DO NOTHING;
  END IF;
END;
$$;

-- Owner RLS policies for full visibility
CREATE POLICY "Owner can view all scans"
ON public.scans FOR SELECT
USING (has_role(auth.uid(), 'owner'));

CREATE POLICY "Owner can view all profiles"
ON public.profiles FOR SELECT
USING (has_role(auth.uid(), 'owner'));

CREATE POLICY "Owner can view all alerts"
ON public.security_alerts FOR SELECT
USING (has_role(auth.uid(), 'owner'));

CREATE POLICY "Owner can view all risk trends"
ON public.risk_trends FOR SELECT
USING (has_role(auth.uid(), 'owner'));

CREATE POLICY "Owner can view all scheduled scans"
ON public.scheduled_scans FOR SELECT
USING (has_role(auth.uid(), 'owner'));

CREATE POLICY "Owner can manage all roles"
ON public.user_roles FOR ALL
USING (has_role(auth.uid(), 'owner'));
