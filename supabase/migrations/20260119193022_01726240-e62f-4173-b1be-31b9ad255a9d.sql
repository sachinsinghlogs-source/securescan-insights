-- Force RLS on profiles table to prevent bypassing
ALTER TABLE public.profiles FORCE ROW LEVEL SECURITY;

-- Force RLS on scans table to prevent bypassing
ALTER TABLE public.scans FORCE ROW LEVEL SECURITY;