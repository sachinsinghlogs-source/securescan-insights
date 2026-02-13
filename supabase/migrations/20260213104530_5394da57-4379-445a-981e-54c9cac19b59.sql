
-- Step 1: Add 'owner' to the app_role enum only
ALTER TYPE public.app_role ADD VALUE IF NOT EXISTS 'owner';
