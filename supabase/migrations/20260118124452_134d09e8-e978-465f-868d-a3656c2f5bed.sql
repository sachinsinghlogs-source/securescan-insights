-- Create profiles table for user data
CREATE TABLE public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  full_name TEXT,
  plan_type TEXT NOT NULL DEFAULT 'free' CHECK (plan_type IN ('free', 'pro')),
  daily_scans_used INTEGER NOT NULL DEFAULT 0,
  last_scan_date DATE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS on profiles
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- Profiles policies
CREATE POLICY "Users can view own profile" ON public.profiles
  FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can update own profile" ON public.profiles
  FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "Users can insert own profile" ON public.profiles
  FOR INSERT WITH CHECK (auth.uid() = id);

-- Create scans table
CREATE TABLE public.scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  target_url TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'scanning', 'completed', 'failed')),
  risk_level TEXT CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
  risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
  ssl_valid BOOLEAN,
  ssl_expiry_date TIMESTAMP WITH TIME ZONE,
  ssl_issuer TEXT,
  headers_score INTEGER,
  missing_headers TEXT[],
  present_headers TEXT[],
  detected_technologies TEXT[],
  detected_cms TEXT,
  server_info TEXT,
  scan_duration_ms INTEGER,
  raw_results JSONB,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  completed_at TIMESTAMP WITH TIME ZONE
);

-- Enable RLS on scans
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;

-- Scans policies
CREATE POLICY "Users can view own scans" ON public.scans
  FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can create own scans" ON public.scans
  FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own scans" ON public.scans
  FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own scans" ON public.scans
  FOR DELETE USING (auth.uid() = user_id);

-- Create function to update timestamps
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = public;

-- Create trigger for profiles
CREATE TRIGGER update_profiles_updated_at
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW
  EXECUTE FUNCTION public.update_updated_at_column();

-- Create function to handle new user signups
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, email, full_name)
  VALUES (NEW.id, NEW.email, NEW.raw_user_meta_data->>'full_name');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Create trigger for new user signups
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_user();

-- Create function to reset daily scan count
CREATE OR REPLACE FUNCTION public.check_and_reset_daily_scans(p_user_id UUID)
RETURNS INTEGER AS $$
DECLARE
  v_last_scan_date DATE;
  v_daily_scans INTEGER;
BEGIN
  SELECT last_scan_date, daily_scans_used INTO v_last_scan_date, v_daily_scans
  FROM public.profiles WHERE id = p_user_id;
  
  IF v_last_scan_date IS NULL OR v_last_scan_date < CURRENT_DATE THEN
    UPDATE public.profiles 
    SET daily_scans_used = 0, last_scan_date = CURRENT_DATE
    WHERE id = p_user_id;
    RETURN 0;
  END IF;
  
  RETURN v_daily_scans;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Create index for faster scan queries
CREATE INDEX idx_scans_user_id ON public.scans(user_id);
CREATE INDEX idx_scans_created_at ON public.scans(created_at DESC);
CREATE INDEX idx_scans_status ON public.scans(status);