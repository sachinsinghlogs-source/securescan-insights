export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.1"
  }
  public: {
    Tables: {
      alert_preferences: {
        Row: {
          alert_type: string
          cooldown_hours: number
          created_at: string
          enabled: boolean
          id: string
          min_severity: string
          updated_at: string
          user_id: string
        }
        Insert: {
          alert_type: string
          cooldown_hours?: number
          created_at?: string
          enabled?: boolean
          id?: string
          min_severity?: string
          updated_at?: string
          user_id: string
        }
        Update: {
          alert_type?: string
          cooldown_hours?: number
          created_at?: string
          enabled?: boolean
          id?: string
          min_severity?: string
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      failed_login_attempts: {
        Row: {
          attempt_count: number
          email: string
          first_attempt_at: string
          id: string
          ip_address: unknown
          last_attempt_at: string
          locked_until: string | null
        }
        Insert: {
          attempt_count?: number
          email: string
          first_attempt_at?: string
          id?: string
          ip_address?: unknown
          last_attempt_at?: string
          locked_until?: string | null
        }
        Update: {
          attempt_count?: number
          email?: string
          first_attempt_at?: string
          id?: string
          ip_address?: unknown
          last_attempt_at?: string
          locked_until?: string | null
        }
        Relationships: []
      }
      profiles: {
        Row: {
          created_at: string
          daily_scans_used: number
          email: string
          email_notifications: boolean
          full_name: string | null
          id: string
          last_scan_date: string | null
          plan_type: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          daily_scans_used?: number
          email: string
          email_notifications?: boolean
          full_name?: string | null
          id: string
          last_scan_date?: string | null
          plan_type?: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          daily_scans_used?: number
          email?: string
          email_notifications?: boolean
          full_name?: string | null
          id?: string
          last_scan_date?: string | null
          plan_type?: string
          updated_at?: string
        }
        Relationships: []
      }
      rate_limits: {
        Row: {
          endpoint: string
          id: string
          request_count: number
          user_id: string
          window_start: string
        }
        Insert: {
          endpoint: string
          id?: string
          request_count?: number
          user_id: string
          window_start?: string
        }
        Update: {
          endpoint?: string
          id?: string
          request_count?: number
          user_id?: string
          window_start?: string
        }
        Relationships: []
      }
      risk_trends: {
        Row: {
          id: string
          missing_headers_count: number | null
          present_headers_count: number | null
          recorded_at: string
          risk_level: string
          risk_score: number
          scan_id: string
          scheduled_scan_id: string | null
          ssl_valid: boolean | null
          target_url: string
          user_id: string
        }
        Insert: {
          id?: string
          missing_headers_count?: number | null
          present_headers_count?: number | null
          recorded_at?: string
          risk_level: string
          risk_score: number
          scan_id: string
          scheduled_scan_id?: string | null
          ssl_valid?: boolean | null
          target_url: string
          user_id: string
        }
        Update: {
          id?: string
          missing_headers_count?: number | null
          present_headers_count?: number | null
          recorded_at?: string
          risk_level?: string
          risk_score?: number
          scan_id?: string
          scheduled_scan_id?: string | null
          ssl_valid?: boolean | null
          target_url?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "risk_trends_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "risk_trends_scheduled_scan_id_fkey"
            columns: ["scheduled_scan_id"]
            isOneToOne: false
            referencedRelation: "scheduled_scans"
            referencedColumns: ["id"]
          },
        ]
      }
      scans: {
        Row: {
          completed_at: string | null
          created_at: string
          detected_cms: string | null
          detected_technologies: string[] | null
          headers_score: number | null
          id: string
          missing_headers: string[] | null
          present_headers: string[] | null
          raw_results: Json | null
          risk_level: string | null
          risk_score: number | null
          scan_duration_ms: number | null
          server_info: string | null
          ssl_expiry_date: string | null
          ssl_issuer: string | null
          ssl_valid: boolean | null
          status: string
          target_url: string
          user_id: string
        }
        Insert: {
          completed_at?: string | null
          created_at?: string
          detected_cms?: string | null
          detected_technologies?: string[] | null
          headers_score?: number | null
          id?: string
          missing_headers?: string[] | null
          present_headers?: string[] | null
          raw_results?: Json | null
          risk_level?: string | null
          risk_score?: number | null
          scan_duration_ms?: number | null
          server_info?: string | null
          ssl_expiry_date?: string | null
          ssl_issuer?: string | null
          ssl_valid?: boolean | null
          status?: string
          target_url: string
          user_id: string
        }
        Update: {
          completed_at?: string | null
          created_at?: string
          detected_cms?: string | null
          detected_technologies?: string[] | null
          headers_score?: number | null
          id?: string
          missing_headers?: string[] | null
          present_headers?: string[] | null
          raw_results?: Json | null
          risk_level?: string | null
          risk_score?: number | null
          scan_duration_ms?: number | null
          server_info?: string | null
          ssl_expiry_date?: string | null
          ssl_issuer?: string | null
          ssl_valid?: boolean | null
          status?: string
          target_url?: string
          user_id?: string
        }
        Relationships: []
      }
      scheduled_scans: {
        Row: {
          created_at: string
          environment: Database["public"]["Enums"]["scan_environment"]
          id: string
          is_active: boolean
          last_scan_id: string | null
          next_scan_at: string | null
          scan_frequency: string
          target_url: string
          updated_at: string
          user_id: string
        }
        Insert: {
          created_at?: string
          environment?: Database["public"]["Enums"]["scan_environment"]
          id?: string
          is_active?: boolean
          last_scan_id?: string | null
          next_scan_at?: string | null
          scan_frequency?: string
          target_url: string
          updated_at?: string
          user_id: string
        }
        Update: {
          created_at?: string
          environment?: Database["public"]["Enums"]["scan_environment"]
          id?: string
          is_active?: boolean
          last_scan_id?: string | null
          next_scan_at?: string | null
          scan_frequency?: string
          target_url?: string
          updated_at?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "scheduled_scans_last_scan_id_fkey"
            columns: ["last_scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
        ]
      }
      security_alerts: {
        Row: {
          alert_type: string
          created_at: string
          current_value: string | null
          description: string | null
          email_sent: boolean
          email_sent_at: string | null
          id: string
          is_dismissed: boolean
          is_read: boolean
          previous_value: string | null
          scan_id: string | null
          scheduled_scan_id: string | null
          severity: string
          target_url: string | null
          title: string
          user_id: string
        }
        Insert: {
          alert_type: string
          created_at?: string
          current_value?: string | null
          description?: string | null
          email_sent?: boolean
          email_sent_at?: string | null
          id?: string
          is_dismissed?: boolean
          is_read?: boolean
          previous_value?: string | null
          scan_id?: string | null
          scheduled_scan_id?: string | null
          severity?: string
          target_url?: string | null
          title: string
          user_id: string
        }
        Update: {
          alert_type?: string
          created_at?: string
          current_value?: string | null
          description?: string | null
          email_sent?: boolean
          email_sent_at?: string | null
          id?: string
          is_dismissed?: boolean
          is_read?: boolean
          previous_value?: string | null
          scan_id?: string | null
          scheduled_scan_id?: string | null
          severity?: string
          target_url?: string | null
          title?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "security_alerts_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "security_alerts_scheduled_scan_id_fkey"
            columns: ["scheduled_scan_id"]
            isOneToOne: false
            referencedRelation: "scheduled_scans"
            referencedColumns: ["id"]
          },
        ]
      }
      security_audit_log: {
        Row: {
          created_at: string
          details: Json | null
          event_category: string
          event_type: string
          id: string
          ip_address: unknown
          resource_id: string | null
          resource_type: string | null
          severity: string
          user_agent: string | null
          user_id: string | null
        }
        Insert: {
          created_at?: string
          details?: Json | null
          event_category: string
          event_type: string
          id?: string
          ip_address?: unknown
          resource_id?: string | null
          resource_type?: string | null
          severity?: string
          user_agent?: string | null
          user_id?: string | null
        }
        Update: {
          created_at?: string
          details?: Json | null
          event_category?: string
          event_type?: string
          id?: string
          ip_address?: unknown
          resource_id?: string | null
          resource_type?: string | null
          severity?: string
          user_agent?: string | null
          user_id?: string | null
        }
        Relationships: []
      }
      user_roles: {
        Row: {
          granted_at: string
          granted_by: string | null
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          granted_at?: string
          granted_by?: string | null
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          granted_at?: string
          granted_by?: string | null
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      check_and_reset_daily_scans: {
        Args: { p_user_id: string }
        Returns: number
      }
      check_rate_limit: {
        Args: {
          p_endpoint: string
          p_max_requests?: number
          p_user_id: string
          p_window_minutes?: number
        }
        Returns: boolean
      }
      cleanup_old_rate_limits: { Args: never; Returns: number }
      get_user_role: {
        Args: { _user_id: string }
        Returns: Database["public"]["Enums"]["app_role"]
      }
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
      log_security_event: {
        Args: {
          p_details?: Json
          p_event_category: string
          p_event_type: string
          p_ip_address?: unknown
          p_resource_id?: string
          p_resource_type?: string
          p_severity?: string
          p_user_agent?: string
          p_user_id?: string
        }
        Returns: string
      }
    }
    Enums: {
      app_role: "admin" | "moderator" | "user"
      scan_environment: "production" | "staging" | "development"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: ["admin", "moderator", "user"],
      scan_environment: ["production", "staging", "development"],
    },
  },
} as const
