

# Phase 6: Smart Alerting

## Overview
Upgrade the alerting system from time-based (alert on every scan) to change-based (alert only on meaningful security regressions). This reduces noise and makes alerts truly actionable.

## Current State
- The `detect_security_changes` database trigger fires on every completed scan and creates alerts for risk increases, SSL invalidation, config drift, and SSL expiry.
- The `send-alert-emails` edge function sends emails for critical/high alerts via Resend.
- `NotificationSettings` provides a single email toggle.
- `AlertsPanel` shows all alerts in a flat list with read/dismiss actions.

## What Changes

### 1. Database: Add alert preferences and deduplication

**New table: `alert_preferences`**
- `user_id`, `alert_type` (risk_increased, ssl_invalid, ssl_expiring, config_drift, new_technology), `enabled` (boolean), `min_severity` (low/medium/high/critical), `cooldown_hours` (prevents repeated alerts for the same issue)

**Modify `detect_security_changes` trigger:**
- Add deduplication logic: skip creating an alert if an identical alert (same type, same URL) was created within the user's cooldown window
- Add "improvement" alerts (risk decreased, SSL restored, headers added) as low-severity positive notifications
- Add a `new_technology` alert type when new technologies are detected on a domain

### 2. Frontend: Granular notification preferences

**Upgrade `NotificationSettings.tsx`:**
- Replace the single email toggle with per-alert-type controls
- Each alert type gets: enable/disable toggle, minimum severity selector, cooldown period selector (1h, 6h, 12h, 24h, 48h)
- Show a preview of what each alert type looks like
- Group into categories: "Security Regressions" and "Improvements"

### 3. Frontend: Smart alert grouping in AlertsPanel

**Upgrade `AlertsPanel.tsx`:**
- Group alerts by domain instead of flat list
- Add filter/sort controls: by severity, by type, by date range
- Add "Improvement" alerts with green styling (risk decreased, headers added)
- Show alert frequency stats: "3 alerts this week for example.com"
- Add a "Snooze domain" action to temporarily suppress alerts for a specific domain

### 4. Update `send-alert-emails` edge function
- Check per-alert-type preferences before sending
- Respect cooldown periods
- Batch multiple alerts for the same domain into a single digest email instead of individual emails
- Add an "improvements" section to emails showing positive changes

## Technical Details

### Database Migration
```text
CREATE TABLE alert_preferences (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  alert_type TEXT NOT NULL,
  enabled BOOLEAN DEFAULT true,
  min_severity TEXT DEFAULT 'medium',
  cooldown_hours INTEGER DEFAULT 24,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(user_id, alert_type)
);
-- RLS: users can manage their own preferences

ALTER TABLE security_alerts ADD COLUMN target_url TEXT;
-- Populate from scan_id join for grouping
```

### Updated Trigger Logic (pseudocode)
```text
-- Before creating alert, check:
1. Does user have this alert_type enabled? (default: yes)
2. Is the severity >= user's min_severity for this type?
3. Was a similar alert created within cooldown_hours?
-- If all pass, create the alert
-- Also create "improvement" alerts for positive changes
```

### Files to Create/Modify
- **Create**: (none, all modifications to existing files)
- **Modify**: 
  - `NotificationSettings.tsx` -- granular per-type controls
  - `AlertsPanel.tsx` -- domain grouping, filters, improvement alerts
  - `send-alert-emails/index.ts` -- preference-aware, digest mode
  - Database trigger `detect_security_changes` -- deduplication, improvements, preference checks
  - Database migration for `alert_preferences` table and `target_url` column

