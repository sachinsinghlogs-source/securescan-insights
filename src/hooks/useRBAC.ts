/**
 * Role-Based Access Control Hook
 * 
 * Provides client-side role checking for UI rendering.
 * SECURITY NOTE: This is for UI purposes only. 
 * All sensitive operations MUST be validated server-side via RLS policies.
 */

import { useState, useEffect } from 'react';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/integrations/supabase/client';

export type AppRole = 'owner' | 'admin' | 'moderator' | 'user';

interface RBACState {
  role: AppRole | null;
  isOwner: boolean;
  isAdmin: boolean;
  isModerator: boolean;
  isLoading: boolean;
  error: Error | null;
}

/**
 * Hook for checking user roles
 * Uses the has_role database function for accurate role checking
 */
export function useRBAC(): RBACState {
  const { user } = useAuth();
  const [state, setState] = useState<RBACState>({
    role: null,
    isOwner: false,
    isAdmin: false,
    isModerator: false,
    isLoading: true,
    error: null,
  });

  useEffect(() => {
    async function fetchRole() {
      if (!user) {
        setState({
          role: null,
          isOwner: false,
          isAdmin: false,
          isModerator: false,
          isLoading: false,
          error: null,
        });
        return;
      }

      try {
        const { data: role, error } = await supabase.rpc('get_user_role', {
          _user_id: user.id,
        });

        if (error) throw error;

        const userRole = (role as AppRole) || 'user';

        setState({
          role: userRole,
          isOwner: userRole === 'owner',
          isAdmin: userRole === 'owner' || userRole === 'admin',
          isModerator: userRole === 'owner' || userRole === 'admin' || userRole === 'moderator',
          isLoading: false,
          error: null,
        });
      } catch (error) {
        console.error('Error fetching user role:', error);
        setState({
          role: 'user',
          isOwner: false,
          isAdmin: false,
          isModerator: false,
          isLoading: false,
          error: error instanceof Error ? error : new Error('Failed to fetch role'),
        });
      }
    }

    fetchRole();
  }, [user]);

  return state;
}

/**
 * Hook for checking specific role
 */
export function useHasRole(requiredRole: AppRole): boolean {
  const { role, isLoading } = useRBAC();
  
  if (isLoading || !role) return false;
  
  const roleHierarchy: Record<AppRole, number> = {
    owner: 4,
    admin: 3,
    moderator: 2,
    user: 1,
  };
  
  return roleHierarchy[role] >= roleHierarchy[requiredRole];
}
