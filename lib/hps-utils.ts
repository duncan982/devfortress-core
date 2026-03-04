import { createSupabaseRouteClient } from '@core/lib/supabase/server';
import { logInfo } from '@core/lib/logger';

export async function saveHPSLog(
  hpsId: string,
  userId: string,
  action: string,
  details: Record<string, unknown>
) {
  const supabase = await createSupabaseRouteClient();
  // @ts-expect-error Database types are incomplete
  await supabase.from('HPSLog').insert({
    id: crypto.randomUUID(),
    hpsId,
    userId,
    action,
    details,
  });
  logInfo('HPS log saved', { hpsId, action });
}

export async function checkQuota(userId: string): Promise<boolean> {
  const supabase = await createSupabaseRouteClient();
  // @ts-expect-error Database types are incomplete
  const userResult = await supabase
    .from('User')
    .select('tier')
    .eq('id', userId)
    .single();
  const userData = (userResult as { data: { tier: string } | null }).data;
  if (!userData) return false; // or throw, but for quota check, assume false

  const tierLimits: Record<string, number> = {
    STARTER: 1,
    PROFESSIONAL: 5,
    ENTERPRISE: 20,
  };
  const limit = tierLimits[userData.tier as string] || 0;

  // @ts-expect-error Database types are incomplete
  const countResult = await supabase
    .from('HPSInstance')
    .select('*', { count: 'exact' })
    .eq('userId', userId)
    .eq('status', 'ACTIVE');
  const count = (countResult as { count: number }).count;
  return (count || 0) < limit;
}
