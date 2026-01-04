import { createSupabaseRouteClient } from '@core/lib/supabase/server';
import { logInfo } from '@core/lib/logger';

export async function saveHPSLog(hpsId: string, userId: string, action: string, details: Record<string, unknown>) {
  const supabase = await createSupabaseRouteClient();
  // @ts-expect-error Database types are incomplete
  await supabase.from('HPSLog').insert({
    id: crypto.randomUUID(),
    hpsId,
    userId,
    action,
    details
  });
  logInfo('HPS log saved', { hpsId, action });
}

export async function checkQuota(userId: string): Promise<boolean> {
  const supabase = await createSupabaseRouteClient();
  const { data: userData } = await (supabase.from('User').select('tier').eq('id', userId).single() as unknown as { data: { tier: string } | null });
  if (!userData) return false; // or throw, but for quota check, assume false

  const tierLimits: Record<string, number> = { STARTER: 1, PROFESSIONAL: 5, ENTERPRISE: 20 };
  const limit = tierLimits[userData.tier as string] || 0;

  const { count } = await (supabase.from('HPSInstance').select('*', { count: 'exact' }).eq('userId', userId).eq('status', 'ACTIVE') as unknown as { count: number });
  return (count || 0) < limit;
}