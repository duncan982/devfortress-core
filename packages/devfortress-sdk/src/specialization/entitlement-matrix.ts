// packages/devfortress-sdk/src/specialization/entitlement-matrix.ts

import type { SpecializationModeId } from './manifest';
import { SPECIALIZATION_MANIFESTS } from './manifest';

export type SubscriptionTier =
  | 'free'
  | 'starter'
  | 'pro'
  | 'team'
  | 'enterprise';

const TIER_ORDER: SubscriptionTier[] = [
  'free',
  'starter',
  'pro',
  'team',
  'enterprise',
];

export function isEntitled(
  modeId: SpecializationModeId,
  customerTier: SubscriptionTier
): boolean {
  const manifest = SPECIALIZATION_MANIFESTS[modeId];
  if (!manifest) return false;
  const requiredIndex = TIER_ORDER.indexOf(manifest.requiredTier);
  const customerIndex = TIER_ORDER.indexOf(customerTier);
  return customerIndex >= requiredIndex;
}

export function getEntitledModes(
  customerTier: SubscriptionTier
): SpecializationModeId[] {
  return (
    Object.keys(SPECIALIZATION_MANIFESTS) as SpecializationModeId[]
  ).filter(modeId => isEntitled(modeId, customerTier));
}

export function getUpsellModes(
  customerTier: SubscriptionTier
): SpecializationModeId[] {
  return (
    Object.keys(SPECIALIZATION_MANIFESTS) as SpecializationModeId[]
  ).filter(modeId => !isEntitled(modeId, customerTier));
}
