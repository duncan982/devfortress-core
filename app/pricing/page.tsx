/**
 * Pricing — open-core redirect
 *
 * The full pricing page (Paddle billing, plan comparison, enterprise intake)
 * lives in the hosted platform at devfortress.net/pricing.
 * This open-core build redirects there permanently.
 */

import { redirect } from 'next/navigation';

export default function PricingPage() {
  redirect('https://devfortress.net/pricing');
}

export const metadata = {
  title: 'Pricing — DevFortress',
  description:
    'View DevFortress pricing plans at devfortress.net/pricing.',
};
