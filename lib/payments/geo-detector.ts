/**
 * Geo-detection service for routing users to appropriate payment providers
 * Detects user location and recommends optimal payment processor
 *
 * NOTE: Disabled for MVP - GitHub Marketplace subscriptions only
 * POST-MVP: Enable for credit purchasing with Paddle/Paystack
 */

import { logInfo, logWarn } from '../logger';
import { PaymentProvider } from './types';

export interface GeoLocation {
  country?: string;
  continent?: string;
  currency?: string;
  ip?: string;
  state?: string;
}

export interface ProviderRecommendation {
  primary: PaymentProvider;
  alternatives: PaymentProvider[];
  reason: string;
}

/**
 * African countries where Paystack has strong presence
 */
const PAYSTACK_COUNTRIES = [
  'NG', // Nigeria
  'GH', // Ghana
  'ZA', // South Africa
  'KE', // Kenya
  'CI', // Côte d'Ivoire
  'EG', // Egypt
];

/**
 * Detect user's geo-location from request headers or IP
 * Uses Cloudflare headers, Vercel geolocation, or fallback to IP lookup
 */
export async function detectUserLocation(
  request: Request
): Promise<GeoLocation> {
  try {
    // Try Cloudflare headers (if behind Cloudflare)
    const cfCountry = request.headers.get('cf-ipcountry');
    if (cfCountry && cfCountry !== 'XX') {
      logInfo('Detected country from Cloudflare', { country: cfCountry });
      return {
        country: cfCountry,
        continent: getContinent(cfCountry),
      };
    }

    // Try Vercel geolocation headers
    const vercelCountry = request.headers.get('x-vercel-ip-country');
    if (vercelCountry) {
      logInfo('Detected country from Vercel', { country: vercelCountry });
      return {
        country: vercelCountry,
        continent: getContinent(vercelCountry),
      };
    }

    // Fallback: Try to get IP and use a free geo-IP service
    const ip =
      request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
      request.headers.get('x-real-ip') ||
      'unknown';

    logInfo('Detected IP address', { ip });

    // For local development or unknown IPs, return default
    if (
      ip === 'unknown' ||
      ip.startsWith('127.') ||
      ip.startsWith('192.168.')
    ) {
      logWarn('Local/unknown IP, using default location', { ip });
      return {
        country: 'US',
        continent: 'NA',
        ip,
      };
    }

    // In production, you might want to use a geo-IP service
    // For now, return US as default
    return {
      country: 'US',
      continent: 'NA',
      ip,
    };
  } catch (error) {
    logWarn('Failed to detect geo-location', { error });
    return {
      country: 'US',
      continent: 'NA',
    };
  }
}

/**
 * Get continent code from country code
 */
function getContinent(countryCode: string): string {
  const africanCountries = PAYSTACK_COUNTRIES;
  const europeanCountries = [
    'GB',
    'FR',
    'DE',
    'IT',
    'ES',
    'NL',
    'BE',
    'CH',
    'AT',
    'SE',
    'NO',
    'DK',
    'FI',
    'PL',
    'PT',
    'IE',
  ];
  const asianCountries = [
    'CN',
    'JP',
    'KR',
    'IN',
    'SG',
    'MY',
    'TH',
    'ID',
    'PH',
    'VN',
  ];
  const oceaniaCountries = ['AU', 'NZ'];

  if (africanCountries.includes(countryCode)) return 'AF';
  if (europeanCountries.includes(countryCode)) return 'EU';
  if (asianCountries.includes(countryCode)) return 'AS';
  if (oceaniaCountries.includes(countryCode)) return 'OC';
  return 'NA'; // Default to North America
}

/**
 * Recommend payment provider based on user location
 */
export function recommendPaymentProvider(
  location: GeoLocation
): ProviderRecommendation {
  const country = location.country || 'US';

  // African countries → Paystack (local payment methods, mobile money)
  if (PAYSTACK_COUNTRIES.includes(country)) {
    return {
      primary: PaymentProvider.PAYSTACK,
      alternatives: [PaymentProvider.PADDLE],
      reason: `Paystack recommended for ${country} — supports local payment methods and mobile money`,
    };
  }

  // All other countries → Paddle (global MoR, handles tax/compliance)
  return {
    primary: PaymentProvider.PADDLE,
    alternatives: [],
    reason:
      'Paddle recommended — handles international payments, tax, and compliance as Merchant of Record',
  };
}

/**
 * Get available payment providers for a location
 */
export function getAvailableProviders(
  location: GeoLocation
): PaymentProvider[] {
  const country = location.country || 'US';
  const providers: PaymentProvider[] = [PaymentProvider.PADDLE];

  // Add Paystack for African markets
  if (PAYSTACK_COUNTRIES.includes(country)) {
    providers.push(PaymentProvider.PAYSTACK);
  }

  return providers;
}

/**
 * Get currency for a country
 */
export function getCurrencyForCountry(countryCode: string): string {
  const currencyMap: Record<string, string> = {
    NG: 'NGN',
    GH: 'GHS',
    ZA: 'ZAR',
    KE: 'KES',
    GB: 'GBP',
    EU: 'EUR',
    JP: 'JPY',
    IN: 'INR',
    AU: 'AUD',
    CA: 'CAD',
    // Add more as needed
  };

  return currencyMap[countryCode] || 'USD';
}
