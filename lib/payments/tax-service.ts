import { logInfo, logWarn } from '../logger';
import { getTaxNexusStates } from '../env';
import type { GeoLocation } from './geo-detector';

export type TaxJurisdictionType = 'VAT' | 'SALES_TAX' | 'NONE';

export interface TaxCalculationInput {
  amount: number; // Base amount in minor units (e.g. cents)
  currency: string;
  country?: string; // ISO 3166-1 alpha-2 country code supplied by billing data
  stateOrProvince?: string; // ISO 3166-2 subdivision, used primarily for the US
  isBusiness?: boolean; // Indicates B2B transactions
  taxId?: string; // VAT/TIN identifier supplied by customer
  locationEvidence?: GeoLocation; // Geolocation evidence (IP, headers, etc.)
  nexusOverrides?: string[]; // Override nexus configuration (uppercase codes)
}

export interface TaxCalculationResult {
  taxAmount: number; // Computed tax in minor units
  totalAmount: number; // amount + taxAmount
  rate: number; // Decimal rate e.g. 0.16
  taxType: TaxJurisdictionType;
  jurisdiction?: string; // Human readable jurisdiction reference
  notes: string[];
  doubleTaxationReliefApplied: boolean;
  requiresReverseChargeNote: boolean;
}

const KENYA_VAT_RATE = 0.16;

const EU_VAT_RATES: Record<string, number> = {
  AT: 0.2,
  BE: 0.21,
  BG: 0.2,
  CY: 0.19,
  CZ: 0.21,
  DE: 0.19,
  DK: 0.25,
  EE: 0.2,
  ES: 0.21,
  FI: 0.24,
  FR: 0.2,
  GR: 0.24,
  HR: 0.25,
  HU: 0.27,
  IE: 0.23,
  IT: 0.22,
  LT: 0.21,
  LU: 0.17,
  LV: 0.21,
  MT: 0.18,
  NL: 0.21,
  PL: 0.23,
  PT: 0.23,
  RO: 0.19,
  SE: 0.25,
  SI: 0.22,
  SK: 0.2,
};

const US_STATE_TAX_RATES: Record<string, number> = {
  CA: 0.0825,
  NY: 0.08875,
  TX: 0.0625,
  FL: 0.06,
  WA: 0.065,
};

const DOUBLE_TAX_TREATY_COUNTRIES = new Set([
  'GB',
  'DE',
  'FR',
  'NL',
  'SE',
  'NO',
  'DK',
  'IN',
  'ZA',
  'CA',
  'US',
  'AE',
  'CN',
]);

const VAT_ID_REGEX = /^[A-Z]{2}[A-Z0-9]{6,12}$/;

const normalizeCountry = (code?: string) => code?.trim().toUpperCase();
const normalizeState = (code?: string) => code?.trim().toUpperCase();

const hasValidEuVatId = (country: string, vatId?: string) => {
  if (!vatId) {
    return false;
  }

  const normalized = vatId.replace(/[^A-Z0-9]/gi, '').toUpperCase();

  if (!VAT_ID_REGEX.test(normalized)) {
    return false;
  }

  return normalized.startsWith(country);
};

const isEuCountry = (country?: string) =>
  Boolean(
    country && Object.prototype.hasOwnProperty.call(EU_VAT_RATES, country)
  );

interface CalculationContext {
  country?: string;
  state?: string;
  notes: string[];
  nexusSet: Set<string>;
}

const finalizeResult = (
  baseAmount: number,
  partial: Omit<TaxCalculationResult, 'totalAmount'>
): TaxCalculationResult => ({
  ...partial,
  totalAmount: baseAmount + partial.taxAmount,
});

export function calculateTax(input: TaxCalculationInput): TaxCalculationResult {
  const notes: string[] = [];
  const context: CalculationContext = {
    country: normalizeCountry(input.country || input.locationEvidence?.country),
    state: normalizeState(
      input.stateOrProvince || input.locationEvidence?.state
    ),
    notes,
    nexusSet: new Set(
      (input.nexusOverrides ?? getTaxNexusStates()).map((code: string) =>
        code.trim().toUpperCase()
      )
    ),
  };

  if (!context.country) {
    notes.push(
      'No billing country detected; tax calculation skipped pending address verification.'
    );
    const result = finalizeResult(input.amount, {
      taxAmount: 0,
      rate: 0,
      taxType: 'NONE',
      jurisdiction: undefined,
      notes,
      doubleTaxationReliefApplied: false,
      requiresReverseChargeNote: false,
    });
    logWarn('Unable to determine tax jurisdiction', {
      reason: 'missing_country',
    });
    return result;
  }

  if (context.country === 'KE') {
    notes.push('Applying 16% VAT for Kenyan customers per VAT Act 2013.');
    if (input.isBusiness && input.taxId) {
      notes.push('Include customer PIN on the e-invoice for compliance.');
    }

    const result = finalizeResult(input.amount, {
      taxAmount: Math.round(input.amount * KENYA_VAT_RATE),
      rate: KENYA_VAT_RATE,
      taxType: 'VAT',
      jurisdiction: 'Kenya',
      notes,
      doubleTaxationReliefApplied: false,
      requiresReverseChargeNote: false,
    });

    logInfo('Calculated domestic VAT', {
      country: context.country,
      rate: result.rate,
      taxAmount: result.taxAmount,
    });

    return result;
  }

  if (isEuCountry(context.country)) {
    const vatRate = EU_VAT_RATES[context.country];

    if (input.isBusiness && hasValidEuVatId(context.country, input.taxId)) {
      notes.push(
        'Valid EU VAT number detected; applying reverse charge and zero-rating the transaction.'
      );
      notes.push(
        'Record reverse charge note on the invoice to comply with Council Directive 2006/112/EC.'
      );
      const result = finalizeResult(input.amount, {
        taxAmount: 0,
        rate: 0,
        taxType: 'VAT',
        jurisdiction: `EU-${context.country}`,
        notes,
        doubleTaxationReliefApplied: true,
        requiresReverseChargeNote: true,
      });
      logInfo('Applied EU reverse charge', {
        country: context.country,
        taxIdProvided: Boolean(input.taxId),
      });
      return result;
    }

    notes.push(
      `Charging ${Math.round(vatRate * 100)}% VAT for EU member state ${context.country}.`
    );
    notes.push('Store evidence of customer location (invoice address + IP).');

    const result = finalizeResult(input.amount, {
      taxAmount: Math.round(input.amount * vatRate),
      rate: vatRate,
      taxType: 'VAT',
      jurisdiction: `EU-${context.country}`,
      notes,
      doubleTaxationReliefApplied: false,
      requiresReverseChargeNote: false,
    });

    logInfo('Calculated EU VAT', {
      country: context.country,
      rate: result.rate,
      taxAmount: result.taxAmount,
    });

    return result;
  }

  if (context.country === 'US') {
    const state = context.state;

    if (!state) {
      notes.push('Customer state not provided; unable to assess US sales tax.');
      const result = finalizeResult(input.amount, {
        taxAmount: 0,
        rate: 0,
        taxType: 'NONE',
        jurisdiction: undefined,
        notes,
        doubleTaxationReliefApplied: false,
        requiresReverseChargeNote: false,
      });
      logWarn('Missing state for US sales tax evaluation', {});
      return result;
    }

    if (!context.nexusSet.has(state)) {
      notes.push(
        `No sales tax nexus configured for ${state}; transaction treated as tax-exempt.`
      );
      const result = finalizeResult(input.amount, {
        taxAmount: 0,
        rate: 0,
        taxType: 'NONE',
        jurisdiction: undefined,
        notes,
        doubleTaxationReliefApplied: false,
        requiresReverseChargeNote: false,
      });
      logInfo('Sales tax skipped - no nexus', {
        state,
      });
      return result;
    }

    const salesTaxRate =
      US_STATE_TAX_RATES[state] ?? 0.07; /* default mid-market estimate */

    notes.push(
      `Applying ${
        Math.round(salesTaxRate * 10000) / 100
      }% sales tax for ${state} due to economic nexus.`
    );

    const result = finalizeResult(input.amount, {
      taxAmount: Math.round(input.amount * salesTaxRate),
      rate: salesTaxRate,
      taxType: 'SALES_TAX',
      jurisdiction: `US-${state}`,
      notes,
      doubleTaxationReliefApplied: false,
      requiresReverseChargeNote: false,
    });

    logInfo('Calculated US sales tax', {
      state,
      rate: result.rate,
      taxAmount: result.taxAmount,
    });

    return result;
  }

  if (DOUBLE_TAX_TREATY_COUNTRIES.has(context.country)) {
    notes.push(
      `Kenya maintains a double taxation treaty with ${context.country}; defaulting to local jurisdictional rules and zero-rating Kenyan VAT.`
    );
    const result = finalizeResult(input.amount, {
      taxAmount: 0,
      rate: 0,
      taxType: 'NONE',
      jurisdiction: context.country,
      notes,
      doubleTaxationReliefApplied: true,
      requiresReverseChargeNote: false,
    });
    logInfo('Applied double taxation relief', {
      country: context.country,
    });
    return result;
  }

  notes.push(
    `No indirect tax obligations configured for ${context.country}; review annually with tax advisors.`
  );

  const result = finalizeResult(input.amount, {
    taxAmount: 0,
    rate: 0,
    taxType: 'NONE',
    jurisdiction: context.country,
    notes,
    doubleTaxationReliefApplied: false,
    requiresReverseChargeNote: false,
  });

  logInfo('No indirect tax applied', {
    country: context.country,
  });

  return result;
}
