/**
 * Enterprise Billing Service
 *
 * Manages enterprise-specific billing operations:
 * - Annual invoice generation
 * - Per-endpoint pricing calculation
 * - Contract tracking
 * - Implementation fee management
 * - Usage-based overage calculation
 */

import { logInfo, logError } from '@core/lib/logger';
import { endpointMeteringService } from './endpoint-metering-service';

/* ─── Types ─── */

export enum BillingCurrency {
  USD = 'USD',
  EUR = 'EUR',
  GBP = 'GBP',
}

export enum InvoiceStatus {
  DRAFT = 'draft',
  SENT = 'sent',
  PAID = 'paid',
  OVERDUE = 'overdue',
  VOID = 'void',
}

export enum ContractStatus {
  ACTIVE = 'active',
  PENDING = 'pending',
  EXPIRED = 'expired',
  CANCELLED = 'cancelled',
}

export interface LineItem {
  description: string;
  quantity: number;
  unitPrice: number; // in cents
  total: number; // in cents
  type:
    | 'base'
    | 'metering'
    | 'addon'
    | 'compliance'
    | 'implementation'
    | 'overage';
}

export interface Invoice {
  id: string;
  orgId: string;
  orgName: string;
  contractId: string;
  invoiceNumber: string;
  status: InvoiceStatus;
  currency: BillingCurrency;
  lineItems: LineItem[];
  subtotal: number; // cents
  tax: number; // cents
  taxRate: number; // percentage
  total: number; // cents
  dueDate: string;
  issuedAt: string;
  paidAt?: string;
  poNumber?: string;
  notes?: string;
}

export interface Contract {
  id: string;
  orgId: string;
  orgName: string;
  status: ContractStatus;
  tier: 'enterprise_business' | 'enterprise' | 'enterprise_plus';
  annualValue: number; // cents
  monthlyEquivalent: number; // cents
  includedEndpoints: number;
  startDate: string;
  endDate: string;
  autoRenew: boolean;
  poNumber?: string;
  compliance: string[];
  securityTier: string;
  deploymentModel: string;
  slaTier: string;
  implementationFee: number; // cents
  implementationPaid: boolean;
  createdAt: string;
}

/* ─── Pricing Constants ─── */

const BASE_ANNUAL_PRICING: Record<string, number> = {
  enterprise_business: 2400000, // $24,000/yr ($2,000/mo)
  enterprise: 6000000, // $60,000/yr ($5,000/mo)
  enterprise_plus: 12000000, // $120,000/yr ($10,000/mo)
};

const COMPLIANCE_ANNUAL_ADDONS: Record<string, number> = {
  pci_dss: 1200000, // $12,000/yr
  soc2: 1800000, // $18,000/yr
  gdpr: 600000, // $6,000/yr
  hipaa: 1200000, // $12,000/yr
};

const SECURITY_TIER_ADDONS: Record<string, number> = {
  hmac: 0,
  mtls: 2400000, // $24,000/yr
  mtls_hsm: 4800000, // $48,000/yr
};

const DEPLOYMENT_ADDONS: Record<string, number> = {
  cloud: 0,
  hybrid: 3600000, // $36,000/yr
  on_premise: 7200000, // $72,000/yr
};

const SLA_ADDONS: Record<string, number> = {
  standard: 0, // 99.9%
  premium: 1200000, // $12,000/yr → 99.95%
  platinum: 3600000, // $36,000/yr → 99.99%
};

/* ─── In-Memory Stores ─── */
const contractStore = new Map<string, Contract>();
const invoiceStore = new Map<string, Invoice>();
let invoiceCounter = 1000;

/* ─── Service ─── */

export class EnterpriseBillingService {
  /* ─── Create contract ─── */
  createContract(params: {
    orgId: string;
    orgName: string;
    tier: 'enterprise_business' | 'enterprise' | 'enterprise_plus';
    includedEndpoints: number;
    compliance: string[];
    securityTier: string;
    deploymentModel: string;
    slaTier: string;
    implementationFee?: number;
    poNumber?: string;
    durationMonths?: number;
  }): Contract {
    const now = new Date();
    const durationMonths = params.durationMonths ?? 12;
    const endDate = new Date(now);
    endDate.setMonth(endDate.getMonth() + durationMonths);

    // Calculate annual value
    let annualValue =
      BASE_ANNUAL_PRICING[params.tier] ??
      BASE_ANNUAL_PRICING.enterprise_business;
    params.compliance.forEach(c => {
      annualValue += COMPLIANCE_ANNUAL_ADDONS[c] ?? 0;
    });
    annualValue += SECURITY_TIER_ADDONS[params.securityTier] ?? 0;
    annualValue += DEPLOYMENT_ADDONS[params.deploymentModel] ?? 0;
    annualValue += SLA_ADDONS[params.slaTier] ?? 0;

    const contract: Contract = {
      id: `con_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      orgId: params.orgId,
      orgName: params.orgName,
      status: ContractStatus.ACTIVE,
      tier: params.tier,
      annualValue,
      monthlyEquivalent: Math.round(annualValue / 12),
      includedEndpoints: params.includedEndpoints,
      startDate: now.toISOString(),
      endDate: endDate.toISOString(),
      autoRenew: true,
      poNumber: params.poNumber,
      compliance: params.compliance,
      securityTier: params.securityTier,
      deploymentModel: params.deploymentModel,
      slaTier: params.slaTier,
      implementationFee: params.implementationFee ?? 0,
      implementationPaid: false,
      createdAt: now.toISOString(),
    };

    contractStore.set(contract.id, contract);
    logInfo('Enterprise contract created', {
      contractId: contract.id,
      orgId: params.orgId,
      tier: params.tier,
      annualValue: annualValue / 100,
    });
    return contract;
  }

  /* ─── Generate invoice ─── */
  generateInvoice(
    contractId: string,
    options?: { taxRate?: number; notes?: string; poNumber?: string }
  ): Invoice | null {
    const contract = contractStore.get(contractId);
    if (!contract) {
      logError('Contract not found for invoice generation', { contractId });
      return null;
    }

    const lineItems: LineItem[] = [];

    // Base platform fee
    lineItems.push({
      description: `DevFortress ${contract.tier.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())} — Annual License`,
      quantity: 1,
      unitPrice: BASE_ANNUAL_PRICING[contract.tier] ?? 0,
      total: BASE_ANNUAL_PRICING[contract.tier] ?? 0,
      type: 'base',
    });

    // Compliance add-ons
    contract.compliance.forEach(c => {
      const price = COMPLIANCE_ANNUAL_ADDONS[c] ?? 0;
      if (price > 0) {
        lineItems.push({
          description: `Compliance: ${c.toUpperCase().replace('_', '-')} Evidence & Reporting`,
          quantity: 1,
          unitPrice: price,
          total: price,
          type: 'compliance',
        });
      }
    });

    // Security tier
    const secPrice = SECURITY_TIER_ADDONS[contract.securityTier] ?? 0;
    if (secPrice > 0) {
      lineItems.push({
        description: `Security: ${contract.securityTier.toUpperCase()} Authentication`,
        quantity: 1,
        unitPrice: secPrice,
        total: secPrice,
        type: 'addon',
      });
    }

    // Deployment model
    const depPrice = DEPLOYMENT_ADDONS[contract.deploymentModel] ?? 0;
    if (depPrice > 0) {
      lineItems.push({
        description: `Deployment: ${contract.deploymentModel.replace('_', '-')} Model`,
        quantity: 1,
        unitPrice: depPrice,
        total: depPrice,
        type: 'addon',
      });
    }

    // SLA tier
    const slaPrice = SLA_ADDONS[contract.slaTier] ?? 0;
    if (slaPrice > 0) {
      lineItems.push({
        description: `SLA: ${contract.slaTier.charAt(0).toUpperCase() + contract.slaTier.slice(1)} Uptime Guarantee`,
        quantity: 1,
        unitPrice: slaPrice,
        total: slaPrice,
        type: 'addon',
      });
    }

    // Implementation fee (first invoice only)
    if (contract.implementationFee > 0 && !contract.implementationPaid) {
      lineItems.push({
        description: 'One-Time Implementation & Onboarding Fee',
        quantity: 1,
        unitPrice: contract.implementationFee,
        total: contract.implementationFee,
        type: 'implementation',
      });
    }

    // Calculate endpoint overage
    const usage = endpointMeteringService.calculateUsage(
      contract.orgId,
      contract.tier
    );
    if (usage.overageCharge > 0) {
      lineItems.push({
        description: `Endpoint Overage: ${usage.overageEndpoints} endpoints beyond ${usage.includedEndpoints} included`,
        quantity: usage.overageEndpoints,
        unitPrice: Math.round(usage.overageCharge / usage.overageEndpoints),
        total: usage.overageCharge,
        type: 'overage',
      });
    }

    const subtotal = lineItems.reduce((sum, item) => sum + item.total, 0);
    const taxRate = options?.taxRate ?? 0;
    const tax = Math.round(subtotal * (taxRate / 100));

    invoiceCounter += 1;
    const invoice: Invoice = {
      id: `inv_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      orgId: contract.orgId,
      orgName: contract.orgName,
      contractId: contract.id,
      invoiceNumber: `DF-${new Date().getFullYear()}-${String(invoiceCounter).padStart(4, '0')}`,
      status: InvoiceStatus.DRAFT,
      currency: BillingCurrency.USD,
      lineItems,
      subtotal,
      tax,
      taxRate,
      total: subtotal + tax,
      dueDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // Net-30
      issuedAt: new Date().toISOString(),
      poNumber: options?.poNumber ?? contract.poNumber,
      notes: options?.notes,
    };

    invoiceStore.set(invoice.id, invoice);
    logInfo('Invoice generated', {
      invoiceId: invoice.id,
      invoiceNumber: invoice.invoiceNumber,
      orgId: contract.orgId,
      total: invoice.total / 100,
      currency: invoice.currency,
    });
    return invoice;
  }

  /* ─── Get contract ─── */
  getContract(contractId: string): Contract | null {
    return contractStore.get(contractId) ?? null;
  }

  /* ─── Get contracts by org ─── */
  getContractsByOrg(orgId: string): Contract[] {
    return Array.from(contractStore.values()).filter(c => c.orgId === orgId);
  }

  /* ─── Get invoice ─── */
  getInvoice(invoiceId: string): Invoice | null {
    return invoiceStore.get(invoiceId) ?? null;
  }

  /* ─── Get invoices by org ─── */
  getInvoicesByOrg(orgId: string): Invoice[] {
    return Array.from(invoiceStore.values())
      .filter(i => i.orgId === orgId)
      .sort(
        (a, b) =>
          new Date(b.issuedAt).getTime() - new Date(a.issuedAt).getTime()
      );
  }

  /* ─── Mark invoice paid ─── */
  markPaid(invoiceId: string): Invoice | null {
    const invoice = invoiceStore.get(invoiceId);
    if (!invoice) return null;
    invoice.status = InvoiceStatus.PAID;
    invoice.paidAt = new Date().toISOString();
    invoiceStore.set(invoiceId, invoice);

    // Mark implementation fee as paid if applicable
    const contract = contractStore.get(invoice.contractId);
    if (contract && !contract.implementationPaid) {
      const hasImplLine = invoice.lineItems.some(
        li => li.type === 'implementation'
      );
      if (hasImplLine) {
        contract.implementationPaid = true;
        contractStore.set(contract.id, contract);
      }
    }

    logInfo('Invoice marked as paid', {
      invoiceId,
      invoiceNumber: invoice.invoiceNumber,
      orgId: invoice.orgId,
    });
    return invoice;
  }

  /* ─── Stats ─── */
  getStats(): {
    activeContracts: number;
    totalARR: number;
    unpaidInvoices: number;
    totalOutstanding: number;
  } {
    const contracts = Array.from(contractStore.values());
    const invoices = Array.from(invoiceStore.values());

    const activeContracts = contracts.filter(
      c => c.status === ContractStatus.ACTIVE
    );
    const totalARR = activeContracts.reduce((sum, c) => sum + c.annualValue, 0);
    const unpaid = invoices.filter(
      i => i.status === InvoiceStatus.SENT || i.status === InvoiceStatus.OVERDUE
    );
    const totalOutstanding = unpaid.reduce((sum, i) => sum + i.total, 0);

    return {
      activeContracts: activeContracts.length,
      totalARR: totalARR / 100,
      unpaidInvoices: unpaid.length,
      totalOutstanding: totalOutstanding / 100,
    };
  }
}

/* ─── Singleton ─── */
export const enterpriseBillingService = new EnterpriseBillingService();
