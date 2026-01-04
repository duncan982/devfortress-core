/**
 * Operation Costs Simulation Service
 *
 * Simulates operational costs for APIForge based on customer projections,
 * infrastructure scaling, and cost optimization strategies.
 *
 * Based on PRICING-ANALYSIS-2025-12-10.md bootstrap model.
 */

import { logInfo, logError } from '@core/lib/logger';

export interface CostSimulationInput {
  /** Number of paying customers */
  payingCustomers: number;
  /** Customer mix: percentage of STARTER/PRO/ENTERPRISE customers */
  customerMix: {
    starter: number; // percentage (0-1)
    pro: number; // percentage (0-1)
    enterprise: number; // percentage (0-1)
  };
  /** Average usage per customer type (API generations per month) */
  averageUsage: {
    starter: number;
    pro: number;
    enterprise: number;
  };
  /** Growth projection (months to simulate) */
  projectionMonths: number;
  /** Growth rate per month (as decimal, e.g., 0.1 for 10%) */
  monthlyGrowthRate: number;
}

export interface MonthlyCostBreakdown {
  /** Month number (1-based) */
  month: number;
  /** Number of paying customers this month */
  customers: number;
  /** Monthly Recurring Revenue */
  mrr: number;

  /** Infrastructure costs */
  infrastructure: {
    vercel: number;
    supabase: number;
    sentry: number;
    total: number;
  };

  /** Variable costs (OpenAI API) */
  variableCosts: {
    openai: number;
    total: number;
  };

  /** Personnel costs */
  personnel: {
    founder: number;
    total: number;
  };

  /** Total costs */
  totalCosts: number;
  /** Net profit/loss */
  netProfit: number;
  /** Profit margin percentage */
  profitMargin: number;
}

export interface CostSimulationResult {
  /** Monthly breakdowns */
  monthlyBreakdown: MonthlyCostBreakdown[];
  /** Summary statistics */
  summary: {
    totalRevenue: number;
    totalCosts: number;
    totalProfit: number;
    averageProfitMargin: number;
    breakEvenMonth: number;
    profitableMonths: number;
  };
  /** Key insights and recommendations */
  insights: string[];
}

export class OperationCostsSimulationService {
  // Pricing constants (aligned with SUBSCRIPTION_PRICING)
  private static readonly PRICING = {
    STARTER: 99,
    PRO: 199,
    ENTERPRISE: 499,
  };

  // OpenAI cost per generation
  private static readonly OPENAI_COST_PER_GENERATION = 0.30;

  // Infrastructure cost tiers
  private static readonly INFRASTRUCTURE_COSTS = {
    // Phase 1: Free tiers ($0)
    FREE: {
      vercel: 0,
      supabase: 0,
      sentry: 0,
    },
    // Phase 2: Paid tiers ($71/mo)
    PAID: {
      vercel: 20,
      supabase: 25,
      sentry: 26,
    },
  };

  // Infrastructure upgrade triggers
  private static readonly UPGRADE_TRIGGERS = {
    INFRASTRUCTURE_UPGRADE: 20, // customers
    FOUNDER_SALARY: 33, // customers for $3K MRR
  };

  /**
   * Run cost simulation based on input parameters
   */
  static simulateCosts(input: CostSimulationInput): CostSimulationResult {
    try {
      logInfo('Running operation costs simulation', {
        payingCustomers: input.payingCustomers,
        projectionMonths: input.projectionMonths,
      });

      const monthlyBreakdown: MonthlyCostBreakdown[] = [];
      let currentCustomers = input.payingCustomers;

      for (let month = 1; month <= input.projectionMonths; month++) {
        const breakdown = this.calculateMonthlyCosts(
          month,
          currentCustomers,
          input.customerMix,
          input.averageUsage
        );

        monthlyBreakdown.push(breakdown);

        // Apply growth for next month
        currentCustomers = Math.round(currentCustomers * (1 + input.monthlyGrowthRate));
      }

      const summary = this.calculateSummary(monthlyBreakdown);
      const insights = this.generateInsights(monthlyBreakdown, summary, input);

      return {
        monthlyBreakdown,
        summary,
        insights,
      };
    } catch (error) {
      logError('Failed to run cost simulation', { error, input });
      throw error;
    }
  }

  /**
   * Calculate costs for a specific month
   */
  private static calculateMonthlyCosts(
    month: number,
    customers: number,
    customerMix: CostSimulationInput['customerMix'],
    averageUsage: CostSimulationInput['averageUsage']
  ): MonthlyCostBreakdown {
    // Calculate customer distribution
    const starterCustomers = Math.round(customers * customerMix.starter);
    const proCustomers = Math.round(customers * customerMix.pro);
    const enterpriseCustomers = Math.round(customers * customerMix.enterprise);

    // Calculate MRR
    const mrr =
      starterCustomers * this.PRICING.STARTER +
      proCustomers * this.PRICING.PRO +
      enterpriseCustomers * this.PRICING.ENTERPRISE;

    // Determine infrastructure tier
    const usePaidInfrastructure = customers >= this.UPGRADE_TRIGGERS.INFRASTRUCTURE_UPGRADE;
    const infraCosts = usePaidInfrastructure
      ? this.INFRASTRUCTURE_COSTS.PAID
      : this.INFRASTRUCTURE_COSTS.FREE;

    // Calculate OpenAI costs
    const openaiCost =
      starterCustomers * averageUsage.starter * this.OPENAI_COST_PER_GENERATION +
      proCustomers * averageUsage.pro * this.OPENAI_COST_PER_GENERATION +
      enterpriseCustomers * averageUsage.enterprise * this.OPENAI_COST_PER_GENERATION;

    // Calculate personnel costs
    const founderSalary = mrr >= 3000 ? 3000 : 0; // $3K when MRR >= $3K

    const totalCosts = infraCosts.vercel + infraCosts.supabase + infraCosts.sentry + openaiCost + founderSalary;
    const netProfit = mrr - totalCosts;
    const profitMargin = mrr > 0 ? (netProfit / mrr) * 100 : 0;

    return {
      month,
      customers,
      mrr,
      infrastructure: {
        vercel: infraCosts.vercel,
        supabase: infraCosts.supabase,
        sentry: infraCosts.sentry,
        total: infraCosts.vercel + infraCosts.supabase + infraCosts.sentry,
      },
      variableCosts: {
        openai: openaiCost,
        total: openaiCost,
      },
      personnel: {
        founder: founderSalary,
        total: founderSalary,
      },
      totalCosts,
      netProfit,
      profitMargin,
    };
  }

  /**
   * Calculate summary statistics
   */
  private static calculateSummary(breakdown: MonthlyCostBreakdown[]) {
    const totalRevenue = breakdown.reduce((sum, month) => sum + month.mrr, 0);
    const totalCosts = breakdown.reduce((sum, month) => sum + month.totalCosts, 0);
    const totalProfit = totalRevenue - totalCosts;
    const averageProfitMargin = breakdown.reduce((sum, month) => sum + month.profitMargin, 0) / breakdown.length;

    // Find break-even month (first month with positive profit)
    const breakEvenMonth = breakdown.findIndex(month => month.netProfit > 0) + 1;

    // Count profitable months
    const profitableMonths = breakdown.filter(month => month.netProfit > 0).length;

    return {
      totalRevenue,
      totalCosts,
      totalProfit,
      averageProfitMargin,
      breakEvenMonth: breakEvenMonth || breakdown.length + 1, // If never profitable, set to after projection
      profitableMonths,
    };
  }

  /**
   * Generate insights and recommendations
   */
  private static generateInsights(
    breakdown: MonthlyCostBreakdown[],
    summary: CostSimulationResult['summary'],
    input: CostSimulationInput
  ): string[] {
    const insights: string[] = [];

    // Profitability insights
    if (summary.totalProfit > 0) {
      insights.push(`✅ **Overall Profitable**: $${summary.totalProfit.toFixed(2)} profit over ${input.projectionMonths} months`);
    } else {
      insights.push(`❌ **Overall Loss**: $${Math.abs(summary.totalProfit).toFixed(2)} loss over ${input.projectionMonths} months`);
    }

    // Break-even analysis
    if (summary.breakEvenMonth <= input.projectionMonths) {
      insights.push(`📈 **Break-even achieved** in month ${summary.breakEvenMonth}`);
    } else {
      insights.push(`⚠️ **No break-even** within ${input.projectionMonths} months`);
    }

    // Growth insights
    const finalMonth = breakdown[breakdown.length - 1];
    const initialMonth = breakdown[0];
    const growthRate = ((finalMonth.customers - initialMonth.customers) / initialMonth.customers) * 100;

    insights.push(`📊 **Customer growth**: ${initialMonth.customers} → ${finalMonth.customers} customers (${growthRate.toFixed(1)}%)`);

    // Cost efficiency
    const avgMargin = summary.averageProfitMargin;
    if (avgMargin > 50) {
      insights.push(`💰 **Excellent margins**: ${avgMargin.toFixed(1)}% average profit margin`);
    } else if (avgMargin > 20) {
      insights.push(`👍 **Good margins**: ${avgMargin.toFixed(1)}% average profit margin`);
    } else if (avgMargin > 0) {
      insights.push(`⚠️ **Thin margins**: ${avgMargin.toFixed(1)}% average profit margin`);
    } else {
      insights.push(`❌ **Loss-making**: ${avgMargin.toFixed(1)}% average profit margin`);
    }

    // Infrastructure timing
    const infraUpgradeMonth = breakdown.findIndex(month => month.customers >= this.UPGRADE_TRIGGERS.INFRASTRUCTURE_UPGRADE) + 1;
    if (infraUpgradeMonth > 0 && infraUpgradeMonth <= input.projectionMonths) {
      insights.push(`🏗️ **Infrastructure upgrade** triggered in month ${infraUpgradeMonth} (${breakdown[infraUpgradeMonth - 1].customers} customers)`);
    }

    // Founder salary timing
    const salaryMonth = breakdown.findIndex(month => month.mrr >= 3000) + 1;
    if (salaryMonth > 0 && salaryMonth <= input.projectionMonths) {
      insights.push(`💼 **Founder salary** starts in month ${salaryMonth} (MRR: $${breakdown[salaryMonth - 1].mrr})`);
    }

    return insights;
  }

  /**
   * Quick simulation with default conservative parameters
   */
  static quickSimulation(startingCustomers: number = 5, months: number = 12): CostSimulationResult {
    return this.simulateCosts({
      payingCustomers: startingCustomers,
      customerMix: {
        starter: 0.8, // 80% starter
        pro: 0.15, // 15% pro
        enterprise: 0.05, // 5% enterprise
      },
      averageUsage: {
        starter: 20, // 20 generations/mo (below limit)
        pro: 40, // 40 generations/mo
        enterprise: 150, // 150 generations/mo
      },
      projectionMonths: months,
      monthlyGrowthRate: 0.1, // 10% monthly growth
    });
  }
}