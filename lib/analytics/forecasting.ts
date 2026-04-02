/**
 * Advanced Analytics and Forecasting Service
 * AI/ML-powered forecasting for revenue, churn, and feature usage
 */

import { prisma } from '@core/lib/prisma';
import { logInfo, logError } from '@core/lib/logger';
import OpenAI from 'openai';

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

/**
 * Time series data point
 */
export interface TimeSeriesDataPoint {
  date: Date;
  value: number;
  metadata?: Record<string, unknown>;
}

/**
 * Forecast result
 */
export interface ForecastResult {
  predictions: TimeSeriesDataPoint[];
  confidence: number; // 0-1
  insights: string[];
  metrics: {
    mape?: number; // Mean Absolute Percentage Error
    rmse?: number; // Root Mean Squared Error
    trend: 'increasing' | 'decreasing' | 'stable';
    seasonality?: string;
  };
}

/**
 * Churn prediction result
 */
export interface ChurnPrediction {
  userId: string;
  churnProbability: number; // 0-1
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  factors: Array<{
    factor: string;
    impact: number; // -1 to 1
    description: string;
  }>;
  recommendations: string[];
}

/**
 * Feature usage insights
 */
export interface FeatureUsageInsight {
  feature: string;
  totalUsers: number;
  activeUsers: number;
  adoptionRate: number; // 0-1
  trend: 'growing' | 'declining' | 'stable';
  predictions: {
    nextMonth: number;
    nextQuarter: number;
  };
  insights: string[];
}

/**
 * Revenue analytics
 */
export interface RevenueAnalytics {
  current: {
    mrr: number; // Monthly Recurring Revenue
    arr: number; // Annual Recurring Revenue
    averageRevenuePerUser: number;
    totalRevenue: number;
  };
  forecast: {
    nextMonth: number;
    nextQuarter: number;
    nextYear: number;
    confidence: number;
  };
  insights: string[];
}

/**
 * Advanced Analytics Service
 */
export class AdvancedAnalyticsService {
  /**
   * Forecast revenue using historical data and AI
   */
  static async forecastRevenue(
    lookbackMonths: number = 12,
    forecastMonths: number = 3
  ): Promise<ForecastResult> {
    try {
      // Get historical revenue data
      const historicalData = await this.getHistoricalRevenue(lookbackMonths);

      if (historicalData.length === 0) {
        throw new Error('Insufficient historical data for forecasting');
      }

      // Use AI to analyze trends and generate forecast
      const aiAnalysis = await this.getAIForecast(
        historicalData,
        forecastMonths,
        'revenue'
      );

      // Apply simple trend analysis as fallback
      const predictions = this.generateTrendPredictions(
        historicalData,
        forecastMonths
      );

      const trend = this.calculateTrend(historicalData);
      const confidence = this.calculateConfidence(historicalData);

      logInfo('Revenue forecast generated', {
        lookbackMonths,
        forecastMonths,
        confidence,
      });

      return {
        predictions,
        confidence,
        insights: aiAnalysis.insights,
        metrics: {
          trend,
          mape: this.calculateMAPE(historicalData, predictions),
        },
      };
    } catch (error) {
      logError('Failed to forecast revenue', error);
      throw new Error('Failed to generate revenue forecast');
    }
  }

  /**
   * Predict user churn using engagement metrics
   */
  static async predictChurn(userId?: string): Promise<ChurnPrediction[]> {
    try {
      const users = userId
        ? [await this.getUserEngagementData(userId)]
        : await this.getAllUsersEngagementData();

      const predictions: ChurnPrediction[] = [];

      for (const user of users) {
        if (!user) continue;

        const churnProbability = await this.calculateChurnProbability(user);
        const riskLevel = this.getRiskLevel(churnProbability);
        const factors = this.identifyChurnFactors(user);
        const recommendations = this.generateChurnRecommendations(
          factors,
          riskLevel
        );

        predictions.push({
          userId: user.id,
          churnProbability,
          riskLevel,
          factors,
          recommendations,
        });
      }

      logInfo('Churn predictions generated', { count: predictions.length });
      return predictions.sort(
        (a, b) => b.churnProbability - a.churnProbability
      );
    } catch (error) {
      logError('Failed to predict churn', error);
      throw new Error('Failed to generate churn predictions');
    }
  }

  /**
   * Analyze feature usage trends and predict adoption
   */
  static async analyzeFeatureUsage(): Promise<FeatureUsageInsight[]> {
    try {
      const features = [
        'api_generation',
        'security_scan',
        'honeypot',
        'github_integration',
        'threat_detection',
        'documentation',
        'monitoring',
      ];

      const insights: FeatureUsageInsight[] = [];

      for (const feature of features) {
        const usageData = await this.getFeatureUsageData(feature);
        const trend = this.calculateTrend(usageData);
        const predictions = this.predictFeatureUsage(usageData);

        const totalUsers = await prisma.user.count();
        const activeUsers = usageData[usageData.length - 1]?.value || 0;
        const adoptionRate = totalUsers > 0 ? activeUsers / totalUsers : 0;

        insights.push({
          feature,
          totalUsers,
          activeUsers,
          adoptionRate,
          trend:
            trend === 'increasing'
              ? 'growing'
              : trend === 'decreasing'
                ? 'declining'
                : 'stable',
          predictions,
          insights: await this.getFeatureInsights(feature, usageData, trend),
        });
      }

      logInfo('Feature usage analysis complete', { features: insights.length });
      return insights;
    } catch (error) {
      logError('Failed to analyze feature usage', error);
      throw new Error('Failed to analyze feature usage');
    }
  }

  /**
   * Get comprehensive revenue analytics
   */
  static async getRevenueAnalytics(): Promise<RevenueAnalytics> {
    try {
      // Get current revenue metrics
      const subscriptions = await prisma.subscription.findMany({
        where: {
          status: 'ACTIVE',
        },
        include: {
          user: true,
        },
      });

      const creditTransactions = await prisma.creditTransaction.findMany({
        where: {
          type: 'PURCHASE',
          createdAt: {
            gte: new Date(new Date().setMonth(new Date().getMonth() - 1)),
          },
        },
      });

      // Calculate MRR based on subscription plans
      const mrr = subscriptions.reduce((sum, sub) => {
        const planRevenue = this.getPlanMonthlyRevenue(sub.plan);
        return sum + planRevenue;
      }, 0);

      const arr = mrr * 12;
      const totalRevenue = creditTransactions.reduce(
        (sum, tx) => sum + tx.amount,
        0
      );
      const averageRevenuePerUser =
        subscriptions.length > 0 ? mrr / subscriptions.length : 0;

      // Generate forecast
      const forecastData = await this.forecastRevenue(12, 12);
      const nextMonthPrediction = forecastData.predictions[0]?.value || mrr;
      const nextQuarterPrediction =
        forecastData.predictions[2]?.value || mrr * 3;
      const nextYearPrediction = forecastData.predictions[11]?.value || arr;

      const analytics: RevenueAnalytics = {
        current: {
          mrr,
          arr,
          averageRevenuePerUser,
          totalRevenue,
        },
        forecast: {
          nextMonth: nextMonthPrediction,
          nextQuarter: nextQuarterPrediction,
          nextYear: nextYearPrediction,
          confidence: forecastData.confidence,
        },
        insights: forecastData.insights,
      };

      logInfo('Revenue analytics calculated', { mrr, arr });
      return analytics;
    } catch (error) {
      logError('Failed to get revenue analytics', error);
      throw new Error('Failed to calculate revenue analytics');
    }
  }

  /**
   * Get historical revenue data
   */
  private static async getHistoricalRevenue(
    months: number
  ): Promise<TimeSeriesDataPoint[]> {
    const data: TimeSeriesDataPoint[] = [];
    const now = new Date();

    for (let i = months - 1; i >= 0; i--) {
      const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const nextMonth = new Date(now.getFullYear(), now.getMonth() - i + 1, 1);

      const transactions = await prisma.creditTransaction.findMany({
        where: {
          type: 'PURCHASE',
          createdAt: {
            gte: date,
            lt: nextMonth,
          },
        },
      });

      const revenue = transactions.reduce((sum, tx) => sum + tx.amount, 0);

      data.push({
        date,
        value: revenue,
        metadata: {
          transactionCount: transactions.length,
        },
      });
    }

    return data;
  }

  /**
   * Use OpenAI to generate forecast insights
   */
  private static async getAIForecast(
    historicalData: TimeSeriesDataPoint[],
    forecastMonths: number,
    type: string
  ): Promise<{ insights: string[] }> {
    try {
      const dataString = historicalData
        .map(d => `${d.date.toISOString().split('T')[0]}: ${d.value}`)
        .join('\n');

      const prompt = `Analyze this ${type} data and provide insights:

${dataString}

Provide:
1. Key trends observed
2. Seasonal patterns if any
3. Forecast insights for the next ${forecastMonths} months
4. Potential risks or opportunities

Format as JSON with an array of insight strings.`;

      const response = await openai.chat.completions.create({
        model: 'gpt-4o-mini',
        messages: [
          {
            role: 'system',
            content:
              'You are a data analytics expert specializing in business forecasting.',
          },
          { role: 'user', content: prompt },
        ],
        temperature: 0.3,
        response_format: { type: 'json_object' },
      });

      const result = JSON.parse(
        response.choices[0].message.content || '{"insights":[]}'
      );
      return { insights: result.insights || [] };
    } catch (error) {
      logError('Failed to get AI forecast', error);
      return { insights: ['AI analysis unavailable'] };
    }
  }

  /**
   * Generate trend-based predictions
   */
  private static generateTrendPredictions(
    historicalData: TimeSeriesDataPoint[],
    forecastMonths: number
  ): TimeSeriesDataPoint[] {
    if (historicalData.length < 2) {
      return [];
    }

    // Simple linear regression
    const n = historicalData.length;
    const xSum = (n * (n - 1)) / 2;
    const ySum = historicalData.reduce((sum, d) => sum + d.value, 0);
    const xySum = historicalData.reduce((sum, d, i) => sum + i * d.value, 0);
    const xSquaredSum = (n * (n - 1) * (2 * n - 1)) / 6;

    const slope = (n * xySum - xSum * ySum) / (n * xSquaredSum - xSum * xSum);
    const intercept = (ySum - slope * xSum) / n;

    const predictions: TimeSeriesDataPoint[] = [];
    const lastDate = historicalData[historicalData.length - 1].date;

    for (let i = 1; i <= forecastMonths; i++) {
      const predictedValue = Math.max(0, slope * (n + i - 1) + intercept);
      const date = new Date(lastDate.getFullYear(), lastDate.getMonth() + i, 1);

      predictions.push({
        date,
        value: predictedValue,
      });
    }

    return predictions;
  }

  /**
   * Calculate trend direction
   */
  private static calculateTrend(
    data: TimeSeriesDataPoint[]
  ): 'increasing' | 'decreasing' | 'stable' {
    if (data.length < 2) return 'stable';

    const first = data.slice(0, Math.floor(data.length / 2));
    const second = data.slice(Math.floor(data.length / 2));

    const firstAvg = first.reduce((sum, d) => sum + d.value, 0) / first.length;
    const secondAvg =
      second.reduce((sum, d) => sum + d.value, 0) / second.length;

    const change = (secondAvg - firstAvg) / firstAvg;

    if (change > 0.1) return 'increasing';
    if (change < -0.1) return 'decreasing';
    return 'stable';
  }

  /**
   * Calculate forecast confidence
   */
  private static calculateConfidence(data: TimeSeriesDataPoint[]): number {
    if (data.length < 3) return 0.3;

    // Calculate variance
    const mean = data.reduce((sum, d) => sum + d.value, 0) / data.length;
    const variance =
      data.reduce((sum, d) => sum + Math.pow(d.value - mean, 2), 0) /
      data.length;
    const stdDev = Math.sqrt(variance);
    const coefficientOfVariation = mean !== 0 ? stdDev / mean : 1;

    // Lower CV = higher confidence
    const confidence = Math.max(
      0.3,
      Math.min(0.95, 1 - coefficientOfVariation)
    );
    return confidence;
  }

  /**
   * Calculate Mean Absolute Percentage Error
   */
  private static calculateMAPE(
    actual: TimeSeriesDataPoint[],
    predicted: TimeSeriesDataPoint[]
  ): number {
    if (actual.length === 0) return 0;

    const errors = actual.map((a, i) => {
      const p = predicted[i]?.value || a.value;
      return Math.abs((a.value - p) / Math.max(a.value, 1));
    });

    return errors.reduce((sum, e) => sum + e, 0) / errors.length;
  }

  /**
   * Get user engagement data for churn prediction
   */
  private static async getUserEngagementData(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        apiProjects: true,
        subscriptions: true,
        creditBalance: true,
        auditLogs: {
          where: {
            createdAt: {
              gte: new Date(new Date().setDate(new Date().getDate() - 30)),
            },
          },
        },
      },
    });

    return user;
  }

  /**
   * Get engagement data for all users
   */
  private static async getAllUsersEngagementData() {
    const users = await prisma.user.findMany({
      include: {
        apiProjects: true,
        subscriptions: true,
        creditBalance: true,
        auditLogs: {
          where: {
            createdAt: {
              gte: new Date(new Date().setDate(new Date().getDate() - 30)),
            },
          },
        },
      },
      take: 100, // Limit for performance
    });

    return users;
  }

  /**
   * Calculate churn probability based on engagement metrics
   */
  private static async calculateChurnProbability(user: {
    id: string;
    createdAt: Date;
    lastLoginAt: Date | null;
    apiProjects: unknown[];
    subscriptions: { status: string }[];
    creditBalance: { available: number; consumed: number } | null;
    auditLogs: unknown[];
  }): Promise<number> {
    let churnScore = 0;

    // Factor 1: Last login (30%)
    const daysSinceLogin = user.lastLoginAt
      ? (Date.now() - user.lastLoginAt.getTime()) / (1000 * 60 * 60 * 24)
      : 999;

    if (daysSinceLogin > 30) churnScore += 0.3;
    else if (daysSinceLogin > 14) churnScore += 0.15;
    else if (daysSinceLogin > 7) churnScore += 0.05;

    // Factor 2: API project activity (25%)
    const hasActiveProjects = user.apiProjects.length > 0;
    if (!hasActiveProjects) churnScore += 0.25;

    // Factor 3: Subscription status (25%)
    const hasActiveSubscription = user.subscriptions.some(
      s => s.status === 'ACTIVE'
    );
    if (!hasActiveSubscription) churnScore += 0.25;

    // Factor 4: Recent activity (20%)
    const recentActivityCount = user.auditLogs.length;
    if (recentActivityCount === 0) churnScore += 0.2;
    else if (recentActivityCount < 5) churnScore += 0.1;

    return Math.min(1, churnScore);
  }

  /**
   * Determine risk level from churn probability
   */
  private static getRiskLevel(
    probability: number
  ): 'low' | 'medium' | 'high' | 'critical' {
    if (probability >= 0.75) return 'critical';
    if (probability >= 0.5) return 'high';
    if (probability >= 0.25) return 'medium';
    return 'low';
  }

  /**
   * Identify factors contributing to churn
   */
  private static identifyChurnFactors(user: {
    lastLoginAt: Date | null;
    apiProjects: unknown[];
    subscriptions: { status: string }[];
    auditLogs: unknown[];
  }): Array<{ factor: string; impact: number; description: string }> {
    const factors = [];

    const daysSinceLogin = user.lastLoginAt
      ? (Date.now() - user.lastLoginAt.getTime()) / (1000 * 60 * 60 * 24)
      : 999;

    if (daysSinceLogin > 14) {
      factors.push({
        factor: 'inactivity',
        impact: 0.3,
        description: `No login for ${Math.floor(daysSinceLogin)} days`,
      });
    }

    if (user.apiProjects.length === 0) {
      factors.push({
        factor: 'no_projects',
        impact: 0.25,
        description: 'No API projects created',
      });
    }

    const hasActiveSubscription = user.subscriptions.some(
      s => s.status === 'ACTIVE'
    );
    if (!hasActiveSubscription) {
      factors.push({
        factor: 'no_subscription',
        impact: 0.25,
        description: 'No active subscription',
      });
    }

    if (user.auditLogs.length < 5) {
      factors.push({
        factor: 'low_engagement',
        impact: 0.2,
        description: 'Low platform activity in last 30 days',
      });
    }

    return factors;
  }

  /**
   * Generate recommendations to reduce churn
   */
  private static generateChurnRecommendations(
    factors: Array<{ factor: string }>,
    riskLevel: string
  ): string[] {
    const recommendations: string[] = [];

    if (factors.some(f => f.factor === 'inactivity')) {
      recommendations.push(
        'Send re-engagement email with new features highlight'
      );
      recommendations.push('Offer limited-time discount or bonus credits');
    }

    if (factors.some(f => f.factor === 'no_projects')) {
      recommendations.push('Provide onboarding tutorial or quick-start guide');
      recommendations.push(
        'Offer free API generation credits to encourage first project'
      );
    }

    if (factors.some(f => f.factor === 'no_subscription')) {
      recommendations.push('Highlight subscription benefits and ROI');
      recommendations.push('Offer trial period for premium features');
    }

    if (factors.some(f => f.factor === 'low_engagement')) {
      recommendations.push('Send educational content about platform features');
      recommendations.push('Schedule product demo or consultation call');
    }

    if (riskLevel === 'critical') {
      recommendations.push('🚨 Priority: Immediate personal outreach required');
    }

    return recommendations;
  }

  /**
   * Get feature usage data
   */
  private static async getFeatureUsageData(
    feature: string
  ): Promise<TimeSeriesDataPoint[]> {
    const data: TimeSeriesDataPoint[] = [];
    const now = new Date();

    for (let i = 11; i >= 0; i--) {
      const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const nextMonth = new Date(now.getFullYear(), now.getMonth() - i + 1, 1);

      const count = await prisma.auditLog.count({
        where: {
          message: {
            contains: feature.toUpperCase(),
            mode: 'insensitive',
          },
          createdAt: {
            gte: date,
            lt: nextMonth,
          },
        },
      });

      data.push({
        date,
        value: count,
      });
    }

    return data;
  }

  /**
   * Predict future feature usage
   */
  private static predictFeatureUsage(data: TimeSeriesDataPoint[]): {
    nextMonth: number;
    nextQuarter: number;
  } {
    const predictions = this.generateTrendPredictions(data, 3);

    return {
      nextMonth: predictions[0]?.value || 0,
      nextQuarter: predictions.reduce((sum, p) => sum + p.value, 0),
    };
  }

  /**
   * Get AI-powered insights for feature usage
   */
  private static async getFeatureInsights(
    feature: string,
    data: TimeSeriesDataPoint[],
    trend: 'increasing' | 'decreasing' | 'stable'
  ): Promise<string[]> {
    const insights: string[] = [];

    const latestValue = data[data.length - 1]?.value || 0;
    const previousValue = data[data.length - 2]?.value || 0;
    const change =
      previousValue !== 0
        ? ((latestValue - previousValue) / previousValue) * 100
        : 0;

    if (trend === 'increasing') {
      insights.push(
        `${feature} usage is growing (${change.toFixed(1)}% month-over-month)`
      );
      insights.push(
        'Consider expanding feature capabilities to support growth'
      );
    } else if (trend === 'decreasing') {
      insights.push(
        `${feature} usage is declining (${change.toFixed(1)}% month-over-month)`
      );
      insights.push('Investigate user feedback and consider improvements');
    } else {
      insights.push(`${feature} usage is stable`);
      insights.push('Monitor for opportunities to drive adoption');
    }

    return insights;
  }

  /**
   * Get monthly revenue for a subscription plan
   */
  private static getPlanMonthlyRevenue(plan: string): number {
    const planPricing: Record<string, number> = {
      FREE: 0,
      STARTER: 99,
      PRO: 199,
      TEAM: 499,
      ENTERPRISE: 499, // Legacy alias for TEAM
      BUSINESS: 2000,
      ENTERPRISE_PLUS: 5000,
    };

    return planPricing[plan] || 0;
  }
}
