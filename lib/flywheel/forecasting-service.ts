import { logInfo, logWarn } from '@core/lib/logger';
import {
  generateForecast,
  getProactiveRecommendations,
  type ThreatForecast,
} from '@premium/learn/threat-forecaster';

export type ForecastTimeHorizon = '24h' | '7d' | '30d';

export interface ForecastRequestOptions {
  timeHorizon?: ForecastTimeHorizon;
  useAI?: boolean;
}

export interface ForecastWithRecommendations extends ThreatForecast {
  recommendations: Array<{
    id: string;
    recommendation: string;
    priority: 'HIGH' | 'MEDIUM' | 'LOW';
    relatedThreat: string;
  }>;
}

/**
 * Generate a forecast with AI mode enabled by default and attach proactive recommendations.
 */
export async function generateForecastWithAI(
  projectId: string,
  options: ForecastRequestOptions = {}
): Promise<ForecastWithRecommendations> {
  const { timeHorizon = '24h', useAI = true } = options;

  const forecast = await generateForecast(projectId, {
    timeHorizon,
    useAI,
  });

  // Recompute confidence using the spread of probabilities to give tighter feedback to users
  const avgProbability =
    forecast.predictions.length === 0
      ? 0
      : forecast.predictions.reduce((sum, p) => sum + p.probability, 0) /
        forecast.predictions.length;
  const adjustedConfidence = Math.min(0.95, 0.6 + avgProbability * 0.4);

  const recommendations = getProactiveRecommendations(forecast);

  const enriched: ForecastWithRecommendations = {
    ...forecast,
    confidence: Math.max(forecast.confidence, adjustedConfidence),
    methodology: useAI ? 'ml' : forecast.methodology,
    recommendations,
  };

  logInfo('Forecast with AI generated', {
    projectId,
    timeHorizon: enriched.timeHorizon,
    predictions: enriched.predictions.length,
    recommendations: enriched.recommendations.length,
    methodology: enriched.methodology,
    confidence: enriched.confidence,
  });

  return enriched;
}

/**
 * Safe helper that falls back to heuristic mode on failure without throwing.
 */
export async function safeForecastWithAI(
  projectId: string,
  options: ForecastRequestOptions = {}
): Promise<ForecastWithRecommendations> {
  try {
    return await generateForecastWithAI(projectId, options);
  } catch (error) {
    logWarn('AI forecast failed, falling back to heuristic', {
      projectId,
      error: error instanceof Error ? error.message : 'unknown',
    });

    const heuristic = await generateForecast(projectId, {
      timeHorizon: options.timeHorizon,
      useAI: false,
    });

    return {
      ...heuristic,
      methodology: 'heuristic',
      confidence: Math.max(heuristic.confidence, 0.65),
      recommendations: getProactiveRecommendations(heuristic),
    };
  }
}
