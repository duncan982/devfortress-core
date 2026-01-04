/**
 * Anomaly Detection Dashboard Component
 * Displays anomaly statistics and allows training management
 */

'use client';

import { useState, useEffect } from 'react';
import { Button } from '@core/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@core/components/ui/card';
import { Badge } from '@core/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from '@core/components/ui/alert';
import { Loader2, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';

interface AnomalyStats {
  totalAnomalies: number;
  validatedAnomalies: number;
  accuracy: number;
  recentAnomalies: Array<{
    id: string;
    honeypot: { id: string; name: string; slug: string };
    sourceIp: string;
    type: string;
    confidence: number;
    severity: string;
    detectedAt: Date;
    validated: boolean | null;
  }>;
}

interface TrainingStatus {
  isTraining: boolean;
  progress?: string;
  error?: string;
  success?: {
    accuracy: number;
    falsePositiveRate: number;
  };
}

export function AnomalyDetectionDashboard({
  honeypotId,
}: {
  honeypotId?: string;
}) {
  const [stats, setStats] = useState<AnomalyStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [trainingStatus, setTrainingStatus] = useState<TrainingStatus>({
    isTraining: false,
  });

  const fetchStats = async () => {
    try {
      setLoading(true);
      const url = honeypotId
        ? `/api/anomaly-detection?honeypotId=${honeypotId}`
        : '/api/anomaly-detection';

      const response = await fetch(url);
      const data = await response.json();

      if (data.success) {
        setStats(data.stats);
      }
    } catch {
      // Error handled silently
    } finally {
      setLoading(false);
    }
  };

  const handleTrainModel = async () => {
    try {
      setTrainingStatus({
        isTraining: true,
        progress: 'Initiating training...',
      });

      const response = await fetch('/api/anomaly-detection/train', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ honeypotId }),
      });

      const data = await response.json();

      if (data.success) {
        setTrainingStatus({
          isTraining: false,
          success: data.metrics,
        });
        // Refresh stats after training
        await fetchStats();
      } else {
        setTrainingStatus({
          isTraining: false,
          error: data.error || 'Training failed',
        });
      }
    } catch {
      setTrainingStatus({
        isTraining: false,
        error: 'Failed to train model',
      });
    }
  };

  useEffect(() => {
    fetchStats();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [honeypotId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!stats) {
    return (
      <Alert>
        <AlertTriangle className="h-4 w-4" />
        <AlertTitle>Error</AlertTitle>
        <AlertDescription>
          Failed to load anomaly detection statistics
        </AlertDescription>
      </Alert>
    );
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'destructive';
      case 'HIGH':
        return 'destructive';
      case 'MEDIUM':
        return 'default';
      case 'LOW':
        return 'secondary';
      default:
        return 'default';
    }
  };

  return (
    <div className="space-y-6">
      {/* Training Status */}
      {trainingStatus.success && (
        <Alert className="border-green-500">
          <CheckCircle className="h-4 w-4 text-green-500" />
          <AlertTitle>Training Complete</AlertTitle>
          <AlertDescription>
            Model updated with{' '}
            {(trainingStatus.success.accuracy * 100).toFixed(1)}% accuracy and{' '}
            {(trainingStatus.success.falsePositiveRate * 100).toFixed(2)}% false
            positive rate.
          </AlertDescription>
        </Alert>
      )}

      {trainingStatus.error && (
        <Alert variant="destructive">
          <XCircle className="h-4 w-4" />
          <AlertTitle>Training Failed</AlertTitle>
          <AlertDescription>{trainingStatus.error}</AlertDescription>
        </Alert>
      )}

      {/* Statistics Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Total Anomalies</CardDescription>
            <CardTitle className="text-3xl">{stats.totalAnomalies}</CardTitle>
          </CardHeader>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Validated</CardDescription>
            <CardTitle className="text-3xl">
              {stats.validatedAnomalies}
            </CardTitle>
          </CardHeader>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Accuracy</CardDescription>
            <CardTitle className="text-3xl">
              {(stats.accuracy * 100).toFixed(1)}%
            </CardTitle>
          </CardHeader>
        </Card>
      </div>

      {/* Training Button */}
      <Card>
        <CardHeader>
          <CardTitle>Model Training</CardTitle>
          <CardDescription>
            Train the anomaly detection model with validated data. Requires at
            least 100 validated samples.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button
            onClick={handleTrainModel}
            disabled={
              trainingStatus.isTraining || stats.validatedAnomalies < 100
            }
          >
            {trainingStatus.isTraining ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Training in progress...
              </>
            ) : (
              'Train Model'
            )}
          </Button>
          {stats.validatedAnomalies < 100 && (
            <p className="mt-2 text-sm text-muted-foreground">
              Need {100 - stats.validatedAnomalies} more validated samples to
              train
            </p>
          )}
        </CardContent>
      </Card>

      {/* Recent Anomalies */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Anomalies</CardTitle>
          <CardDescription>
            Latest detected anomalies across your honeypots
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {stats.recentAnomalies.length === 0 ? (
              <p className="text-center text-muted-foreground">
                No anomalies detected
              </p>
            ) : (
              stats.recentAnomalies.map(anomaly => (
                <div
                  key={anomaly.id}
                  className="flex items-center justify-between rounded-lg border p-4"
                >
                  <div className="flex-1 space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">
                        {anomaly.honeypot.name}
                      </span>
                      <Badge variant={getSeverityColor(anomaly.severity)}>
                        {anomaly.severity}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {anomaly.type} from {anomaly.sourceIp}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Confidence: {(anomaly.confidence * 100).toFixed(0)}%
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    {anomaly.validated === true && (
                      <Badge variant="outline" className="text-green-500">
                        <CheckCircle className="mr-1 h-3 w-3" />
                        Validated
                      </Badge>
                    )}
                    {anomaly.validated === false && (
                      <Badge variant="outline" className="text-red-500">
                        <XCircle className="mr-1 h-3 w-3" />
                        False Positive
                      </Badge>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
