'use client';

import { useState, useEffect } from 'react';
import { logError } from '@core/lib/logger/client';

export default function HPSQuota() {
  const [quota, setQuota] = useState<{
    used: number;
    limit: number;
    credits: number;
  }>({ used: 0, limit: 0, credits: 0 });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchQuota();
  }, []);

  const fetchQuota = async () => {
    try {
      const res = await fetch('/api/hps/quota');
      if (res.ok) {
        const data = await res.json();
        setQuota(data);
      }
    } catch (error) {
      logError('Failed to fetch quota', error);
    } finally {
      setLoading(false);
    }
  };

  const handleBuyCredits = async () => {
    try {
      const res = await fetch('/api/hps/buy-credits', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount: 10 }),
      });
      if (res.ok) {
        const { url } = await res.json();
        if (url) window.location.href = url;
      } else {
        const data = await res.json();
        logError('Buy credits unavailable', data);
        alert(data.message || 'Credit purchases are temporarily unavailable.');
      }
    } catch (error) {
      logError('Failed to buy credits', error);
    }
  };

  if (loading) return <div>Loading quota...</div>;

  return (
    <div className="rounded-2xl border border-neutral-200 bg-neutral-50 p-6 dark:border-neutral-800 dark:bg-neutral-900">
      <h3 className="text-lg font-semibold">HPS Quota</h3>
      <p className="text-neutral-900 dark:text-white">
        Used: {quota.used} / {quota.limit}
      </p>
      <p className="text-neutral-900 dark:text-white">
        Credits: {quota.credits}
      </p>
      {quota.used >= quota.limit && (
        <button
          onClick={handleBuyCredits}
          className="mt-2 rounded-lg bg-primary-600 px-4 py-2 text-sm font-semibold text-white hover:bg-primary-700"
        >
          Buy More Credits
        </button>
      )}
    </div>
  );
}
