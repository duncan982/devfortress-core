
'use client';

import { useCallback, useEffect, useRef } from 'react';
import { useAuthSession } from '@core/components/providers/session-provider';

interface InactivityHandlerProps {
  timeoutMinutes: number;
}

const activityEvents: Array<keyof DocumentEventMap> = [
  'click',
  'keydown',
  'mousemove',
  'scroll',
  'touchstart',
];

export function InactivityHandler({ timeoutMinutes }: InactivityHandlerProps) {
  const { status, signOut } = useAuthSession();
  const timerRef = useRef<NodeJS.Timeout | null>(null);

  const clearTimer = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (status !== 'authenticated') {
      clearTimer();
      return undefined;
    }

    const timeoutMs = timeoutMinutes * 60 * 1000;

    const resetTimer = () => {
      clearTimer();
      timerRef.current = setTimeout(() => {
        void signOut({ redirectTo: '/auth/signin?timeout=1' });
      }, timeoutMs);
    };

    activityEvents.forEach(event =>
      document.addEventListener(event, resetTimer)
    );
    resetTimer();

    return () => {
      activityEvents.forEach(event =>
        document.removeEventListener(event, resetTimer)
      );
      clearTimer();
    };
  }, [clearTimer, signOut, status, timeoutMinutes]);

  return null;
}
