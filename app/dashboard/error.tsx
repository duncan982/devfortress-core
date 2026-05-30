'use client';

export default function SectionError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 p-8 text-center">
      <p className="text-sm font-medium text-destructive">
        {error.message || 'An error occurred in this section.'}
      </p>
      <button onClick={reset} className="text-xs underline">
        Retry
      </button>
    </div>
  );
}
