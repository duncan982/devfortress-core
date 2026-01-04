'use client';

import Link from 'next/link';
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
} from 'react';

type RawSearchResult = {
  article?: {
    slug?: string | null;
    title?: string | null;
    content?: string | null;
  };
};

type SearchStatus = 'idle' | 'loading' | 'results' | 'empty' | 'error';

const MIN_QUERY_LENGTH = 3;
const DEBOUNCE_DELAY = 300;

const sanitizeSnippet = (value: string | null | undefined, limit = 100) => {
  if (!value) {
    return '';
  }

  const normalized = value
    .replace(/[#*_`>]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  if (normalized.length <= limit) {
    return normalized;
  }

  return `${normalized.slice(0, Math.max(0, limit - 3))}...`;
};

export function HelpSearch() {
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState<SearchStatus>('idle');
  const [results, setResults] = useState<RawSearchResult[]>([]);
  const debounceRef = useRef<number | null>(null);
  const latestQueryRef = useRef('');

  useEffect(() => {
    return () => {
      if (debounceRef.current !== null) {
        window.clearTimeout(debounceRef.current);
        debounceRef.current = null;
      }
    };
  }, []);

  const performSearch = useCallback(async (value: string) => {
    setStatus('loading');
    latestQueryRef.current = value;

    try {
      const response = await fetch(
        `/api/help?query=${encodeURIComponent(value)}`
      );
      if (!response.ok) {
        throw new Error('Search request failed');
      }

      const payload = await response.json();
      const normalized = Array.isArray(payload?.results) ? payload.results : [];

      if (latestQueryRef.current !== value) {
        return;
      }

      if (normalized.length === 0) {
        setResults([]);
        setStatus('empty');
        return;
      }

      setResults(normalized);
      setStatus('results');
    } catch {
      if (latestQueryRef.current !== value) {
        return;
      }
      setStatus('error');
    }
  }, []);

  const handleInputChange = useCallback(
    (event: ChangeEvent<HTMLInputElement>) => {
      const value = event.target.value;
      setQuery(value);

      if (debounceRef.current !== null) {
        window.clearTimeout(debounceRef.current);
        debounceRef.current = null;
      }

      const trimmed = value.trim();

      if (trimmed.length < MIN_QUERY_LENGTH) {
        latestQueryRef.current = trimmed;
        setResults([]);
        setStatus('idle');
        return;
      }

      debounceRef.current = window.setTimeout(() => {
        performSearch(trimmed);
        debounceRef.current = null;
      }, DEBOUNCE_DELAY);
    },
    [performSearch]
  );

  const shouldShowPanel = status !== 'idle';

  return (
    <div className="mx-auto max-w-2xl">
      <label htmlFor="help-search" className="sr-only">
        Search the help center
      </label>
      <div className="relative">
        <input
          type="search"
          id="help-search"
          placeholder="Search for help articles..."
          className="w-full rounded-lg border border-neutral-300 px-6 py-4 pl-12 text-lg shadow-sm transition-colors focus:border-transparent focus:ring-2 focus:ring-primary-500 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100"
          autoComplete="off"
          value={query}
          onChange={handleInputChange}
        />
        <svg
          className="pointer-events-none absolute left-4 top-5 h-6 w-6 text-neutral-400"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
          />
        </svg>
      </div>

      {shouldShowPanel && (
        <div className="mt-4" role="status" aria-live="polite">
          <div className="rounded-lg bg-white p-4 shadow-md transition-colors dark:bg-neutral-900">
            <p className="mb-2 text-sm font-medium text-neutral-600 dark:text-neutral-300">
              Search Results
            </p>

            {status === 'loading' && (
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Searching...
              </p>
            )}

            {status === 'error' && (
              <p className="text-sm text-error-600 dark:text-error-400">
                Unable to load search results. Please try again.
              </p>
            )}

            {status === 'empty' && (
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                No results found.
              </p>
            )}

            {status === 'results' && (
              <div className="space-y-2">
                {results.map(result => {
                  const article = result.article;
                  if (!article?.slug) {
                    return null;
                  }

                  const title = article.title ?? 'Untitled Article';
                  const snippet = sanitizeSnippet(article.content);

                  return (
                    <Link
                      key={article.slug}
                      href={`/help/article/${article.slug}`}
                      className="block border-b border-neutral-200 py-3 transition-colors last:border-0 hover:bg-neutral-50 dark:border-neutral-700 dark:hover:bg-neutral-800"
                    >
                      <h4 className="font-medium text-neutral-900 dark:text-neutral-100">
                        {title}
                      </h4>
                      {snippet && (
                        <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-400">
                          {snippet}
                        </p>
                      )}
                    </Link>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
