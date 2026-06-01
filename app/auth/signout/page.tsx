'use client';
import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';

export default function SignOutPage() {
  const router = useRouter();
  useEffect(() => {
    const supabase = createClient();
    supabase.auth.signOut().then(() => { router.push('/'); router.refresh(); });
  }, [router]);
  return (
    <div className="flex min-h-screen items-center justify-center bg-white dark:bg-neutral-950">
      <p className="text-sm text-neutral-500 dark:text-neutral-400">Signing out…</p>
    </div>
  );
}
