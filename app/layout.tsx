// Open-core stub layout — minimal App Router root layout for self-hosted deployments.
// The hosted platform (devfortress.net) uses an extended layout with auth providers,
// analytics, and theme management from the private repository.
import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'DevFortress',
  description:
    'Developer-first security platform for APIs, applications, and AI agents.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
