/**
 * Enterprise — open-core redirect
 *
 * The full enterprise page (feature showcase, compliance matrix, intake form)
 * lives in the hosted platform at devfortress.net/enterprise.
 * This open-core build redirects there permanently.
 */

import { redirect } from 'next/navigation';

export default function EnterprisePage() {
  redirect('https://devfortress.net/enterprise');
}

export const metadata = {
  title: 'Enterprise — DevFortress',
  description:
    'DevFortress enterprise security plans at devfortress.net/enterprise.',
};
