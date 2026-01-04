/**
 * Structured Data utilities for SEO
 * Generates JSON-LD structured data for better search engine understanding
 */

export interface Organization {
  '@context': 'https://schema.org';
  '@type': 'Organization';
  name: string;
  url: string;
  logo: string;
  description: string;
  sameAs: string[];
  contactPoint?: {
    '@type': 'ContactPoint';
    contactType: string;
    email: string;
    url: string;
  };
}

export interface WebApplication {
  '@context': 'https://schema.org';
  '@type': 'WebApplication';
  name: string;
  url: string;
  description: string;
  applicationCategory: string;
  operatingSystem: string;
  offers: {
    '@type': 'Offer';
    price: string;
    priceCurrency: string;
  };
  aggregateRating?: {
    '@type': 'AggregateRating';
    ratingValue: string;
    ratingCount: string;
  };
}

export interface SoftwareApplication {
  '@context': 'https://schema.org';
  '@type': 'SoftwareApplication';
  name: string;
  applicationCategory: string;
  operatingSystem: string;
  offers: {
    '@type': 'Offer';
    price: string;
    priceCurrency: string;
  };
}

export interface BreadcrumbList {
  '@context': 'https://schema.org';
  '@type': 'BreadcrumbList';
  itemListElement: Array<{
    '@type': 'ListItem';
    position: number;
    name: string;
    item: string;
  }>;
}

/**
 * Organization structured data for DevFortress
 */
export const organizationSchema: Organization = {
  '@context': 'https://schema.org',
  '@type': 'Organization',
  name: 'DevFortress',
  url: 'https://devfortress.net',
  logo: 'https://devfortress.net/logo.png',
  description:
    'Enterprise-grade API security platform with AI-powered generation, threat intelligence, and automated defense systems.',
  sameAs: [
    'https://twitter.com/devfortress',
    'https://github.com/devfortress',
    'https://linkedin.com/company/devfortress',
  ],
  contactPoint: {
    '@type': 'ContactPoint',
    contactType: 'Customer Support',
    email: 'support@devfortress.net',
    url: 'https://devfortress.net/contact',
  },
};

/**
 * Web application structured data
 */
export const webApplicationSchema: WebApplication = {
  '@context': 'https://schema.org',
  '@type': 'WebApplication',
  name: 'DevFortress Platform',
  url: 'https://devfortress.net',
  description:
    'Build secure APIs with AI assistance, deploy honeypots for threat intelligence, and continuously improve security posture.',
  applicationCategory: 'DeveloperApplication',
  operatingSystem: 'Web Browser',
  offers: {
    '@type': 'Offer',
    price: '69',
    priceCurrency: 'USD',
  },
};

/**
 * Generate breadcrumb structured data
 */
export function generateBreadcrumbs(
  items: Array<{ name: string; url: string }>
): BreadcrumbList {
  return {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: items.map((item, index) => ({
      '@type': 'ListItem',
      position: index + 1,
      name: item.name,
      item: item.url,
    })),
  };
}

/**
 * Generate FAQ structured data
 */
export function generateFAQSchema(
  faqs: Array<{ question: string; answer: string }>
) {
  return {
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    mainEntity: faqs.map(faq => ({
      '@type': 'Question',
      name: faq.question,
      acceptedAnswer: {
        '@type': 'Answer',
        text: faq.answer,
      },
    })),
  };
}

/**
 * Render JSON-LD script tag
 */
export function renderJsonLd(data: unknown) {
  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }}
    />
  );
}
