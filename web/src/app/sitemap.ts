import type { MetadataRoute } from 'next';

/** The landing page is the site's only indexable page. */
export default function sitemap(): MetadataRoute.Sitemap {
  return [{ url: 'https://passport.scarce.sh', changeFrequency: 'monthly', priority: 1 }];
}
