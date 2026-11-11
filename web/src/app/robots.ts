import type { MetadataRoute } from 'next';

/** Crawl rules for the public product site. */
export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: '*', allow: '/' },
    sitemap: 'https://passport.scarce.sh/sitemap.xml',
  };
}
