import type { Metadata, Viewport } from 'next';
import './globals.css';

export const metadata: Metadata = {
  metadataBase: new URL('https://passport.scarce.sh'),
  title: 'Passport — Prove it. Don’t show it.',
  description:
    'Passport turns the chip in your passport into private, verifiable claims. Answer “18 or older?” with a zero-knowledge proof; your name, photo and document number stay on your phone.',
  openGraph: {
    title: 'Passport — Prove it. Don’t show it.',
    description:
      'Private, verifiable claims from the chip in your passport. Zero-knowledge proofs, checkable off-chain and on Solana.',
    url: 'https://passport.scarce.sh',
    siteName: 'Passport',
    type: 'website',
  },
  twitter: { card: 'summary_large_image' },
};

export const viewport: Viewport = { themeColor: '#ffffff' };

/** The public site uses local system fonts and makes no third-party requests. */
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
