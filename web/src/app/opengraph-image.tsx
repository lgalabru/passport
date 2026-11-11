import { ImageResponse } from 'next/og';

export const alt = 'Passport — Prove it. Don’t show it.';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

/** Static social card with no remote font or image dependencies. */
export default function OpenGraphImage() {
  return new ImageResponse(
    <div
      style={{
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        padding: '65px 80px',
        background: '#ffffff',
        color: '#0b0b0c',
        fontFamily: 'sans-serif',
      }}
    >
      <div style={{ display: 'flex', fontSize: 34, fontWeight: 600 }}>passport</div>
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          marginTop: 90,
          fontSize: 76,
          lineHeight: 1.1,
          fontWeight: 600,
        }}
      >
        <span>Prove it.</span>
        <span style={{ color: '#a1a1a6' }}>Don’t show it.</span>
      </div>
      <div style={{ display: 'flex', marginTop: 'auto', fontSize: 22, color: '#6e6e73' }}>
        Private, verifiable claims from the chip in your passport.
      </div>
    </div>,
    size,
  );
}
