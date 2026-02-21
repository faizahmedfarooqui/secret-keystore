import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Secret Keystore Demo',
  description: 'Next.js example with @faizahmedfarooqui/secret-keystore',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body style={{
        fontFamily: 'system-ui, -apple-system, sans-serif',
        margin: 0,
        padding: '2rem',
        backgroundColor: '#0a0a0a',
        color: '#ededed',
        minHeight: '100vh',
      }}>
        {children}
      </body>
    </html>
  );
}

