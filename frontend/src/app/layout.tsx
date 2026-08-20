import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'RepoLens - Code Analysis & Repository Intelligence',
  description: 'AI-powered code quality, security analysis, and repository intelligence platform.',
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
