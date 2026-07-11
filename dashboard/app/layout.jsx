import './globals.css';

export const metadata = {
  title: 'SilentGuard XDR — Command Matrix',
  description: 'Autonomous endpoint detection & response dashboard',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body className="bg-slate-950 text-slate-100 min-h-screen antialiased">
        {children}
      </body>
    </html>
  );
}
