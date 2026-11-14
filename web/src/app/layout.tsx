import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";

import { Providers } from "@/components/providers";
import { AppShell } from "@/components/shell/app-shell";

import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

// Where the console is published (GitHub Pages); link previews resolve their image against it.
const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? "https://chris91ss.github.io/ai4ci-agentic-soc/";
const DESCRIPTION =
  "SOC console of an agentic Security Operations Center for a simulated enterprise: incidents, agent traces, evidence and containment.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: { default: "Agentic SOC", template: "%s · Agentic SOC" },
  description: DESCRIPTION,
  openGraph: {
    title: "Agentic SOC",
    description: DESCRIPTION,
    url: SITE_URL,
    siteName: "Agentic SOC",
    images: [{ url: "social.png", width: 1200, height: 630, alt: "Agentic SOC: an incident investigated and contained by the triage agent" }],
  },
  twitter: { card: "summary_large_image", images: ["social.png"] },
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}>
      <body className="min-h-full">
        <Providers>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  );
}
