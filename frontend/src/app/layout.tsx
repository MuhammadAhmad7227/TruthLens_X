import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = { title: "TruthLens X", description: "Digital forensics and evidence intelligence" };
export default function RootLayout({children}:{children:React.ReactNode}) { return <html lang="en"><body>{children}</body></html>; }
