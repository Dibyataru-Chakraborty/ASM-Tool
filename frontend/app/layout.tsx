import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import '@/styles/globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: { default: 'ASM Platform', template: '%s | ASM Platform' },
  description: 'Enterprise Attack Surface Management Platform',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className={`${inter.className} bg-[#0d1117] text-gray-100 antialiased`}>
        {children}
      </body>
    </html>
  )
}
