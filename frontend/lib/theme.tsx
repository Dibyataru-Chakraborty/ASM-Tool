'use client'

import { createContext, ReactNode, useContext, useEffect, useState } from 'react'

type Theme = 'dark' | 'light'

type ThemeContextValue = {
  theme: Theme
  toggleTheme: () => void
}

const STORAGE_KEY = 'asm-theme'
const ThemeContext = createContext<ThemeContextValue | null>(null)

function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme
  document.documentElement.style.colorScheme = theme
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>('dark')

  useEffect(() => {
    const stored = window.localStorage.getItem(STORAGE_KEY)
    const initialTheme: Theme = stored === 'light' ? 'light' : 'dark'
    setTheme(initialTheme)
    applyTheme(initialTheme)
  }, [])

  const toggleTheme = () => {
    setTheme(current => {
      const nextTheme: Theme = current === 'dark' ? 'light' : 'dark'
      window.localStorage.setItem(STORAGE_KEY, nextTheme)
      applyTheme(nextTheme)
      return nextTheme
    })
  }

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  const context = useContext(ThemeContext)
  if (!context) {
    throw new Error('useTheme must be used within ThemeProvider')
  }
  return context
}
