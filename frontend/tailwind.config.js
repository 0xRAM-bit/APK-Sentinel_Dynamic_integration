/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        sentinel: {
          bg: '#0f1117',
          surface: '#161922',
          border: '#23262f',
          hover: '#1c1f2a',
          text: '#e4e5e9',
          muted: '#8b8d97',
          accent: '#3b82f6',
        },
        risk: {
          low: '#22c55e',
          moderate: '#84cc16',
          medium: '#eab308',
          high: '#f97316',
          critical: '#ef4444',
        },
        severity: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#3b82f6',
          info: '#6b7280',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}
