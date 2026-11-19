/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          950: '#07090E',
          900: '#0B0F19',
          850: '#101626',
          800: '#161F36',
          700: '#1F2C4C',
          accent: '#06B6D4',
          emerald: '#10B981',
          danger: '#EF4444',
          warning: '#F59E0B',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        'cyber-cyan': '0 0 20px -3px rgba(6, 182, 212, 0.25)',
        'cyber-emerald': '0 0 20px -3px rgba(16, 185, 129, 0.25)',
        'cyber-danger': '0 0 20px -3px rgba(239, 68, 68, 0.25)',
      }
    },
  },
  plugins: [],
}
