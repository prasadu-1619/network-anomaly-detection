/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#0a0a1e',
          panel: 'rgba(18, 18, 36, 0.7)',
          accent: '#00d4ff',
          success: '#00ff88',
          warning: '#ffa500',
          danger: '#ff0055',
          text: '#a8b8d4',
          header: 'rgba(15, 12, 41, 0.95)',
          'header-accent': 'rgba(60, 43, 120, 0.8)',
        }
      },
      fontFamily: {
        sans: ['Inter', 'Segoe UI', 'sans-serif'],
        mono: ['monospace'],
      },
      backgroundImage: {
        'cyber-gradient': 'linear-gradient(135deg, #0a0a1e, #2d1b4e, #1a1a3e)',
        'header-gradient': 'linear-gradient(135deg, rgba(15, 12, 41, 0.95), rgba(60, 43, 120, 0.8))',
      },
      boxShadow: {
        'cyber': '0 4px 20px rgba(0, 0, 0, 0.4)',
        'cyber-hover': '0 6px 20px rgba(0, 212, 255, 0.15)',
        'cyber-accent': '0 0 10px rgba(0, 212, 255, 0.5)',
      }
    },
  },
  plugins: [],
}
