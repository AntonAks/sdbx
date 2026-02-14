/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class', // Enable manual toggle via <html class="dark">
  content: [
    './frontend/**/*.{html,js}'
  ],
  theme: {
    extend: {
      colors: {
        slate: {
          950: '#020617',
        }
      }
    }
  },
  plugins: []
}
