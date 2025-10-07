const path = require('path');

// Base directory for Hugo project
const baseDir = path.join(__dirname, '..');

/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    `${baseDir}/themes/**/layouts/**/*.html`,
    `${baseDir}/content/**/layouts/**/*.html`,
    `${baseDir}/layouts/**/*.html`,
    `${baseDir}/content/**/*.html`,
    `${baseDir}/content/**/*.md`,
    `${baseDir}/public/**/*.html`,
  ],
  theme: {
    extend: {
      // 自定義顏色
      colors: {
        'custom-blue': '#1e40af',
        'custom-green': '#059669',
      },
      // 自定義字型
      fontFamily: {
        'sans': ['"Inter"', '-apple-system', 'BlinkMacSystemFont', 'avenir next', 'avenir', 'segoe ui', 'helvetica neue', 'helvetica', 'Cantarell', 'Ubuntu', 'roboto', 'noto', 'arial', 'sans-serif'],
        'custom': ['"Your Custom Font"', 'sans-serif'],
      },
      // 自定義間距
      spacing: {
        '128': '32rem',
        '144': '36rem',
      },
      // 自定義斷點
      screens: {
        '3xl': '1920px',
      },
    },
  },
  plugins: [],
  variants: ['group-hover'],
}
