/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#0E1116",
          900: "#12151B",
          800: "#1A1F27",
          700: "#232936",
          600: "#2A303B",
          500: "#3A4250",
        },
        paper: {
          DEFAULT: "#E9E6DA",
          muted: "#8B92A0",
          dim: "#5B6270",
        },
        brass: {
          DEFAULT: "#C9A227",
          bright: "#E0BB44",
          dim: "#8A6E1C",
        },
        alarm: {
          DEFAULT: "#B5453A",
          bright: "#D25B4E",
          dim: "#7A2E26",
        },
        hold: {
          DEFAULT: "#4F7CAC",
          bright: "#6B98C8",
          dim: "#33526F",
        },
      },
      fontFamily: {
        display: ["'Space Grotesk'", "sans-serif"],
        body: ["'IBM Plex Sans'", "sans-serif"],
        mono: ["'IBM Plex Mono'", "monospace"],
      },
    },
  },
  plugins: [],
};
