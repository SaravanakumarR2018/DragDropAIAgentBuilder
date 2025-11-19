import baseConfig from "../frontend/tailwind.config.mjs";

/** @type {import('tailwindcss').Config} */
const config = {
  ...baseConfig,
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
    "../frontend/src/**/*.{js,ts,jsx,tsx}",
  ],
};

export default config;
