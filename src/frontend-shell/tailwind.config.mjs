import baseConfig from "../frontend/tailwind.config.mjs";

const content = Array.from(
  new Set([
    ...(baseConfig.content ?? []),
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ]),
);

const config = {
  ...baseConfig,
  content,
};

export default config;
