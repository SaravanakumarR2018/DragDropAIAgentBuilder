document.addEventListener("DOMContentLoaded", () => {
  const watermark = document.querySelector(".watermark");
  if (watermark) {
    watermark.setAttribute("title", "This page is served from the new Frontend 2 shell");
  }

  console.info("Frontend 2 landing page loaded");
});
