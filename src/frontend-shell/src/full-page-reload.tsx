import { useEffect } from "react";

export default function FullPageReload() {
  useEffect(() => {
    const href = window.location.pathname + window.location.search + window.location.hash;
    window.location.replace(href);
  }, []);

  return null;
}
