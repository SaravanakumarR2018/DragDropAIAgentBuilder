import { Outlet } from "react-router-dom";

/**
 * Minimal router shell that renders public routes without any of the heavy
 * providers used by the authenticated application.
 */
export function PublicShell() {
  return <Outlet />;
}

export default PublicShell;
