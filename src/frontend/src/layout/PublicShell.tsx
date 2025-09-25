import { Outlet } from "react-router-dom";

export function PublicShell() {
  return (
    <div className="public-shell">
      <Outlet />
    </div>
  );
}