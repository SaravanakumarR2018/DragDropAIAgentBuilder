import ContextWrapper from "@/contexts";
import { Outlet } from "react-router-dom";

export default function ProtectedShell() {
  return (
    <ContextWrapper>
      <Outlet />
    </ContextWrapper>
  );
}