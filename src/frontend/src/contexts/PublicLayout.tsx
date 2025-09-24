import { GradientWrapper } from "@/components/common/GradientWrapper";
import { CustomWrapper } from "@/customization/custom-wrapper";
import { ReactNode } from "react";
import { Outlet } from "react-router-dom";

export function PublicLayout({ children }: { children?: ReactNode }) {
  const content = children ?? <Outlet />;

  return (
    <CustomWrapper>
      <GradientWrapper>{content}</GradientWrapper>
    </CustomWrapper>
  );
}

export default PublicLayout;
