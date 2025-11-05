import type { JSX } from "react";

import AppWithProvider from "./clerk/auth";
import CustomApp from "./customization/custom-App";

export function AppRoot(): JSX.Element {
  return (
    <AppWithProvider>
      <CustomApp />
    </AppWithProvider>
  );
}

export default AppRoot;
