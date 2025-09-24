import { categoryIcons } from "@/utils/styleUtils";

import dynamicIconImports from "lucide-react/dynamicIconImports";

export const checkLucideIcons = (iconName: string): boolean => {
  return (
    !!dynamicIconImports[iconName] ||
    !!categoryIcons[iconName]
  );
};
