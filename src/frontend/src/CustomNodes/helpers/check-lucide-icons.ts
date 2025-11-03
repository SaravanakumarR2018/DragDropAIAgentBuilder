import { categoryIcons } from "@/utils/styleUtils";

export const checkLucideIcons =async (iconName: string):Promise<boolean> => {
   const [lucideIcons, dynamicIconImports] = await Promise.all([
    import("lucide-react"),
    import("lucide-react/dynamicIconImports").then((mod) => mod.default),
  ]);
const lucideIconsPromise=import("lucide-react");
const dynamicIconImportsPromise = import("lucide-react/dynamicIconImports").then((mod)=>mod.default);

export const checkLucideIcons =async (iconName: string):Promise<boolean> => {
  const [lucideIcons, dynamicIconImports] = await Promise.all([lucideIconsPromise, dynamicIconImportsPromise]);
  return (
    !!lucideIcons[iconName] ||
    !!dynamicIconImports[iconName] ||
    !!categoryIcons[iconName]
  );
};
