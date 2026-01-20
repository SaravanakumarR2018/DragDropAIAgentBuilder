import type { APIClassType, APIKindType, APIObjectType } from "@/types/api";

export function buildTemplatesByModule(
  data: APIObjectType,
): Record<string, APIClassType> {
  return Object.keys(data).reduce((acc, curr) => {
    Object.values(data[curr]).forEach((component: APIKindType[keyof APIKindType]) => {
      const moduleName = component?.metadata?.module;
      if (moduleName && !acc[moduleName]) {
        acc[moduleName] = component as APIClassType;
      }
    });
    return acc;
  }, {} as Record<string, APIClassType>);
}

export function resolveTemplateEntry(
  node: { metadata?: { module?: string } } | undefined,
  templatesByName: Record<string, APIClassType>,
  templatesByModule?: Record<string, APIClassType>,
  typeKey?: string,
): APIClassType | undefined {
  const moduleName = node?.metadata?.module;
  if (moduleName && templatesByModule?.[moduleName]) {
    return templatesByModule[moduleName];
  }
  if (typeKey) {
    return templatesByName[typeKey];
  }
  return undefined;
}
