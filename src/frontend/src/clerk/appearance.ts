import type { Appearance } from "@clerk/types";

// Shared Clerk appearance that matches the app theme via CSS variables
export const clerkAppearance: Appearance = {
  variables: {
    colorBackground: "hsl(var(--background))",
    colorInputBackground: "hsl(var(--input))",
    colorInputText: "hsl(var(--foreground))",
    colorPrimary: "hsl(var(--primary))",
    colorText: "hsl(var(--foreground))",
    colorTextSecondary: "hsl(var(--muted-foreground))",
    colorDanger: "hsl(var(--destructive))",
    colorShimmer: "hsl(var(--muted))",
    borderRadius: "12px",
    fontFamily: "var(--font-sans)",
  },
  elements: {
    card: "shadow-none border border-border bg-card text-foreground",
    headerTitle: "text-foreground",
    headerSubtitle: "text-muted-foreground",
    formButtonPrimary: "bg-foreground text-background hover:bg-primary-hover",
    formFieldInput:
      "bg-background text-foreground border border-border focus:ring-2 focus:ring-ring",
    profileSectionPrimaryButton:
      "bg-foreground text-background hover:bg-primary-hover",
    profileSectionSecondaryButton:
      "bg-muted text-foreground hover:bg-muted/80",
    userPreviewMainIdentifier: "text-foreground",
    rootBox: "!w-full",
  },
};
