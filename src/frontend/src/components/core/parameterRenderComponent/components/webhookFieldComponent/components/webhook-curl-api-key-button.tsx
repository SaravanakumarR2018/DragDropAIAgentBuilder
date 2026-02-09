import { useState } from "react";
import { Button } from "@/components/ui/button";
import { ENABLE_DATASTAX_LANGFLOW } from "@/customization/feature-flags";
import { useGenerateToken } from "@/customization/hooks/use-custom-generate-token";
import { createApiKey } from "@/controllers/API";

type WebhookCurlApiKeyButtonProps = {
  onApiKeyGenerated: (apiKey: string) => void;
  disabled?: boolean;
};

const DEFAULT_API_KEY_NAME = "Webhook curl key";

export default function WebhookCurlApiKeyButton({
  onApiKeyGenerated,
  disabled,
}: WebhookCurlApiKeyButtonProps) {
  const [isLoading, setIsLoading] = useState(false);
  const generateToken = useGenerateToken();

  const handleGenerateKey = async () => {
    if (isLoading) {
      return;
    }

    setIsLoading(true);
    try {
      let apiKeyValue = "";

      if (ENABLE_DATASTAX_LANGFLOW) {
        const response = await generateToken();
        apiKeyValue = response?.token ?? response ?? "";
      } else {
        const response = await createApiKey(DEFAULT_API_KEY_NAME);
        apiKeyValue = response?.api_key ?? "";
      }

      if (apiKeyValue) {
        onApiKeyGenerated(apiKeyValue);
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Button
      type="button"
      variant="secondary"
      onClick={handleGenerateKey}
      disabled={disabled || isLoading}
    >
      {isLoading ? "Generating..." : "Generate API Key"}
    </Button>
  );
}
