import { MessageType } from "@/types/messages";

/**
 * Marks an optimistic user message as failed without removing it from the UI.
 * This preserves user intent while allowing global error handling.
 */
export function markOptimisticMessageFailed(
  optimisticMessage: MessageType
): MessageType {
  return {
    ...optimisticMessage,
    properties: {
      ...optimisticMessage.properties,
      optimistic: false,
      failed: true,
    },
  };
}
