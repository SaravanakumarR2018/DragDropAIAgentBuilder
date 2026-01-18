import ShortUniqueId from "short-unique-id";
import type { Message } from "@/types/messages";

const uid = new ShortUniqueId();

type OptimisticMessageParams = {
  flowId: string;
  sessionId: string;
  text: string;
  files?: string[];
};

export const buildOptimisticUserMessage = ({
  flowId,
  sessionId,
  text,
  files = [],
}: OptimisticMessageParams): Message => ({
  flow_id: flowId,
  text,
  sender: "User",
  sender_name: "User",
  session_id: sessionId,
  timestamp: new Date().toISOString(),
  files,
  id: `optimistic_${uid.randomUUID(10)}`,
  edit: false,
  background_color: "",
  text_color: "",
  properties: {
    optimistic: true,
  },
});

export const reconcileOptimisticUserMessages = (
  messages: Message[],
  incomingMessage: Message,
): Message[] => {
  if (incomingMessage.sender !== "User" || incomingMessage.properties?.optimistic) {
    return messages;
  }

  const hasOptimisticMatch = messages.some(
    (message) =>
      message.properties?.optimistic &&
      message.sender === "User" &&
      message.session_id === incomingMessage.session_id &&
      message.text === incomingMessage.text,
  );

  if (!hasOptimisticMatch) {
    return messages;
  }

  return messages.filter(
    (message) =>
      !(
        message.properties?.optimistic &&
        message.sender === "User" &&
        message.session_id === incomingMessage.session_id &&
        message.text === incomingMessage.text
      ),
  );
};
