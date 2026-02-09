export const WEBHOOK_API_KEY_PLACEHOLDER = "LANGFLOW_API_KEY";

const API_KEY_HEADER_REGEX = /x-api-key:\s*([^'"]+)/i;

const buildApiKeyHeader = (apiKeyValue: string) =>
  `-H "x-api-key: ${apiKeyValue}"`;

export const ensureCurlHasApiKeyHeader = (
  curlCommand: string,
  apiKeyValue: string = WEBHOOK_API_KEY_PLACEHOLDER,
): string => {
  if (!curlCommand) {
    return curlCommand;
  }

  const updatedKeyHeader = `x-api-key: ${apiKeyValue}`;

  if (curlCommand.includes("x-api-key:")) {
    return curlCommand.replace(API_KEY_HEADER_REGEX, updatedKeyHeader);
  }

  const hasNewlines = curlCommand.includes("\n");
  const headerToken = hasNewlines
    ? `\n  ${buildApiKeyHeader(apiKeyValue)} \\`
    : ` ${buildApiKeyHeader(apiKeyValue)}`;

  const contentTypeHeader = "-H 'Content-Type: application/json'";
  if (hasNewlines) {
    const contentTypeHeaderWithSlash = `${contentTypeHeader} \\`;
    if (curlCommand.includes(contentTypeHeaderWithSlash)) {
      return curlCommand.replace(
        contentTypeHeaderWithSlash,
        `${contentTypeHeaderWithSlash}\n  ${buildApiKeyHeader(apiKeyValue)} \\`,
      );
    }
  }

  if (curlCommand.includes(contentTypeHeader)) {
    return curlCommand.replace(
      contentTypeHeader,
      `${contentTypeHeader}${headerToken}`,
    );
  }

  const dataFlagMatch = /\s(-d\s|--data\s)/;
  if (dataFlagMatch.test(curlCommand)) {
    return curlCommand.replace(dataFlagMatch, `${headerToken} $1`);
  }

  return `${curlCommand}${headerToken}`.trim();
};
