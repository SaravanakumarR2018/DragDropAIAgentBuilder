import re
from urllib.parse import quote, urlparse, urlunparse

from langchain.agents import AgentExecutor
from langchain_community.agent_toolkits import SQLDatabaseToolkit
from langchain_community.agent_toolkits.sql.base import create_sql_agent
from langchain_community.utilities import SQLDatabase

from lfx.base.agents.agent import LCAgentComponent
from lfx.inputs.inputs import HandleInput, MessageTextInput, SecretStrInput, StrInput
from lfx.io import Output


class SQLAgentComponent(LCAgentComponent):
    display_name = "SQLAgent"
    description = "Construct an SQL agent from an LLM and tools."
    name = "SQLAgent"
    icon = "LangChain"
    inputs = [
        *LCAgentComponent.get_base_inputs(),
        HandleInput(name="llm", display_name="Language Model", input_types=["LanguageModel"], required=True),
        MessageTextInput(
            name="database_uri",
            display_name="Database URI",
            required=True,
            info=(
                "Full URI with credentials OR URI without credentials "
                "(if using separate username/password fields)"
            ),
        ),
        StrInput(
            name="username",
            display_name="Username",
            required=False,
            info="Database username (leave empty if credentials are in URI)",
        ),
        SecretStrInput(
            name="password",
            display_name="Password",
            required=False,
            info="Database password (leave empty if credentials are in URI)",
        ),
        HandleInput(
            name="extra_tools",
            display_name="Extra Tools",
            input_types=["Tool"],
            is_list=True,
            advanced=True,
        ),
    ]

    outputs = [
        Output(display_name="Response", name="response", method="message_response"),
        Output(display_name="Agent", name="agent", method="build_agent", tool_mode=False),
    ]

    def _fix_unbracketed_ipv6(self, uri: str) -> str:
        """
        Pre-process URI to bracket unbracketed IPv6 addresses before urlparse.
        This handles malformed URIs like postgresql://2001:db8::1:5432/mydb
        """
        pattern = r"^(\w+://(?:[^@]+@)?)([\da-fA-F:]+)(:\d+)?(/.*)?$"
        match = re.match(pattern, uri)

        if match:
            scheme_and_creds = match.group(1)
            potential_ipv6 = match.group(2)
            port = match.group(3) or ""
            path = match.group(4) or ""

            if potential_ipv6.count(":") >= 2 and not potential_ipv6.startswith("["):
                return f"{scheme_and_creds}[{potential_ipv6}]{port}{path}"

        return uri

    def _sanitize_uri(self, uri: str) -> str:
        """
        Remove any existing credentials from the URI.
        Handles both standard URIs and SQLite URIs.
        """
        uri = self._fix_unbracketed_ipv6(uri)
        parsed = urlparse(uri)

        if not parsed.netloc:
            return uri

        hostname = parsed.hostname or ""

        netloc = hostname
        if parsed.port:
            netloc += f":{parsed.port}"

        return urlunparse(parsed._replace(netloc=netloc))

    def _build_database_uri(self) -> str:
        """
        Safely construct a database URI supporting:
        - IPv4
        - IPv6 (RFC 3986 compliant, bracketed)
        - IPv6 (unbracketed - will be auto-corrected)
        - URL-encoded credentials
        - Non-host databases (e.g. SQLite) without modification
        - Sanitization of existing credentials in provided URIs
        """
        base_uri = self.database_uri
        base_uri = self._fix_unbracketed_ipv6(base_uri)
        parsed_original = urlparse(base_uri)

        if parsed_original.username and not (self.username and self.password):
            return base_uri

        sanitized_uri = self._sanitize_uri(base_uri)

        if not (self.username and self.password):
            return sanitized_uri

        parsed = urlparse(sanitized_uri)

        if not parsed.hostname:
            return sanitized_uri

        username = quote(self.username, safe="")
        password = quote(self.password, safe="")

        hostname = parsed.hostname

        if ":" in hostname and not (hostname.startswith("[") and hostname.endswith("]")):
            hostname = f"[{hostname}]"

        netloc = f"{username}:{password}@{hostname}"
        if parsed.port:
            netloc += f":{parsed.port}"

        return urlunparse(parsed._replace(netloc=netloc))

    def build_agent(self) -> AgentExecutor:
        database_uri = self._build_database_uri()
        db = SQLDatabase.from_uri(database_uri)
        toolkit = SQLDatabaseToolkit(db=db, llm=self.llm)
        agent_args = self.get_agent_kwargs()
        agent_args["max_iterations"] = agent_args["agent_executor_kwargs"]["max_iterations"]
        del agent_args["agent_executor_kwargs"]["max_iterations"]
        return create_sql_agent(llm=self.llm, toolkit=toolkit, extra_tools=self.extra_tools or [], **agent_args)
