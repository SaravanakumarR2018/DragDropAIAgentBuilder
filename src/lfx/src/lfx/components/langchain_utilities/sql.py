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
        MessageTextInput(name="database_uri", display_name="Database URI", required=True),
        StrInput(
            name="username",
            display_name="Username",
            required=False,
        ),
        SecretStrInput(
            name="password",
            display_name="Password",
            required=False,
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

    def _build_database_uri(self) -> str:
        """
        Credential precedence:
        1. Explicit username/password inputs
        2. Credentials embedded in database_uri
        3. No credentials

        NOTE:
        - IPv4 must NOT use square brackets
        - IPv6 MUST already be bracketed
        - Unbracketed IPv6 will FAIL (intentional)
        """

        parsed = urlparse(self.database_uri)

        # Non-host URIs (e.g., sqlite:///)
        if not parsed.hostname:
            return self.database_uri

        # Credentials from URI
        uri_username = parsed.username
        uri_password = parsed.password

        # Decide final credentials
        if self.username and self.password:
            final_username = self.username
            final_password = self.password
        elif uri_username and uri_password:
            final_username = uri_username
            final_password = uri_password
        else:
            final_username = None
            final_password = None

        hostname = parsed.hostname  # brackets already stripped by urlparse

        # Rebuild netloc
        if final_username and final_password:
            user = quote(final_username, safe="")
            pwd = quote(final_password, safe="")
            netloc = f"{user}:{pwd}@{hostname}"
        else:
            netloc = hostname

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
