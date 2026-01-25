from urllib.parse import urlparse, urlunparse

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
            info="Full URI with credentials OR URI without credentials (if using separate username/password fields)",
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

    def _build_database_uri(self) -> str:
        """
        Construct the database URI either from the full URI or by combining
        the base URI with separate username and password.
        """
        base_uri = self.database_uri

        if self.username and self.password:
            parsed = urlparse(base_uri)

            if parsed.hostname:
                hostname = parsed.hostname
                if ":" in hostname:
                    hostname = f"[{hostname}]"

                netloc = f"{self.username}:{self.password}@{hostname}"
                if parsed.port:
                    netloc += f":{parsed.port}"
            else:
                netloc = f"{self.username}:{self.password}@{parsed.netloc}"

            parsed = parsed._replace(netloc=netloc)
            return urlunparse(parsed)

        return base_uri

    def build_agent(self) -> AgentExecutor:
        database_uri = self._build_database_uri()
        db = SQLDatabase.from_uri(database_uri)
        toolkit = SQLDatabaseToolkit(db=db, llm=self.llm)
        agent_args = self.get_agent_kwargs()
        agent_args["max_iterations"] = agent_args["agent_executor_kwargs"]["max_iterations"]
        del agent_args["agent_executor_kwargs"]["max_iterations"]
        return create_sql_agent(llm=self.llm, toolkit=toolkit, extra_tools=self.extra_tools or [], **agent_args)
