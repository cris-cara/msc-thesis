from __future__ import annotations

import json
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

@dataclass(frozen=True)
class ToolRef:
    """
    Represents a reference to a specific tool and its associated server key.

    This class is used to store and represent the pairing between a server key and a tool name,
    encapsulating the identity of a tool in a given context. It is designed to be immutable.

    Attributes:
        server_key: A unique identifier for the server associated with the tool.
        tool_name: The name of the tool being referenced.
    """
    server_key: str
    tool_name: str

class McpHub:
    """
    Manages communication with multiple tool servers and provides a unified interface for tool interaction.

    This class provides functionality for registering and managing tool servers, querying available tools,
    and invoking tools. It maintains a mapping of tool aliases to their respective server and tool references
    and supports interaction using both custom and OpenAI/Azure OpenAI tool schemas.

    Attributes:
        openai_tools: List of tools in the OpenAI/Azure OpenAI compatible schema.
        tool_aliases: Sorted list of tool aliases currently registered.
    """

    def __init__(self) -> None:
        self._stack = AsyncExitStack()
        self._sessions: Dict[str, ClientSession] = {}
        self._tool_map: Dict[str, ToolRef] = {}
        self._openai_tools: List[dict] = []

    @property
    def tool_aliases(self) -> List[str]:
        """
        Provides a property to retrieve sorted tool aliases from the internal tool map.

        This property returns a list of tool aliases extracted and sorted from the
        internal tool mapping. The aliases represent the keys from the tool map.

        Returns:
            List[str]: A sorted list of tool aliases.
        """
        return sorted(self._tool_map.keys())

    def openai_tools_for(self, allowed_servers: set[str]) -> list[dict]:
        """
        Filters and returns OpenAI tools based on allowed server keys.

        This function iterates over the list of available OpenAI tools and filters
        them based on the provided set of allowed server keys. The server keys are
        extracted from the tool's function name, which has the format
        <server_key>.<function_name>. If the server key of a tool is present in the
        allowed_servers set, the tool is included in the returned list.

        Parameters:
            allowed_servers (set[str]): A set of allowed server keys used to filter
            tools. Only tools with server keys present in this set are included in
            the result.

        Returns:
            list[dict]: A list of dictionaries representing OpenAI tools that match
            the allowed server keys.
        """
        out = []
        for t in self._openai_tools:
            name = t["function"]["name"]  # es: "weather.get_current_weather"
            server_key = name.split(".", 1)[0]
            if server_key in allowed_servers:
                out.append(t)
        return out

    async def add_stdio_server(
        self,
        *,
        server_key: str,
        command: str,
        args: List[str],
    ) -> Any:
        """
        Adds a new stdio server to the current session manager.

        This method registers a server identified by a unique `server_key` and initializes
        it using the given command and arguments. Communication with the server is managed
        through stdio streams. An error is raised if a server with the specified `server_key`
        already exists. This method returns the result of the server initialization.

        Parameters:
            server_key (str): A unique identifier for the server to be added.
            command (str): The command to be executed as the stdio server.
            args (List[str]): A list of arguments to be passed to the stdio server command.

        Returns:
            Any: The result of the server's initialization process.

        Raises:
            ValueError: If a server with the specified `server_key` is already registered.
        """
        if server_key in self._sessions:
            raise ValueError(f"Server already registered: {server_key}")

        server_params = StdioServerParameters(command=command, args=args)
        read, write = await self._stack.enter_async_context(stdio_client(server_params))
        session = await self._stack.enter_async_context(ClientSession(read, write))
        init_result = await session.initialize()
        self._sessions[server_key] = session
        return init_result

    async def refresh_tools(self) -> None:
        """
        Asynchronously refreshes the currently available tools by retrieving and updating their
        details from multiple sessions and servers. Clears the existing tool map and list of
        OpenAI tools, and repopulates them based on retrieved tool information.

        Raises:
            No exceptions are explicitly raised by this method.
        """
        self._tool_map.clear()
        self._openai_tools = []

        for server_key, session in self._sessions.items():
            resp = await session.list_tools()

            for tool in resp.tools:
                # unique alias to avoid server collisions
                alias = f"{server_key}.{tool.name}"
                self._tool_map[alias] = ToolRef(server_key=server_key, tool_name=tool.name)

                input_schema = getattr(tool, "inputSchema", None) or {
                    "type": "object",
                    "properties": {},
                }

                self._openai_tools.append(
                    {
                        "type": "function",
                        "function": {
                            "name": alias,
                            "description": (tool.description or "").strip(),
                            "parameters": input_schema,
                        },
                    }
                )

    async def call(self, tool_alias: str, arguments: Dict[str, Any]) -> Any:
        """
        Executes an asynchronous call to a tool with the provided alias and arguments.

        Parameters:
        tool_alias: str
            The alias for the tool to be called. This must correspond to an alias present in the tool map.
        arguments: Dict[str, Any]
            A dictionary containing the arguments to be passed to the tool.

        Returns:
        Any
            The result of the tool's execution.

        Raises:
        KeyError
            If the provided tool alias is not found in the tool map.
        """
        if tool_alias not in self._tool_map:
            raise KeyError(f"Tool not found: {tool_alias}. Available: {self.tool_aliases}")

        ref = self._tool_map[tool_alias]
        session = self._sessions[ref.server_key]
        return await session.call_tool(name=ref.tool_name, arguments=arguments)

    async def call_from_openai_tool_call(self, tool_call) -> Tuple[str, dict]:
        """
        Calls an OpenAI tool from a given tool call object, processes the result, and
        returns log information and a response message.

        Args:
            tool_call (ToolCall): Object containing information about the tool function
            being called, including the tool alias and its arguments.

        Returns:
            Tuple[str, dict]: A tuple containing a log string summarizing the operation
            and a response dictionary with details about the tool call response.

        Raises:
            Exception: If there are errors during JSON parsing of arguments or while
            calling the tool.
        """
        tool_alias = tool_call.function.name
        raw_args = tool_call.function.arguments or "{}"

        try:
            args = json.loads(raw_args)
        except Exception:
            args = {}

        try:
            result = await self.call(tool_alias, args)

            # extract MCP text contents (if any)
            parts: List[str] = []
            for item in getattr(result, "content", []) or []:
                text = getattr(item, "text", None)
                if text is not None:
                    parts.append(text)
                else:
                    parts.append(str(item))

            content = "\n".join(parts).strip()
            if not content:
                # Fallback: try structuredContent or repr
                structured = getattr(result, "structuredContent", None)
                content = json.dumps(structured, ensure_ascii=False) if structured is not None else str(result)

            log = f"[Used {tool_alias}({args})]"

        except Exception as e:
            log = f"[Tool error] {tool_alias}: {e}"
            content = f"Error while calling MCP tool {tool_alias}: {e}"

        msg = {"role": "tool", "tool_call_id": tool_call.id, "content": content}
        return log, msg

    async def aclose(self) -> None:
        """
        Closes all resources managed by the asynchronous context stack.

        This method ensures that all resources tracked by the context stack are
        properly closed in an asynchronous manner.

        Raises:
            Any exception that may be raised by the `aclose` method of the
            underlying context stack.
        """
        await self._stack.aclose()
