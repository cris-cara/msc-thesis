import json
from typing import Type, TypeVar, Any

T = TypeVar("T")
def rehydrate_after_mcp_tool_call(tool_result: Any, target_class: Type[T]) -> T:
    """
    Extracts the raw JSON string from an MCP tool result (TextContent)
    and rehydrates it into an instance of the specified Python class.

    Args:
        tool_result (Any): The raw object returned by the MCP tool execution
                           (usually containing a list of TextContent objects).
        target_class (Type[T]): The class (e.g., a @dataclass) to instantiate
                                with the extracted data.

    Returns:
        T: An instance of 'target_class' populated with the data from the tool.

    Raises:
        ValueError: If the tool result is malformed, the JSON is invalid,
                    or the data doesn't match the target class structure.
    """
    if target_class == str:
        return str(tool_result.content[0].text)

    try:
        # 1. Extract the raw text from the first content block.
        #    The MCP protocol typically returns a list of content objects;
        #    we assume the JSON payload is in the first TextContent.
        raw_json = tool_result.content[0].text

        # 2. Parse the JSON string into a Python dictionary.
        data = json.loads(raw_json)

        # 3. Rehydrate: Inject the dictionary data into the target class constructor.
        #    This unpacks the dictionary keys as arguments for the class __init__.
        return target_class(**data)

    except (IndexError, AttributeError) as e:
        # This happens if 'tool_result' doesn't have the expected 'content' list structure
        raise ValueError(f"Failed to access tool content: {e}")

    except json.JSONDecodeError as e:
        # This happens if the tool returned a string that isn't valid JSON
        raise ValueError(f"The tool returned invalid JSON: {e}")

    except TypeError as e:
        # This happens if the JSON keys don't match the target_class arguments
        raise ValueError(f"Data mismatch for class {target_class.__name__}: {e}")