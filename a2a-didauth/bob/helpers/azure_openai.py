import os
from typing import TypedDict
from dotenv import load_dotenv
from openai import AzureOpenAI

class AzureOpenAIClient(TypedDict):
    """
    Represents a dictionary structure for an Azure OpenAI Client configuration.

    This class is used to define the data structure for storing an Azure OpenAI client
    instance along with its associated deployment name.

    Attributes:
        client (AzureOpenAI): The Azure OpenAI client instance used to interact
            with the Azure OpenAI service.
        deployment_name (str): The name of the deployment configured in
            the Azure OpenAI service.
    """
    client: AzureOpenAI
    deployment_name: str

def create_azure_openai_client() -> AzureOpenAIClient:
    """
    Creates and returns an instance of AzureOpenAIClient configured with environment variables.

    The function initializes an Azure OpenAI client by loading necessary credentials
    and deployment configurations from the environment variables. If any required
    configuration is missing or there is an internal issue with client creation, an
    exception is raised.

    Raises:
        RuntimeError: If an exception occurs during the creation of the Azure OpenAI
        client instance.

    Returns:
        AzureOpenAIClient: An instance of AzureOpenAIClient configured with the
        specified API endpoint, API key, API version, and deployment name.
    """
    load_dotenv(".env", override=True)

    try:
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        api_key = os.getenv("AZURE_OPENAI_API_KEY")
        api_version = os.getenv("AZURE_OPENAI_API_VERSION")
        deployment_name = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME")
        client = AzureOpenAI(
            api_key=api_key,
            api_version=api_version,
            azure_endpoint=endpoint
        )
    except Exception as e:
        raise RuntimeError(f"Error during creation of client AzureOpenAI: {e}")

    return AzureOpenAIClient(client=client, deployment_name=deployment_name)