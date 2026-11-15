"""One small adapter per provider. All of them share the same complete() method.

Why adapters? Each company's Python library looks a little different. By hiding those
differences here, the rest of the project can just call provider.complete(prompt)
and get back the same kind of answer from OpenAI, Claude, DeepSeek or Gemini.
"""
import os
from dataclasses import dataclass


@dataclass
class Reply:
    """What a provider sends back, in the same shape for every provider.

    A dataclass is a plain container: it just holds these four named values.
    """

    text: str  # The full reply text from the model.
    model_returned: str  # The model name the API reports, which can differ from the one we asked for.
    input_tokens: int | None  # How many tokens our prompt used. None if the API did not say.
    output_tokens: int | None  # How many tokens the reply used. None if the API did not say.


class Provider:
    """Base class. Holds the settings that every adapter needs.

    The classes below inherit from this one and only add their own complete() method.
    """

    def __init__(self, name: str, settings: dict, defaults: dict) -> None:
        """Read one provider block from config.yaml, falling back to the shared defaults."""
        self.name = name  # Short id such as "openai". Used for file names.
        self.label: str = settings["label"]  # Display name such as "OpenAI".
        self.model: str = settings["model"]  # Model id we ask the API for.
        self.api_key_env: str = settings["api_key_env"]  # Name of the environment variable holding the key.
        self.base_url: str | None = settings.get("base_url")  # Only DeepSeek sets this.
        self.max_tokens_param: str = settings.get("max_tokens_param", "max_tokens")
        # A temperature of None means "do not send one". Some models reject the setting.
        # A provider's own value wins. If it has none, the shared default is used.
        self.temperature: float | None = settings.get("temperature", defaults["temperature"])
        self.max_output_tokens: int = defaults["max_output_tokens"]
        self.timeout: int = defaults["timeout_seconds"]

    def api_key(self) -> str:
        """Return the key from the environment, or fail with a clear message."""
        key = os.environ.get(self.api_key_env)
        if not key:
            raise RuntimeError(f"{self.api_key_env} is not set. Add it to .env or the environment.")
        return key

    def complete(self, prompt: str) -> Reply:
        """Send the prompt to the provider and return its reply."""
        raise NotImplementedError  # Each provider class below fills this in.


class OpenAICompatibleProvider(Provider):
    """OpenAI, and DeepSeek too, because DeepSeek speaks the OpenAI API at its own base URL."""

    def complete(self, prompt: str) -> Reply:
        """Send the prompt through the OpenAI chat completions API."""
        # Imported here so a missing library only breaks the provider that needs it.
        from openai import OpenAI

        # base_url is None for OpenAI (the library default is used) and a DeepSeek address for DeepSeek.
        client = OpenAI(api_key=self.api_key(), base_url=self.base_url, timeout=self.timeout)

        # Build the optional settings. Newer OpenAI models call the token limit
        # max_completion_tokens, so its name comes from config.yaml.
        options = {self.max_tokens_param: self.max_output_tokens}
        if self.temperature is not None:
            options["temperature"] = self.temperature

        # THIS is the call that sends the prompt over the internet and waits for the reply.
        response = client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            **options,
        )
        usage = response.usage
        return Reply(
            text=response.choices[0].message.content or "",
            model_returned=response.model,
            input_tokens=usage.prompt_tokens if usage else None,
            output_tokens=usage.completion_tokens if usage else None,
        )


class ClaudeProvider(Provider):
    """Anthropic Messages API."""

    def complete(self, prompt: str) -> Reply:
        """Send the prompt through the Anthropic messages API."""
        from anthropic import Anthropic

        client = Anthropic(api_key=self.api_key(), timeout=self.timeout)
        # No temperature is sent. The current SDK does not accept it for this call.
        # This call sends the prompt and waits for the reply.
        response = client.messages.create(
            model=self.model,
            max_tokens=self.max_output_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        # A Claude reply is a list of blocks. We join the text ones into one string.
        text = "".join(block.text for block in response.content if block.type == "text")
        return Reply(
            text=text,
            model_returned=response.model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        )


class GeminiProvider(Provider):
    """Google Gemini through the google-genai SDK."""

    def complete(self, prompt: str) -> Reply:
        """Send the prompt through the Gemini generate_content API."""
        from google import genai
        from google.genai import types

        # Gemini wants the timeout in milliseconds, our config uses seconds.
        client = genai.Client(
            api_key=self.api_key(),
            http_options=types.HttpOptions(timeout=self.timeout * 1000),
        )
        config = types.GenerateContentConfig(
            temperature=self.temperature,
            max_output_tokens=self.max_output_tokens,
        )
        # This call sends the prompt and waits for the reply.
        response = client.models.generate_content(model=self.model, contents=prompt, config=config)
        usage = response.usage_metadata
        return Reply(
            text=response.text or "",
            model_returned=response.model_version or self.model,
            input_tokens=usage.prompt_token_count if usage else None,
            output_tokens=usage.candidates_token_count if usage else None,
        )


# Maps the provider name in config.yaml to its adapter class.
# DeepSeek reuses the OpenAI class because it speaks the same API.
ADAPTERS: dict[str, type[Provider]] = {
    "openai": OpenAICompatibleProvider,
    "deepseek": OpenAICompatibleProvider,
    "claude": ClaudeProvider,
    "gemini": GeminiProvider,
}


def build_providers(config: dict, names: list[str] | None = None) -> list[Provider]:
    """Build adapters for the chosen provider names, or all of them when names is None."""
    chosen = names or list(config["providers"])
    # One loop builds every provider. There is no copy-pasted block per provider.
    return [ADAPTERS[name](name, config["providers"][name], config) for name in chosen]
