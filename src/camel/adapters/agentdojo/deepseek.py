"""DeepSeek Chat Completions adapter for pinned AgentDojo 0.1.34.

AgentDojo's OpenAI adapter rewrites system messages to the OpenAI-specific
``developer`` role and wraps requests in tenacity retries. DeepSeek's Chat
Completions endpoint accepts ``system`` instead, while hosted evaluation must
account for every request without an unbounded retry layer.
"""

from collections.abc import Sequence
from typing import cast

import openai
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.openai_llm import (
    _function_to_openai,
    _message_to_openai,
    _openai_to_assistant_message,
)
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage
from openai._types import NOT_GIVEN
from openai.types.chat import ChatCompletionMessageParam
from pydantic_ai.messages import ModelMessage, ModelResponse
from pydantic_ai.models import ModelRequestParameters
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.settings import ModelSettings


class DeepSeekStructuredModel(OpenAIModel):
    """Disable thinking for PydanticAI's required structured-output tool.

    ``deepseek-flash`` currently defaults to thinking mode, which rejects the
    ``tool_choice=required`` request PydanticAI uses for typed output. Keeping
    this provider quirk on the model adapter avoids changing generic CaMeL
    quarantined-LLM behavior.
    """

    async def request(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
    ) -> ModelResponse:
        settings = dict(model_settings or {})
        extra_body = dict(cast(dict, settings.get("extra_body") or {}))
        extra_body["thinking"] = {"type": "disabled"}
        settings["extra_body"] = extra_body
        return await super().request(messages, cast(ModelSettings, settings), model_request_parameters)


class DeepSeekLLM(BasePipelineElement):
    """Single-attempt OpenAI-compatible adapter with bounded output."""

    def __init__(self, client: openai.OpenAI, model: str, *, max_tokens: int = 4096) -> None:
        if max_tokens < 1:
            raise ValueError("invalid_deepseek_max_tokens")
        self.client = client
        self.model = model
        self.name = model
        self.max_tokens = max_tokens

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        converted: list[ChatCompletionMessageParam] = []
        for message in messages:
            item = dict(_message_to_openai(message, self.model))
            if item.get("role") == "developer":
                item["role"] = "system"
            converted.append(cast(ChatCompletionMessageParam, item))
        tools = [_function_to_openai(function) for function in runtime.functions.values()]
        completion = self.client.chat.completions.create(
            model=self.model,
            messages=converted,
            tools=tools or NOT_GIVEN,
            tool_choice="auto" if tools else NOT_GIVEN,
            max_tokens=self.max_tokens,
        )
        output = _openai_to_assistant_message(completion.choices[0].message)
        return query, runtime, env, [*messages, output], extra_args
