"""A scripted stand-in for the chat model: replies are given up front, prompts are recorded."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from app.agents.llm import ChatMessage

Reply = dict[str, Any] | str | Exception | Callable[[list[ChatMessage]], Any]


class ScriptedModel:
    name = "scripted-test-model"

    def __init__(self, replies: list[Reply]) -> None:
        self.replies = list(replies)
        self.calls: list[tuple[list[ChatMessage], dict[str, Any]]] = []

    def complete(self, messages: list[ChatMessage], schema: dict[str, Any]) -> str:
        self.calls.append((messages, schema))
        if not self.replies:
            raise AssertionError("scripted model ran out of replies")
        reply = self.replies.pop(0)
        if callable(reply) and not isinstance(reply, Exception):
            reply = reply(messages)
        if isinstance(reply, Exception):
            raise reply
        return reply if isinstance(reply, str) else json.dumps(reply)

    def user_prompt(self, index: int) -> str:
        return self.calls[index][0][-1].content

    def system_prompt(self, index: int) -> str:
        return self.calls[index][0][0].content


def route(next_role: str, instruction: str = "look into it") -> dict[str, Any]:
    return {"next": next_role, "instruction": instruction, "rationale": f"send {next_role}"}


def call(tool: str, **arguments: Any) -> dict[str, Any]:
    return {"action": "tool_call", "tool": tool, "arguments": arguments, "rationale": tool}


def finish(summary: str = "done") -> dict[str, Any]:
    return {"action": "finish", "summary": summary}


def verdict(
    disposition: str = "suspicious_inconclusive",
    confidence: str = "medium",
    supporting: list[str] | None = None,
    contradicting: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "disposition": disposition,
        "confidence": confidence,
        "rationale": "checked the evidence",
        "supporting_evidence_ids": supporting or [],
        "contradicting_evidence_ids": contradicting or [],
        "gaps": [],
        "unsupported_claims": [],
    }
