"""Async LLM client — OpenAI-compatible, used ONLY for remediation summarization.

Safety contract:
  - LLM NEVER receives raw vulnerability discovery tasks.
  - LLM ONLY receives structured, validated finding data + pre-computed template steps.
  - System prompt enforces strict non-invention rules.
  - Graceful degradation: if LLM is unavailable, callers fall back to templates.
"""
from __future__ import annotations

import structlog

log = structlog.get_logger(__name__)

_SYSTEM_PROMPT = """You are a security remediation advisor.

STRICT RULES — violation is not permitted under any circumstances:
1. Only reference vulnerabilities explicitly present in the findings_data field provided to you.
2. Do NOT invent, speculate about, or add vulnerabilities not present in the input data.
3. Do NOT hallucinate CVEs, exploits, affected systems, or attack techniques not explicitly provided.
4. Your ONLY task: synthesize the provided remediation_steps into a coherent, concise remediation narrative for the specific context described in findings_data.
5. Be technical, specific, and actionable. Do not use generic advice.
6. Maximum 200 words. No markdown headers. Plain paragraphs only.
"""


class AsyncLLMClient:
    """Async wrapper around openai SDK with configurable base_url.

    Supports OpenAI, Ollama, Groq, Azure-compatible endpoints.
    """

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str | None = None,
        model: str = "gpt-4o-mini",
        timeout: float = 30.0,
    ) -> None:
        try:
            from openai import AsyncOpenAI  # type: ignore[import-untyped]

            kwargs: dict = {"api_key": api_key, "timeout": timeout}
            if base_url:
                kwargs["base_url"] = base_url
            self._client = AsyncOpenAI(**kwargs)
            self._model = model
            self._enabled = True
        except ImportError:
            log.warning("acl.llm.openai_not_installed", reason="openai package missing")
            self._enabled = False

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def summarize_remediation(
        self,
        *,
        exposure_type: str,
        target_url: str,
        confidence: float,
        poc_triggered: bool,
        evidence_summary: str | None,
        cluster_size: int,
        propagation_depth: int,
        remediation_steps: list[str],
    ) -> str | None:
        """Return an LLM-generated narrative for the provided validated finding.

        Returns None on any error — callers use template steps as fallback.
        """
        if not self._enabled:
            return None

        findings_data = {
            "exposure_type": exposure_type,
            "affected_url": target_url,
            "confidence": confidence,
            "poc_triggered": poc_triggered,
            "evidence_summary": evidence_summary or "N/A",
            "cluster_size": cluster_size,
            "propagation_depth": propagation_depth,
            "remediation_steps": remediation_steps,
        }

        user_message = (
            f"findings_data: {findings_data}\n\n"
            f"Synthesize these {len(remediation_steps)} remediation steps into "
            f"a concise, context-aware remediation narrative."
        )

        try:
            response = await self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_message},
                ],
                max_tokens=300,
                temperature=0.2,  # low temp for factual, reproducible output
            )
            narrative = response.choices[0].message.content
            log.info("acl.llm.summarized", exposure_type=exposure_type)
            return narrative.strip() if narrative else None
        except Exception as exc:
            log.warning("acl.llm.error", error=str(exc))
            return None
