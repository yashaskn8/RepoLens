"""Deterministic, versionable LangChain ChatPromptTemplate factories for RepoLens workflows.

Provides standardized prompt templates for repository analysis, structured extraction,
and security review without embedding credentials, API keys, or raw secrets.
"""

from __future__ import annotations

from langchain_core.prompts import (
    ChatPromptTemplate,
    HumanMessagePromptTemplate,
    SystemMessagePromptTemplate,
)

PROMPT_VERSION_REPO_ANALYSIS = "repo-analysis-v1"
PROMPT_VERSION_STRUCTURED_EXTRACTION = "structured-extraction-v1"
PROMPT_VERSION_SECURITY_REVIEW = "security-review-v1"


def create_repository_analysis_prompt() -> ChatPromptTemplate:
    """Return deterministic prompt template for repository architecture and codebase analysis."""
    system_prompt = (
        "You are RepoLens, an expert repository analysis AI engine. "
        "Analyze the provided repository context, files, and architectural relationships. "
        "Provide accurate, actionable, and mathematically grounded insights without speculation."
    )
    human_prompt = (
        "Repository: {repository_name}\n"
        "Branch / Ref: {branch_name}\n"
        "Context Summary:\n{context_summary}\n\n"
        "Task Instructions:\n{task_description}"
    )
    return ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            ("human", human_prompt),
        ]
    )


def create_structured_extraction_prompt() -> ChatPromptTemplate:
    """Return deterministic prompt template for bounded structured data extraction."""
    system_prompt = (
        "You are a deterministic structured extraction engine. "
        "Extract the requested data strictly conforming to the specified output schema. "
        "Output valid JSON without surrounding commentary, markdown fences, or extra text."
    )
    human_prompt = (
        "Target Schema Description: {schema_description}\n\n"
        "Input Content:\n{content}\n\n"
        "Extraction Directives: {directives}"
    )
    return ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            ("human", human_prompt),
        ]
    )


def create_security_review_prompt() -> ChatPromptTemplate:
    """Return deterministic prompt template for code security audits and patch reviews."""
    system_prompt = (
        "You are an automated code security auditor for RepoLens. "
        "Examine the provided patch, diff, or file contents for security vulnerabilities, "
        "credential leaks, injection vectors, and broken access controls. "
        "Never echo or log raw credential material."
    )
    human_prompt = (
        "Repository: {repository_name}\n"
        "Commit / Diff Scope: {scope}\n\n"
        "Code Diff:\n{diff_content}\n\n"
        "Security Focus Areas:\n{focus_areas}"
    )
    return ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            ("human", human_prompt),
        ]
    )
