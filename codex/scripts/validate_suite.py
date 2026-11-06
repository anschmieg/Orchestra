#!/usr/bin/env python3
"""Validate the executable conformance contract for the Orchestra source tree."""

from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from typing import Callable


REQUIRED_PATHS = (
    "README.md",
    "VISION.md",
    "AGENTS.md",
    "docs/WORKFLOW.md",
    "docs/ARCHITECTURE.md",
    "docs/ROADMAP.md",
    "orchestra.toml",
    ".agent/backend-testing.md",
    ".githooks/pre-commit",
    "codex/scripts/validate_suite.py",
    "codex/scripts/comment_policy.py",
    "codex/tests/test_comment_policy.py",
    "codex/scripts/package_plugin.py",
    "codex/scripts/prepare_source.py",
    "codex/tests/test_prepare_source.py",
    "codex/tests/test_package_plugin.py",
    "codex/scripts/update_local.py",
    "codex/tests/test_update_local.py",
    "packaging/orchestra/.codex-plugin/plugin.json",
    "packaging/README.md",
    "packaging/claude/hooks/hooks.json",
    "packaging/claude/hooks/read_package.py",
    "codex/skills/orchestra/runtime.md",
    "codex/scripts/task_state.py",
    "codex/scripts/commit_phase.py",
    "codex/scripts/adopt_worktree.py",
    "codex/scripts/policy.py",
    "codex/scripts/pr.py",
    "codex/scripts/integrate_local.py",
    "codex/scripts/_common.py",
    "codex/scripts/acceptance_keyring.py",    "codex/scripts/acceptance_evidence.py",    "codex/scripts/acceptance_gate.py",    "codex/scripts/acceptance_reconcile.py",    "codex/scripts/acceptance_policy.py",    "codex/scripts/acceptance_cli.py",    "codex/tests/test_acceptance_keyring.py",    "codex/tests/test_acceptance_evidence.py",    "codex/tests/test_acceptance_gate.py",    "codex/tests/test_acceptance_reconcile.py",    "codex/tests/test_acceptance_adversarial.py",    "codex/tests/test_acceptance_recovery.py",    "docs/acceptance/TRUSTWORTHY_ACCEPTANCE.md",    "codex/config/flow.toml",
    "codex/skills/orchestra/SKILL.md",
    "codex/skills/orchestra/agents/openai.yaml",
    "codex/skills/orchestra-project-start/SKILL.md",
    "codex/skills/orchestra-project-start/agents/openai.yaml",
    "codex/skills/orchestra-repo-readiness/SKILL.md",
    "codex/skills/orchestra-repo-readiness/agents/openai.yaml",
    "codex/skills/orchestra-engineering/SKILL.md",
    "codex/skills/orchestra-engineering/agents/openai.yaml",
    "codex/skills/orchestra-project-verification/SKILL.md",
    "codex/skills/orchestra-project-verification/agents/openai.yaml",
    "codex/skills/orchestrator/SKILL.md",
    "codex/skills/orchestrator/agents/openai.yaml",
    "codex/skills/orchestra-models/SKILL.md",
    "codex/skills/orchestra-models/agents/openai.yaml",
    "codex/skills/orchestra-project-verification/feature-example.md",
    "codex/skills/orchestrator/packet-example.md",
    "codex/skills/orchestrator/acceptance-packet.md",
    "codex/skills/orchestrator/host-transports.md",
    "codex/skills/orchestrator/project-workspace.md",
    "docs/evaluation/MODULAR_ACCEPTANCE.md",
    "codex/tests/fixtures/modular_engineering/make_fixture.py",
    "codex/tests/test_modular_fixture.py",
    "codex/skills/orchestra/references/repository_context.md",
    "codex/skills/orchestra/references/web_research.md",
    "codex/skills/orchestra/references/technical_planning.md",
    "codex/skills/orchestra/references/difficult_debugging.md",
    "codex/skills/orchestra/references/frontend_implementation.md",
    "codex/skills/orchestra/references/browser_acceptance.md",
    "codex/skills/orchestra/references/runtime_verification.md",
    "codex/skills/orchestra/references/architecture_guidance.md",
    "codex/skills/orchestra/references/shared_conduct.md",
    "codex/skills/orchestra/references/finding_triage.md",
    "codex/skills/orchestra/references/planning_stage.md",
    "codex/skills/orchestra-role-analyst/SKILL.md",
    "codex/skills/orchestra-role-analyst/agents/openai.yaml",
    "codex/skills/orchestra-role-implementer/SKILL.md",
    "codex/skills/orchestra-role-implementer/agents/openai.yaml",
    "codex/skills/orchestra-role-reviewer/SKILL.md",
    "codex/skills/orchestra-role-reviewer/agents/openai.yaml",
    "codex/skills/orchestra-role-verifier/SKILL.md",
    "codex/skills/orchestra-role-verifier/agents/openai.yaml",
    "codex/skills/orchestra-phase-commit/SKILL.md",
    "codex/skills/orchestra-phase-commit/agents/openai.yaml",
    "codex/skills/orchestra-delivery-policy/SKILL.md",
    "codex/skills/orchestra-delivery-policy/agents/openai.yaml",
    "codex/skills/orchestra-pr-open/SKILL.md",
    "codex/skills/orchestra-pr-open/agents/openai.yaml",
    "codex/skills/orchestra-pr-review/SKILL.md",
    "codex/skills/orchestra-pr-review/agents/openai.yaml",
    "codex/skills/orchestra-pr-merge/SKILL.md",
    "codex/skills/orchestra-pr-merge/agents/openai.yaml",
    "codex/skills/orchestra-local-integrate/SKILL.md",
    "codex/skills/orchestra-local-integrate/agents/openai.yaml",
    "codex/tests/test_commit_phase.py",
    "codex/tests/test_adopt_worktree.py",
    "codex/tests/test_routing_activation.py",
    "codex/tests/test_planned_flow.py",
    "codex/tests/test_validate_suite.py",
    "codex/tests/test_delivery_policy.py",
    "codex/tests/test_pr_flow.py",
    "codex/tests/test_local_integration.py",
)

PERMANENT_DOCS = (
    "README.md",
    "VISION.md",
    "AGENTS.md",
    "docs/WORKFLOW.md",
    "docs/ARCHITECTURE.md",
    "docs/ROADMAP.md",
)

HISTORICAL_NARRATIVES = (
    (
        "historical product replacement narrative",
        re.compile(
            r"\b(?:this|orchestra)\s+replaces?\s+(?:the\s+)?"
            r"(?:legacy|former|predecessor)\s+"
            r"(?:product|implementation|workflow|runtime)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "historical product label",
        re.compile(
            r"\b(?:legacy|former|predecessor)\s+(?:[\w-]+\s+){0,3}"
            r"(?:product|implementation|repository|runtime|workflow)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "historical repository path",
        re.compile(r"\bOrchestra-legacy\b", re.IGNORECASE),
    ),
    (
        "versioned product identity",
        re.compile(r"\bOrchestra\s+(?:v2|version\s+2)\b", re.IGNORECASE),
    ),
    (
        "rebuild narrative",
        re.compile(
            r"\b(?:clean-room rebuild|target for the rebuild|plan the rebuild|"
            r"during the rebuild|rebuild of Orchestra|fresh Git history)\b",
            re.IGNORECASE,
        ),
    ),
)

ROADMAP_REQUIREMENTS = (
    "This roadmap is non-canonical. It does not override `VISION.md`, "
    "`docs/WORKFLOW.md`, `docs/ARCHITECTURE.md`, or `AGENTS.md`.",
    "Local plugin packaging is supported.",
    "does not prescribe an implementation design.",
)

HOOK_CONTENT = """#!/bin/sh
set -eu
REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec python3 "$REPO_ROOT/codex/scripts/validate_suite.py" --quick --comment-target staged
"""

ROLE_SKILLS = (
    "orchestra-role-analyst",
    "orchestra-role-implementer",
    "orchestra-role-reviewer",
    "orchestra-role-verifier",
)

PLAYBOOK_NAMES = (
    "repository_context",
    "web_research",
    "technical_planning",
    "difficult_debugging",
    "frontend_implementation",
    "browser_acceptance",
    "runtime_verification",
)
ARCHITECTURE_REFERENCE = "architecture_guidance"
SKILL_NAMES = (
    "orchestra",
    "orchestra-project-start",
    "orchestra-repo-readiness",
    "orchestra-engineering",
    "orchestra-project-verification",
    "orchestrator",
    "orchestra-models",
    "orchestra-phase-commit",
    "orchestra-delivery-policy",
    "orchestra-pr-open",
    "orchestra-pr-review",
    "orchestra-pr-merge",
    "orchestra-local-integrate",
    "orchestra-role-analyst",
    "orchestra-role-implementer",
    "orchestra-role-reviewer",
    "orchestra-role-verifier",
)
def check_required_paths(root: Path) -> list[str]:
    """Ensure every current conformance consumer is present and tracked."""
    failures = [
        f"required-path: missing {relative}"
        for relative in REQUIRED_PATHS
        if not (root / relative).is_file()
    ]
    git_dir = root / ".git"
    if not git_dir.exists():
        return failures
    try:
        listed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
        ).stdout
    except OSError as exc:
        failures.append(
            "required-path: unable to verify tracked paths via git ls-files "
            f"({type(exc).__name__})"
        )
        return failures
    except subprocess.CalledProcessError as exc:
        failures.append(
            "required-path: unable to verify tracked paths via git ls-files "
            f"(exit {exc.returncode})"
        )
        return failures
    tracked = set(listed.decode().split("\0")) - {""}
    failures.extend(
        f"required-path: untracked {relative}"
        for relative in REQUIRED_PATHS
        if (root / relative).is_file() and relative not in tracked
    )
    return failures


CAPABILITY_PROFILES = {
    "repository_context": "orchestra_analyst",
    "web_research": "orchestra_analyst",
    "technical_planning": "orchestra_analyst",
    "architecture_analysis": "orchestra_analyst",
    "difficult_debugging": "orchestra_analyst",
    "general_implementation": "orchestra_implementation_worker",
    "frontend_implementation": "orchestra_implementation_worker",
    "independent_review": "orchestra_reviewer",
    "browser_acceptance": "orchestra_verifier",
    "runtime_verification": "orchestra_verifier",
}
REASONING_EFFORTS = {"low", "medium", "high", "xhigh", "max"}


def check_distribution_boundary(root: Path) -> list[str]:
    """Keep generated plugin manifests out of the canonical source roots."""
    failures: list[str] = []
    migration = root / "docs/MIGRATION.md"
    if migration.exists():
        failures.append("distribution-boundary: remove docs/MIGRATION.md")

    for relative in (Path(".codex-plugin"), Path("codex/.codex-plugin")):
        if (root / relative).exists():
            failures.append(
                f"distribution-boundary: generated manifest belongs in a package, not {relative.as_posix()}"
            )
    return failures


def check_delivery_config(root: Path) -> list[str]:
    """Delegate source policy validation to its only loader."""
    helper = root / "codex/scripts/policy.py"
    if not helper.is_file():
        return []
    result = subprocess.run(
        [sys.executable, str(helper), "--repo", str(root), "show"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        return [f"delivery-contract: policy helper returned invalid JSON: {error}"]
    if not isinstance(payload, dict):
        return ["delivery-contract: policy helper returned invalid result"]
    if result.returncode or payload.get("status") != "ok":
        return [f"delivery-contract: {payload.get('reason', 'policy validation failed')}"]
    if payload.get("mode") != "hybrid":
        return ["delivery-contract: source repository mode must be hybrid"]
    return []


def check_flow_assignment(root: Path) -> list[str]:
    path = root / "codex/config/flow.toml"
    if not path.is_file():
        return []
    try:
        flow = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeError) as error:
        return [f"flow-contract: codex/config/flow.toml is invalid: {error}"]
    failures: list[str] = []
    if set(flow) != {"capabilities", "review_pair", "escalation"}:
        failures.append("flow-contract: flow.toml defines capabilities, review_pair and escalation only")

    def entry_failures(label: str, entry: object) -> list[str]:
        if not isinstance(entry, dict) or not {"provider", "model"} <= set(entry) <= {"provider", "model", "effort"}:
            return [f"flow-contract: {label} needs provider and model, and at most effort"]
        if not all(isinstance(entry[key], str) and entry[key].strip() for key in ("provider", "model")):
            return [f"flow-contract: {label} needs a non-empty provider and model"]
        if "effort" in entry and entry["effort"] not in REASONING_EFFORTS:
            return [f"flow-contract: {label} has an invalid effort"]
        return []

    capabilities = flow.get("capabilities")
    if not isinstance(capabilities, dict) or set(capabilities) != set(CAPABILITY_PROFILES):
        failures.append("flow-contract: flow.toml must assign every capability and no other")
    else:
        for capability, entry in capabilities.items():
            failures.extend(entry_failures(f"capabilities.{capability}", entry))
    failures.extend(entry_failures("review_pair", flow.get("review_pair")))
    escalation = flow.get("escalation")
    if not isinstance(escalation, list) or not escalation:
        failures.append("flow-contract: escalation needs at least one attempt")
    else:
        for index, entry in enumerate(escalation, start=2):
            failures.extend(entry_failures(f"escalation attempt {index}", entry))

    for name in ROLE_SKILLS:
        role_path = root / f"codex/skills/{name}/SKILL.md"
        if not role_path.is_file():
            continue
        role_text = role_path.read_text(encoding="utf-8")
        for heading in ("## Input", "## Output", "## Stop conditions"):
            if heading not in role_text:
                failures.append(f"role-contract: {name} is missing {heading}")
        if "shared_conduct.md" not in role_text:
            failures.append(f"role-contract: {name} must reference shared conduct")
    for name in SKILL_NAMES:
        skill = root / f"codex/skills/{name}/SKILL.md"
        if skill.is_file() and re.search(r"\b(?:gpt|claude|grok)-\d", skill.read_text(encoding="utf-8")):
            failures.append(
                "role-contract: model assignments live only in codex/config/flow.toml; "
                f"found one in {skill.relative_to(root)}"
            )
    routing_path = root / "codex/skills/orchestra/SKILL.md"
    if routing_path.is_file():
        routing = routing_path.read_text(encoding="utf-8")
        for capability in CAPABILITY_PROFILES:
            if f"`{capability}`" not in routing:
                failures.append(f"role-contract: {capability} is not consumed by orchestra routing")
    return failures


def _skill_frontmatter(text: str) -> dict[str, str] | None:
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        return None
    raw = text[4:].split("\n---\n", 1)[0]
    metadata: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(":")
        if not separator or not key or not value.strip():
            return None
        metadata[key.strip()] = value.strip()
    return metadata


def _local_markdown_links(text: str) -> list[str]:
    return [
        target
        for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", text)
        if not target.startswith(("#", "http://", "https://"))
    ]


def check_skills_and_runtime(root: Path) -> list[str]:
    """Validate skill metadata, direct links, and the managed routing block."""
    failures: list[str] = []
    for name in SKILL_NAMES:
        skill = root / f"codex/skills/{name}/SKILL.md"
        if not skill.is_file():
            continue
        text = skill.read_text(encoding="utf-8")
        metadata = _skill_frontmatter(text)
        if metadata is None or set(metadata) != {"name", "description"}:
            failures.append(f"skill-contract: {name} needs name and description metadata")
        elif metadata["name"] != name or "TODO" in metadata["description"]:
            failures.append(f"skill-contract: {name} metadata is incomplete")

        for target in _local_markdown_links(text):
            resolved = (skill.parent / target.split("#", 1)[0]).resolve()
            if not resolved.is_file():
                failures.append(f"skill-contract: {name} has broken link {target}")

        runtime = (root / "codex/skills/orchestra/runtime.md").resolve()
        targets = {
            (skill.parent / target.split("#", 1)[0]).resolve()
            for target in _local_markdown_links(text)
        }
        if runtime not in targets:
            failures.append(f"skill-contract: {name} must link runtime.md for runtime and continuity routing")

        metadata_file = skill.parent / "agents/openai.yaml"
        if metadata_file.is_file():
            ui = metadata_file.read_text(encoding="utf-8")
            for field in ("display_name:", "short_description:", "default_prompt:"):
                if field not in ui:
                    failures.append(f"skill-contract: {name} openai.yaml is missing {field}")
            if f"${name}" not in ui:
                failures.append(
                    f"skill-contract: {name} default_prompt must mention ${name}"
                )
            if name in {"orchestra-project-start", "orchestra-engineering", "orchestra-project-verification"} and (
                "allow_implicit_invocation: true" not in ui
            ):
                failures.append(
                    f"skill-contract: {name} must allow implicit invocation"
                )

    references = root / "codex/skills/orchestra/references"
    expected_references = {
        *(f"{name}.md" for name in PLAYBOOK_NAMES),
        f"{ARCHITECTURE_REFERENCE}.md",
        "shared_conduct.md",
        "source_preparation.md",
        "host_t3.md",
        "model_notes.md",
        "finding_triage.md",
        "planning_stage.md",
    }
    if not references.is_dir():
        failures.append("skill-contract: orchestra internal references are missing")
    else:
        actual_references = {entry.name for entry in references.iterdir()}
        if actual_references != expected_references or any(
            not entry.is_file() or entry.is_symlink() for entry in references.iterdir()
        ):
            failures.append(
                "skill-contract: orchestra must contain exactly seven playbooks, "
                "one architecture reference, one shared conduct reference, "
                "one source preparation recipe, the T3 Code adapter, "
                "the model notes, the finding triage and the planning stage"
            )
        routing_path = root / "codex/skills/orchestra/SKILL.md"
        if routing_path.is_file():
            routing = routing_path.read_text(encoding="utf-8")
            for name in PLAYBOOK_NAMES:
                target = f"references/{name}.md"
                if target not in routing:
                    failures.append(
                        f"skill-contract: orchestra does not consume playbook {target}"
                    )
            for forbidden in (
                "references/general_implementation.md",
                "references/independent_review.md",
                "references/architecture_analysis.md",
            ):
                if forbidden in routing:
                    failures.append(
                        f"skill-contract: {forbidden} must not be a playbook"
                    )
    guidance = (references / f"{ARCHITECTURE_REFERENCE}.md").resolve()
    guidance_consumers = [
        *(f"codex/skills/{name}/SKILL.md" for name in (
            "orchestra",
            "orchestra-role-analyst",
            "orchestra-role-implementer",
            "orchestra-role-reviewer",
            "orchestra-role-verifier",
            "orchestra-repo-readiness",
            "orchestra-project-start",
            "orchestra-engineering",
            "orchestra-project-verification",
        )),
        *(f"codex/skills/orchestra/references/{name}.md" for name in (
            "repository_context",
            "technical_planning",
            "runtime_verification",
            "browser_acceptance",
        )),
    ]
    for relative in guidance_consumers:
        consumer = root / relative
        if not consumer.is_file():
            continue  # Required-path validation owns missing source files.
        targets = {
            (consumer.parent / target.split("#", 1)[0]).resolve()
            for target in _local_markdown_links(consumer.read_text(encoding="utf-8"))
        }
        if guidance not in targets:
            failures.append(
                f"skill-contract: {relative} must link to shared engineering guidance "
                f"({ARCHITECTURE_REFERENCE}.md)"
            )

    direct_consumers = {
        "orchestra": (
            "task_state.py",
            ),
        "orchestra-phase-commit": ("commit_phase.py",),
        "orchestra-pr-review": (
            "pr.py",
            "observe",
            "independent_review",
        ),
        "orchestra-pr-open": (
            "pr.py",
            "--expected-task-revision",
        ),
        "orchestra-pr-merge": (
            "--base-worktree",
            "--task-branch",
            "--base-branch",
            "--expected-task-revision",
            "--remote",
            "lease",
        ),
        "orchestra-local-integrate": (
            "--task-worktree",
            "--base-worktree",
            "--expected-task-revision",
            "--checkout-mode",
        ),
    }
    for name, required_text in direct_consumers.items():
        skill = root / f"codex/skills/{name}/SKILL.md"
        if not skill.is_file():
            continue
        text = skill.read_text(encoding="utf-8")
        for expected in required_text:
            if expected not in text:
                failures.append(
                    f"skill-contract: {name} must directly consume {expected}"
                )

    runtime_root = "${ORCHESTRA_RUNTIME_ROOT}"
    exempt = {"orchestra-project-start", "orchestra-engineering",
              "orchestra-project-verification", "orchestrator", "orchestra-repo-readiness",
              *ROLE_SKILLS}
    for name in (skill for skill in SKILL_NAMES if skill not in exempt):
        skill = root / f"codex/skills/{name}/SKILL.md"
        if skill.is_file() and runtime_root not in skill.read_text(encoding="utf-8"):
            failures.append(f"runtime-contract: {name} must name the selected runtime root")
    return failures



def check_modular_routing(root: Path) -> list[str]:
    failures: list[str] = []
    routes = {
        "orchestra-repo-readiness": ("Repository readiness", ("../orchestra-engineering/SKILL.md", "../orchestra-project-verification/SKILL.md")),
        "orchestra-engineering": ("Modular engineering", ("../orchestra-project-verification/SKILL.md",)),
        "orchestra-project-verification": ("Project verification", ("feature-example.md",)),
        "orchestrator": ("Initiative coordination", ("host-transports.md", "packet-example.md", "project-workspace.md", "acceptance-packet.md", "../orchestra/SKILL.md")),
    }
    workflow = root / "docs/WORKFLOW.md"
    policy = workflow.read_text(encoding="utf-8") if workflow.is_file() else ""
    for name, (section, resources) in routes.items():
        skill = root / f"codex/skills/{name}/SKILL.md"
        if not skill.is_file():
            continue
        content = skill.read_text(encoding="utf-8")
        if f"## {section}" not in policy or section not in " ".join(content.split()):
            failures.append(f"modular-routing: {name} must route to WORKFLOW {section}")
        links = {target.split("#", 1)[0] for target in _local_markdown_links(content)}
        for target in ("../orchestra/runtime.md", *resources):
            if target not in links:
                failures.append(f"modular-routing: {name} must link {target}")
    for name in ("orchestrator", "orchestra-repo-readiness"):
        metadata = root / f"codex/skills/{name}/agents/openai.yaml"
        if metadata.is_file() and "allow_implicit_invocation: false" not in metadata.read_text(encoding="utf-8"):
            failures.append(f"modular-routing: {name} must remain explicit-only")
    guidance = root / "codex/skills/orchestra/references/architecture_guidance.md"
    consumers = [
        root / f"codex/skills/{name}/SKILL.md"
        for name in ("orchestra-role-implementer", "orchestra-role-reviewer",
                     "orchestra-engineering", "orchestra-project-start",
                     "orchestra-project-verification", "orchestra-repo-readiness")
    ]
    consumers.append(root / "codex/skills/orchestra/references/shared_conduct.md")
    consumers.append(root / "codex/skills/orchestrator/packet-example.md")
    for consumer in consumers:
        if not consumer.is_file():
            continue
        targets = {
            ((consumer.parent / link.split("#", 1)[0]).resolve(), link.partition("#")[2])
            for link in _local_markdown_links(consumer.read_text(encoding="utf-8"))
        }
        if (guidance.resolve(), "source-comments") not in targets:
            failures.append(f"modular-routing: {consumer.relative_to(root)} must directly link architecture_guidance.md#source-comments")
    evidence_consumers = [
        root / f"codex/skills/{name}/SKILL.md"
        for name in ("orchestra-role-analyst", "orchestra-role-implementer",
                     "orchestra-role-reviewer", "orchestra-role-verifier",
                     "orchestra-engineering")
    ]
    evidence_consumers.extend(
        root / f"codex/skills/orchestra/references/{name}.md"
        for name in ("repository_context", "technical_planning", "runtime_verification")
    )
    evidence_consumers.append(root / "codex/skills/orchestrator/acceptance-packet.md")
    testing_consumers = [
        root / f"codex/skills/{name}/SKILL.md"
        for name in ("orchestra-role-analyst", "orchestra-role-implementer",
                     "orchestra-role-reviewer", "orchestra-role-verifier",
                     "orchestra-engineering",
                     "orchestra-project-verification", "orchestra-repo-readiness")
    ]
    testing_consumers.extend(
        root / f"codex/skills/orchestra/references/{name}.md"
        for name in ("technical_planning", "runtime_verification", "browser_acceptance")
    )
    guidance_routes = {
        "decision-evidence": evidence_consumers,
        "behavioral-verification": testing_consumers,
        "change-quality": [root / f"codex/skills/{name}/SKILL.md" for name in
                           ("orchestra-role-implementer", "orchestra-role-reviewer",
                            "orchestra-engineering")],
        "test-maintenance": [root / "codex/skills/orchestra-repo-readiness/SKILL.md"],
        "staged-outcomes": [root / f"codex/skills/{name}/SKILL.md" for name in
                            ("orchestra", "orchestrator", "orchestra-engineering",
                             "orchestra-project-start")],
    }
    for anchor, consumers in guidance_routes.items():
        for consumer in consumers:
            if not consumer.is_file():
                continue
            targets = {
                ((consumer.parent / link.split("#", 1)[0]).resolve(), link.partition("#")[2])
                for link in _local_markdown_links(consumer.read_text(encoding="utf-8"))
            }
            if (guidance.resolve(), anchor) not in targets:
                failures.append(f"modular-routing: {consumer.relative_to(root)} must directly link architecture_guidance.md#{anchor}")
    return failures


def check_documentation(root: Path) -> list[str]:
    """Validate product identity, roadmap boundary, and timeless documentation."""
    failures: list[str] = []
    roadmap = root / "docs/ROADMAP.md"
    if roadmap.is_file():
        roadmap_text = roadmap.read_text(encoding="utf-8")
        normalized = " ".join(roadmap_text.split())
        for requirement in ROADMAP_REQUIREMENTS:
            if requirement not in normalized:
                failures.append(
                    "documentation: docs/ROADMAP.md is missing required boundary: "
                    f"{requirement}"
                )

    for relative in PERMANENT_DOCS:
        path = root / relative
        if not path.is_file():
            continue
        normalized = " ".join(path.read_text(encoding="utf-8").split())
        for label, pattern in HISTORICAL_NARRATIVES:
            if pattern.search(normalized):
                failures.append(f"documentation: {relative} contains {label}")
                break
    return failures


def check_hook(root: Path) -> list[str]:
    """Keep the hook an executable wrapper around quick conformance."""
    hook = root / ".githooks/pre-commit"
    if not hook.is_file():
        return []
    failures: list[str] = []
    if hook.read_text(encoding="utf-8") != HOOK_CONTENT:
        failures.append(
            "hook-contract: .githooks/pre-commit must only invoke "
            "validate_suite.py --quick"
        )
    if not os.access(hook, os.X_OK):
        failures.append("hook-contract: make .githooks/pre-commit executable")
    return failures


def check_python_syntax(root: Path) -> list[str]:
    """Parse the Python implementation and its tests without executing them."""
    failures: list[str] = []
    for base in (root / "codex/scripts", root / "codex/tests"):
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            try:
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (SyntaxError, UnicodeError) as error:
                relative = path.relative_to(root).as_posix()
                failures.append(f"python-syntax: {relative}: {error}")
    return failures


def check_python_tests(root: Path) -> list[str]:
    """Run the repository's standard-library unit tests in full mode."""
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "codex/tests",
            "-p",
            "test_*.py",
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    if result.returncode == 0:
        return []
    output = "\n".join(
        part.strip() for part in (result.stdout, result.stderr) if part.strip()
    )
    return [f"python-tests: unittest discovery failed\n{output}"]



def check_trustworthy_acceptance(root: Path) -> list[str]:
    failures: list[str] = []
    scripts = [
        "codex/scripts/acceptance_keyring.py",
        "codex/scripts/acceptance_evidence.py",
        "codex/scripts/acceptance_gate.py",
        "codex/scripts/acceptance_reconcile.py",
        "codex/scripts/acceptance_policy.py",
        "codex/scripts/acceptance_cli.py",
    ]
    for relative in scripts:
        path = root / relative
        if not path.is_file():
            failures.append(f"trustworthy-acceptance: missing {relative}")
    tests = [
        "codex/tests/test_acceptance_keyring.py",
        "codex/tests/test_acceptance_evidence.py",
        "codex/tests/test_acceptance_gate.py",
        "codex/tests/test_acceptance_reconcile.py",
        "codex/tests/test_acceptance_adversarial.py",
        "codex/tests/test_acceptance_recovery.py",
    ]
    for relative in tests:
        if not (root / relative).is_file():
            failures.append(f"trustworthy-acceptance: missing {relative}")
    doc = root / "docs/acceptance/TRUSTWORTHY_ACCEPTANCE.md"
    if not doc.is_file():
        failures.append("trustworthy-acceptance: missing docs/acceptance/TRUSTWORTHY_ACCEPTANCE.md")
    return failures


def check_repository_conventions(root: Path) -> list[str]:
    """Keep this repository's `.agent/` hard-gate command declaration exact."""
    failures: list[str] = []
    relative = ".agent/backend-testing.md"
    path = root / relative
    if not path.is_file():
        return [f"repository-conventions: missing {relative}"]
    normalized = " ".join(path.read_text(encoding="utf-8").lower().split())
    for contract in (
        "python3 codex/scripts/validate_suite.py --full",
        "python3 codex/scripts/validate_suite.py --quick",
    ):
        if contract not in normalized:
            failures.append(
                f"repository-conventions: {relative} must name {contract}"
            )
    return failures


Check = Callable[[Path], list[str]]
QUICK_CHECKS: tuple[Check, ...] = (
    check_required_paths,
    check_distribution_boundary,
    check_delivery_config,
    check_documentation,
    check_hook,
    check_flow_assignment,
    check_skills_and_runtime,
    check_modular_routing,
    check_repository_conventions,
    check_trustworthy_acceptance,
)
FULL_CHECKS: tuple[Check, ...] = QUICK_CHECKS + (
    check_python_syntax,
    check_python_tests,
)


def comment_base(root: Path, selected: str | None) -> str:
    def git(*args: str) -> str:
        result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
        if result.returncode:
            raise ValueError(f"comment-policy: cannot resolve Git base ({result.stderr.strip()}); fetch the base or pass --comment-base SHA")
        return result.stdout.strip()

    if selected != "ci":
        if selected is not None:
            return selected
        head = subprocess.run(["git", "-C", str(root), "rev-parse", "--verify", "HEAD"], capture_output=True)
        return "HEAD" if head.returncode == 0 else "EMPTY"
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        raise ValueError("comment-policy: --comment-base ci requires GITHUB_EVENT_PATH")
    event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    if not isinstance(event, dict):
        raise ValueError("comment-policy: CI event must be a JSON object")
    kind = os.environ.get("GITHUB_EVENT_NAME")
    if kind == "pull_request":
        base = event.get("pull_request", {}).get("base", {}).get("sha")
        if not isinstance(base, str) or not re.fullmatch(r"[0-9a-fA-F]{40,64}", base) or set(base) == {"0"}:
            raise ValueError("comment-policy: pull request event has no valid base SHA")
        return base
    if kind == "push":
        base = event.get("before")
        if isinstance(base, str) and re.fullmatch(r"[0-9a-fA-F]{40,64}", base) and set(base) != {"0"}:
            return base
        if not isinstance(base, str) or not re.fullmatch(r"0{40}|0{64}", base):
            raise ValueError("comment-policy: push event has no valid before SHA")
        branch = event.get("repository", {}).get("default_branch")
        if not isinstance(branch, str) or not branch or branch.startswith("-"):
            raise ValueError("comment-policy: new branch event has no default branch")
        parents = git("rev-list", "--parents", "-n", "1", "HEAD").split()
        if len(parents) == 1:
            return "EMPTY"
        if event.get("ref") == f"refs/heads/{branch}":
            raise ValueError("comment-policy: first multi-commit default-branch push has no pre-push base; supply an explicitly reviewed --comment-base SHA")
        return git("merge-base", "HEAD", f"refs/remotes/origin/{branch}")
    if kind == "workflow_dispatch":
        parents = git("rev-list", "--parents", "-n", "1", "HEAD").split()
        return parents[1] if len(parents) > 1 else "EMPTY"
    raise ValueError(f"comment-policy: unsupported CI event {kind!r}; pass an explicit base SHA")


def validate(root: Path, mode: str, *, base: str | None = None,
             target: str = "worktree", full_scan: bool = False,
             enforce_full_scan: bool = False) -> list[str]:
    checks = QUICK_CHECKS if mode == "quick" else FULL_CHECKS
    failures: list[str] = []
    for check in QUICK_CHECKS:
        failures.extend(check(root))
        if failures:
            return failures
    from comment_policy import CommentPolicyError, check_repository
    try:
        findings = check_repository(root, base=comment_base(root, base) if not full_scan else "HEAD",
                                    target=target, full_scan=full_scan)
    except (CommentPolicyError, ValueError, OSError) as error:
        return [str(error)]
    if full_scan and not enforce_full_scan:
        print(f"DIAGNOSTIC: Python source comments full scan: {len(findings)} finding(s); no Git-delta enforcement.")
        for finding in findings:
            print(f"DIAGNOSTIC: {finding}")
    elif findings:
        return findings
    for check in checks[len(QUICK_CHECKS):]:
        failures.extend(check(root))
        if failures:
            break
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--quick", action="store_true", help="run hook-safe checks")
    mode.add_argument("--full", action="store_true", help="run all local checks")
    parser.add_argument("--comment-base", help="Git revision for introduced Python comments; ci resolves the GitHub event base")
    parser.add_argument("--comment-target", choices=("worktree", "staged"), default="worktree")
    parser.add_argument("--comment-full-scan", action="store_true", help="diagnose all Python comments, including source exports without Git")
    parser.add_argument("--comment-enforce-full-scan", action="store_true", help="gate a full scan only after explicitly declaring the entire source scope repaired")
    args = parser.parse_args()
    if args.comment_enforce_full_scan and not args.comment_full_scan:
        parser.error("--comment-enforce-full-scan requires --comment-full-scan")
    if args.comment_full_scan and (args.comment_base or args.comment_target != "worktree"):
        parser.error("full scan cannot be combined with a Git base or staged target")
    return args


def main() -> int:
    args = parse_args()
    mode = "quick" if args.quick else "full"
    root = Path(__file__).resolve().parents[2]
    failures = validate(root, mode, base=args.comment_base, target=args.comment_target,
                        full_scan=args.comment_full_scan, enforce_full_scan=args.comment_enforce_full_scan)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        print(f"Conformance failed with {len(failures)} actionable issue(s).")
        return 1
    check_count = len(QUICK_CHECKS if mode == "quick" else FULL_CHECKS) + 1
    print(f"OK: {mode} conformance passed ({check_count} checks).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
