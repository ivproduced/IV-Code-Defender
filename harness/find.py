# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Find loop: start container, run find-agent, parse output, extract PoC.

Budget: max_turns=2000 (one run is hours, not minutes).
"""
from __future__ import annotations

import json
import time

from . import docker_ops, sandbox
from .agent import run_agent, parse_xml_tag, AgentResult
from .artifacts import CrashArtifact
from .config import TargetConfig
from .profiles import build_find_prompt, is_web, load_web_manifest


DEFAULT_FIND_MAX_TURNS = 2000


async def run_find(
    target: TargetConfig,
    model: str,
    max_turns: int = DEFAULT_FIND_MAX_TURNS,
    agent_env: dict[str, str] | None = None,
    container_name: str = "find_target",
    focus_area: str | None = None,
    known_bugs: list[str] | None = None,
    found_bugs_path: str | None = None,
    transcript_path: str | None = None,
    progress_prefix: str | None = None,
    accept_dos: bool = False,
    system_prompt: str | None = None,
    max_resume_attempts: int = 20,
) -> tuple[CrashArtifact | None, AgentResult, dict[str, float]]:
    """Run one find attempt against a target.

    Returns (crash_or_none, agent_result, timings).
    crash is None if no PoC was emitted or the claimed path was empty.

    Assumes the image is already built (caller owns docker_ops.build).
    """
    timings: dict[str, float] = {}

    mounts = [(str(found_bugs_path), "/tmp/found_bugs.jsonl")] if found_bugs_path else None
    with sandbox.agent_container(
        target.image_tag, container_name, agent_env,
        memory=target.memory_limit, shm_size=target.shm_size, mounts=mounts,
    ) as container:
        prompt = build_find_prompt(
            target=target,
            focus_area=focus_area,
            known_bugs=known_bugs if known_bugs is not None else target.known_bugs,
            found_bugs_path="/tmp/found_bugs.jsonl" if found_bugs_path else None,
            accept_dos=accept_dos,
        )
        t0 = time.time()
        result = await run_agent(
            prompt=prompt,
            max_turns=max_turns,
            model=model,
            container=container,
            transcript_path=transcript_path,
            progress_prefix=progress_prefix,
            system_prompt=system_prompt,
            max_resume_attempts=max_resume_attempts,
        )
        timings["find"] = time.time() - t0

        # Parse tags — scan backwards, don't trust the last message.
        text = result.find_tagged_message("poc_path")
        if is_web(target.profile):
            text = result.find_tagged_message("replay_manifest_path")
            manifest_path = parse_xml_tag(text, "replay_manifest_path")
            dup_check = parse_xml_tag(text, "dup_check")
            if not manifest_path:
                return None, result, timings
            manifest_bytes = docker_ops.read_file(container, manifest_path)
            if not manifest_bytes:
                return None, result, timings
            try:
                manifest = load_web_manifest(manifest_bytes, target)
            except ValueError:
                return None, result, timings
            replay_command = manifest["replay_command"]
            if manifest_path not in replay_command:
                return None, result, timings
            evidence = manifest["evidence"]
            return CrashArtifact(
                poc_path=manifest_path,
                poc_bytes=manifest_bytes,
                reproduction_command=replay_command,
                crash_type=parse_xml_tag(text, "finding_type") or "web-finding",
                crash_output=json.dumps(evidence, sort_keys=True)[:10_000],
                exit_code=0,
                dup_check=dup_check,
                profile=target.profile,
                replay_manifest=manifest,
                evidence_bundle=evidence,
                detection_signal=json.dumps(manifest["detection_signal"], sort_keys=True),
            ), result, timings

        poc_path = parse_xml_tag(text, "poc_path")
        reproduction_command = parse_xml_tag(text, "reproduction_command")
        crash_type = parse_xml_tag(text, "crash_type")
        crash_output = parse_xml_tag(text, "crash_output") or ""
        exit_code_str = parse_xml_tag(text, "exit_code")
        dup_check = parse_xml_tag(text, "dup_check")

        if not poc_path or not reproduction_command:
            return None, result, timings

        # Empty bytes → agent narrated a path it never wrote.
        poc_bytes = docker_ops.read_file(container, poc_path)
        if not poc_bytes:
            return None, result, timings

        crash = CrashArtifact(
            poc_path=poc_path,
            poc_bytes=poc_bytes,
            reproduction_command=reproduction_command,
            crash_type=crash_type or "unknown",
            crash_output=crash_output[:10_000],  # ASAN traces are huge; top is what matters
            exit_code=_parse_exit_code(exit_code_str),
            dup_check=dup_check,
        )
        return crash, result, timings


def _parse_exit_code(s: str | None) -> int:
    if s is None:
        return -1
    s = s.strip()
    if s.lstrip("-").isdigit():
        return int(s)
    return -1
