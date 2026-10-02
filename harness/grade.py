# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Grade loop: fresh container from same image, grader agent verifies PoC.

The trust boundary is the image tag — find-agent could write anywhere
in its container but can't retroactively modify the image. A fresh container
from the same tag is pristine. Only the PoC bytes cross the boundary.

Budget: 50 turns — it's a checklist, not research.
"""
from __future__ import annotations

import asyncio
import math
import os
import re
import subprocess
import time
from dataclasses import dataclass

from . import docker_ops, sandbox
from .agent import run_agent, parse_xml_tag, AgentResult
from .artifacts import CrashArtifact, GraderVerdict
from .asan import crash_reason, top_frame
from .config import TargetConfig
from .io_utils import atomic_write_bytes
from .profiles import (build_grade_prompt, is_web, load_web_manifest,
                       trusted_reproduction_command)
from .prompts.untrusted import make_nonce, untrusted_block


GRADE_MAX_TURNS = 50
REPLAY_RUNS = 3
REPLAY_TIMEOUT_S = 600


@dataclass(frozen=True)
class ReplayObservation:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def output(self) -> str:
        return f"{self.stdout}\n{self.stderr}".strip()


async def run_grade(
    crash: CrashArtifact,
    target: TargetConfig,
    model: str,
    workspace_dir: str,
    agent_env: dict[str, str] | None = None,
    container_name: str = "grader_target",
    transcript_path: str | None = None,
    progress_prefix: str | None = None,
    system_prompt: str | None = None,
    accept_dos: bool = False,
) -> tuple[GraderVerdict, AgentResult, float]:
    """Verify a CrashArtifact in a fresh container.

    workspace_dir: host-side results dir where we also persist poc.bin so
    it survives the container teardown.
    """
    grade_started = time.time()
    artifact_name = "replay.json" if is_web(target.profile) else "poc.bin"
    workspace_artifact = f"/tmp/{artifact_name}"
    adapted_cmd = trusted_reproduction_command(target, crash, workspace_artifact)

    os.makedirs(workspace_dir, exist_ok=True)
    atomic_write_bytes(os.path.join(workspace_dir, artifact_name), crash.poc_bytes)

    # The executable oracle gets no provider credentials and no network. This
    # keeps target execution out of the model-authenticated process tree.
    replay_name = f"{container_name}_replay"
    with sandbox.agent_container(
        target.image_tag, replay_name, auth=None, network="none"
    ) as replay_container:
        docker_ops.write_file(replay_container, workspace_artifact, crash.poc_bytes)
        observations = await _collect_replay(replay_container, adapted_cmd)

    machine_criteria, machine_evidence = _machine_verdict(
        crash, target, observations, accept_dos=accept_dos
    )
    if not all(machine_criteria.values()):
        return (
            GraderVerdict(
                passed=False,
                score=0.0,
                criteria={
                    f"criterion_{i}": machine_criteria.get(f"criterion_{i}", False)
                    for i in range(1, 6)
                },
                evidence=machine_evidence,
            ),
            AgentResult(),
            time.time() - grade_started,
        )

    # The semantic grader receives pipeline-captured evidence and no tools. It
    # cannot execute the target or replace the machine replay with assertions.
    with sandbox.agent_container(target.image_tag, container_name, agent_env) as container:
        docker_ops.write_file(container, workspace_artifact, crash.poc_bytes)
        prompt = build_grade_prompt(
            target=target, crash=crash, adapted_command=adapted_cmd,
            workspace_artifact=workspace_artifact,
        )
        prompt += (
            "\n\n## Pipeline-owned replay evidence\n"
            "The orchestrator already executed the exact command three times in "
            "a separate credential-free, networkless container. These observations "
            "are authoritative. Do not rerun the target; evaluate the remaining "
            "semantic criteria from this evidence and the supplied finding.\n\n"
            f"{untrusted_block(machine_evidence, make_nonce())}\n"
        )
        if accept_dos:
            prompt += (
                "\nBenchmark mode is enabled: allocation-size-too-big and "
                "other explicitly submitted DoS-class sanitizer failures are "
                "eligible; do not fail them solely for being resource-driven.\n"
            )
        result = await run_agent(
            prompt=prompt,
            max_turns=GRADE_MAX_TURNS,
            model=model,
            container=container,
            tools=[],
            transcript_path=transcript_path,
            progress_prefix=progress_prefix,
            system_prompt=system_prompt,
        )
        elapsed = time.time() - grade_started

        text = result.find_tagged_message("overall")
        verdict = _parse_verdict(text)
        merged = {
            key: verdict.criteria.get(key, False) and passed
            for key, passed in machine_criteria.items()
        }
        verdict.criteria.update(merged)
        verdict.passed = verdict.passed and all(machine_criteria.values())
        verdict.evidence = f"{machine_evidence}\n\nSemantic grader:\n{verdict.evidence}"
        return verdict, result, elapsed


async def _collect_replay(container: str, command: str) -> list[ReplayObservation]:
    observations: list[ReplayObservation] = []
    for _ in range(REPLAY_RUNS):
        try:
            rc, stdout, stderr = await asyncio.to_thread(
                docker_ops.exec_sh,
                container,
                command,
                timeout=REPLAY_TIMEOUT_S,
            )
            observations.append(ReplayObservation(rc, stdout, stderr))
        except subprocess.TimeoutExpired:
            observations.append(
                ReplayObservation(None, "", "", timed_out=True)
            )
    return observations


_OOM_MARKERS = (
    "out of memory",
    "cannot allocate",
    "allocator is out of memory",
    "allocation-size-too-big",
)


def _machine_verdict(
    crash: CrashArtifact,
    target: TargetConfig,
    observations: list[ReplayObservation],
    *,
    accept_dos: bool = False,
) -> tuple[dict[str, bool], str]:
    """Return machine-owned criteria and a bounded evidence transcript."""
    criteria: dict[str, bool] = {
        "criterion_1": bool(crash.poc_bytes),
    }
    outputs = [item.output for item in observations]
    oom_markers = (
        tuple(marker for marker in _OOM_MARKERS if marker != "allocation-size-too-big")
        if accept_dos else _OOM_MARKERS
    )
    no_resource_failure = all(
        not item.timed_out
        and item.returncode not in (124, 137)
        and not any(marker in item.output.lower() for marker in oom_markers)
        for item in observations
    )

    if is_web(target.profile):
        try:
            load_web_manifest(crash.poc_bytes, target)
        except ValueError:
            criteria["criterion_1"] = False
        successful = [
            item.returncode == 0 and not item.timed_out for item in observations
        ]
        signal = target.detection_signal or ""
        criteria.update({
            "criterion_2": len(observations) == REPLAY_RUNS and all(successful),
            "criterion_3": no_resource_failure and bool(signal)
            and all(signal in output for output in outputs),
            # Security relevance and sequence consistency remain semantic, but
            # must still be explicitly passed by the no-tool grader.
            "criterion_4": True,
            "criterion_5": True,
        })
    else:
        signatures = [_crash_signature(output) for output in outputs]
        claimed_signature = _crash_signature(crash.crash_output)
        reproduced = [
            item.returncode not in (None, 0) and signature is not None
            for item, signature in zip(observations, signatures)
        ]
        landed = [sig for sig, ok in zip(signatures, reproduced) if ok]
        criteria.update({
            "criterion_2": len(landed) >= 2,
            "criterion_3": no_resource_failure,
            "criterion_4": len(landed) >= 2
            and sum(
                signature is not None and target.source_root in signature[1]
                for signature in signatures
            ) >= 2,
            "criterion_5": len(landed) >= 2
            and len(set(landed)) == 1
            and (claimed_signature is None or landed[0] == claimed_signature),
        })

    lines = []
    for index, item in enumerate(observations, 1):
        clipped = item.output[-4000:]
        lines.append(
            f"[run {index}] rc={item.returncode} timeout={item.timed_out}\n{clipped}"
        )
    lines.append(
        "[machine criteria] "
        + ", ".join(f"{key}={'PASS' if value else 'FAIL'}"
                    for key, value in sorted(criteria.items()))
    )
    return criteria, "\n\n".join(lines)


def _crash_signature(output: str) -> tuple[str, str] | None:
    """Identify both the sanitizer class and the source crash site.

    Line numbers can shift between equivalent frames, so compare function and
    file while retaining different functions or files as distinct sites.
    """
    reason = crash_reason(output).get("crash_type")
    if not reason:
        lowered = output.lower()
        if "assertion" in lowered and "failed" in lowered:
            reason = "assertion-failure"
        elif "addresssanitizer:deadlysignal" in lowered:
            reason = "deadly-signal"
    frame = top_frame(output)
    if not reason or not frame:
        return None
    return reason, re.sub(r":\d+(?::\d+)?$", "", frame)


def _parse_verdict(text: str) -> GraderVerdict:
    """Parse grader output and enforce the five-criterion rubric in code."""
    criteria: dict[str, bool] = {}
    for i in range(1, 6):
        val = parse_xml_tag(text, f"criterion_{i}")
        criteria[f"criterion_{i}"] = (
            val is not None and val.upper().startswith("PASS")
        )

    overall = parse_xml_tag(text, "overall")
    overall_pass = overall is not None and overall.upper().startswith("PASS")
    return GraderVerdict(
        passed=overall_pass and all(criteria.values()),
        score=_parse_score(parse_xml_tag(text, "score")),
        criteria=criteria,
        evidence=parse_xml_tag(text, "evidence") or "",
    )


def _parse_score(s: str | None) -> float:
    if not s:
        return 0.0
    try:
        value = float(s.strip())
    except ValueError:
        return 0.0
    return value if math.isfinite(value) and 0.0 <= value <= 1.0 else 0.0
