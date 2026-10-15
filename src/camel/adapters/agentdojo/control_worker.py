"""Fixed inert child for controller tests. Never loads models or task environments."""

import os
import sys
import time
from pathlib import Path

from camel.adapters.agentdojo.controller import Job, bounded_json, write_json


def main():
    def guard(event, arguments):
        if event in {
            "socket.connect",
            "socket.getaddrinfo",
            "socket.sendto",
            "urllib.Request",
            "subprocess.Popen",
            "os.system",
            "os.fork",
            "os.posix_spawn",
        }:
            raise RuntimeError("synthetic_worker_is_offline")

    sys.addaudithook(guard)
    directory = Path(sys.argv[1]).resolve()
    job = Job.model_validate(bounded_json(directory / "request.json"))
    spec = job.episode
    write_json(directory / "ready.json", dict(episode_id=spec.episode_id))
    if job.case == "crash":
        os._exit(9)
    if job.case in {"goal", "effect_timeout"}:
        write_json(directory / "state.json", dict(episode_id=spec.episode_id, synthetic_goal=True, extra_effect=True))
    if job.case in {"hang", "effect_timeout", "cancel"}:
        while True:
            time.sleep(0.05)
    messages = [
        dict(role="user", content=[dict(type="text", content="INERT SYNTHETIC REQUEST")]),
        dict(role="assistant", content=[], tool_calls=None),
    ]
    if job.case == "tool_error":
        messages.insert(1, dict(role="tool", content=[], error="SYNTHETIC TOOL ERROR"))
    write_json(
        directory / "trace.json",
        dict(
            suite_name=spec.suite,
            pipeline_name=spec.pipeline_name,
            user_task_id=spec.user_task_id,
            injection_task_id=spec.injection_task_id,
            attack_type=spec.attack_type,
            benchmark_version=spec.benchmark_version,
            agentdojo_package_version=spec.package_version,
            utility=True,
            security=job.case in {"goal", "native_error", "tool_error"},
            duration=0.01,
            error="SYNTHETIC NATIVE ERROR" if job.case == "native_error" else None,
            injections={"synthetic_vector": "INERT DATA"} if spec.kind == "attack" else {},
            messages=messages,
        ),
    )
    if job.case != "missing_usage":
        usage = [
            dict(
                call_index=index,
                role=call.role,
                input_tokens=call.input_tokens,
                output_tokens=call.max_output_tokens + (1 if job.case == "bad_usage" else 0),
                cost_units=call.max_cost_units,
            )
            for index, call in enumerate(job.calls)
        ]
        write_json(directory / "usage.json", usage)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
