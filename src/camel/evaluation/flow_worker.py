"""Fixed connected D worker; only fixture SQLite and durable simulated records."""

import hashlib
import os
import sys
import time
from pathlib import Path

from camel.adapters.agentdojo.controller import bounded_json, write_json
from camel.evaluation.connected import run_flow
from camel.evaluation.flow_process import ProcessJob
from camel.evaluation.replay import RecordingTool


def pause():
    while True:
        time.sleep(0.05)


class JournalRecorder(RecordingTool):
    def __init__(self, directory: Path, job: ProcessJob):
        super().__init__()
        self.directory, self.job = directory, job
        for name in ["intents", "records", "errors"]:
            (directory / name).mkdir()

    def invoke(self, effect, payload, response):
        write_json(
            self.directory / "intents/000.json",
            dict(job_id=self.job.job_id, case_id=self.job.flow.case_id, effect_id=effect.effect_id),
        )
        if self.job.mode == "hang_at_intent":
            write_json(self.directory / "paused.json", dict(stage="intent"))
            pause()
        super().invoke(effect, payload, response)
        write_json(
            self.directory / "records/000.json",
            dict(job_id=self.job.job_id, case_id=self.job.flow.case_id, sequence=0, record=self.ledger[-1]),
        )
        if self.job.mode == "error_after":
            write_json(
                self.directory / "errors/000.json", dict(stage="recording_tool", error="SYNTHETIC RECORDER ERROR")
            )


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
            raise RuntimeError("D_workflow_worker_is_offline")

    sys.addaudithook(guard)
    directory = Path(sys.argv[1]).resolve()
    job = ProcessJob.model_validate(bounded_json(directory / "request.json", 131072))
    write_json(directory / "ready.json", dict(job_id=job.job_id))
    if job.mode == "hang_before":
        pause()
    recorder = JournalRecorder(directory, job)
    try:
        row = run_flow(job.flow, directory / "flow", recorder=recorder)
        write_json(directory / "result.json", row)
        write_json(directory / "result_ready.json", dict(job_id=job.job_id))
        if job.mode == "hang_after":
            pause()
        if job.mode == "crash_after":
            os._exit(9)
    except Exception as error:
        write_json(
            directory / "errors/exception.json",
            dict(
                error_type=type(error).__name__,
                error_sha256=hashlib.sha256(str(error).encode(errors="surrogatepass")).hexdigest(),
            ),
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
