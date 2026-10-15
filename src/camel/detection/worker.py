"""One bounded provider attempt. JSON IPC only; mock mode rejects networking."""

import contextlib
import json
import os
import sys
import time

from camel.detection.models import ParseRequest, ProviderSettings


def main() -> None:
    status = "PROVIDER_ERROR"
    payload = None
    try:
        raw = sys.stdin.buffer.read(1048577)
        if len(raw) > 1048576:
            raise ValueError("worker_input_limit")
        packet = json.loads(raw)
        settings = ProviderSettings.model_validate_json(json.dumps(packet["settings"]))
        request = ParseRequest.model_validate_json(json.dumps(packet["request"]))
        maximum = packet["max_output_bytes"]
        if settings.kind == "mock":

            def offline_guard(event, arguments):
                if event in {"socket.connect", "socket.getaddrinfo", "urllib.Request"}:
                    raise RuntimeError("mock provider prohibits networking")

            sys.addaudithook(offline_guard)
            reply = settings.replies[min(packet["attempt"] - 1, len(settings.replies) - 1)]
            if reply.mode == "timeout":
                time.sleep(60)
            if reply.mode == "raise":
                raise RuntimeError("synthetic provider failure")
            if reply.mode == "insufficient":
                payload = json.dumps({"schema_version": 1, "have_enough_information": False, "facts": []})
            elif reply.mode == "oversize":
                payload = "x" * (maximum + 1)
            else:
                payload = reply.output
        else:
            from camel.detection.parsing import legacy_complete

            with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                payload = legacy_complete(request, settings.model or "")
        if not isinstance(payload, str):
            raise ValueError("non_text_provider_output")
        if len(payload.encode("utf-8")) > maximum:
            status = "OUTPUT_LIMIT"
            payload = None
        else:
            status = "OK"
    except Exception:
        status = "PROVIDER_ERROR"
        payload = None
    sys.stdout.write(json.dumps({"status": status, "payload": payload}, ensure_ascii=False))


if __name__ == "__main__":
    main()
