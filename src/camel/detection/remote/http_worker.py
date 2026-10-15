"""One HTTPS request to the fixed user-selected host. No redirects or retries."""

import json
import sys
import urllib.error
import urllib.request
from typing import Any

from camel.detection.remote.client import BASE_URL, EMBEDDING_MODEL, OUTPUT_LIMIT, VERIFIER_MODEL


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def scrub_reasoning(value: Any) -> tuple[Any, bool]:
    """Remove duplicated provider traces recursively, retaining only presence flags."""
    if isinstance(value, dict):
        cleaned = {}
        present = False
        for key, item in value.items():
            if key in {"reasoning", "reasoning_content", "reasoning_details", "thinking", "analysis"}:
                present |= bool(item)
                continue
            nested, found = scrub_reasoning(item)
            cleaned[key] = nested
            present |= found
        return cleaned, present
    if isinstance(value, list):
        items = [scrub_reasoning(item) for item in value]
        return [item for item, _ in items], any(found for _, found in items)
    return value, False


def perform(packet):
    endpoint = packet["endpoint"]
    payload = packet["payload"]
    if endpoint not in {"embeddings", "chat/completions"}:
        raise ValueError("invalid_endpoint")
    if payload.get("model") != (EMBEDDING_MODEL if endpoint == "embeddings" else VERIFIER_MODEL):
        raise ValueError("invalid_model")
    if endpoint == "chat/completions" and payload.get("max_tokens") != OUTPUT_LIMIT:
        raise ValueError("invalid_output_budget")
    credential = packet["credential"]
    request = urllib.request.Request(
        BASE_URL + "/" + endpoint,
        data=json.dumps(payload, ensure_ascii=False).encode(),
        headers={
            "Authorization": "Bearer " + credential,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=25) as response:
            raw = response.read(2_097_153)
            if len(raw) > 2_097_152:
                return {"status": "RESPONSE_LIMIT", "http_status": response.status}
            text = raw.decode("utf-8")
            if credential in text:
                return {"status": "CREDENTIAL_REFLECTION", "http_status": response.status}
            body = json.loads(text)
            # Do not retain hidden reasoning traces, headers, or server-side error descriptions.
            if isinstance(body, dict):
                choices = body.get("choices", [])
                for index, choice in enumerate(choices):
                    if isinstance(choice, dict):
                        cleaned, found = scrub_reasoning(choice)
                        cleaned["reasoning_present"] = bool(found or choice.get("reasoning_present"))
                        choices[index] = cleaned
                body, _ = scrub_reasoning(body)
            return {"status": "OK", "http_status": response.status, "body": body}
    except urllib.error.HTTPError as error:
        return {"status": "HTTP_ERROR", "http_status": error.code}
    except Exception as error:
        return {"status": "NETWORK_OR_PROTOCOL_ERROR", "error_type": type(error).__name__}


def main():
    try:
        raw = sys.stdin.buffer.read(131073)
        if len(raw) > 131072:
            raise ValueError("input_limit")
        result = perform(json.loads(raw))
    except Exception:
        result = {"status": "WORKER_ERROR"}
    sys.stdout.write(json.dumps(result, ensure_ascii=True))


if __name__ == "__main__":
    main()
