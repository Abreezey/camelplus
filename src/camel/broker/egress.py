"""Pinned-IP HTTP egress for approved EGRESS effects (arch.md §6.9).

Synchronous mirror of B's ``PinnedHTTPTransport``: every request re-resolves
DNS through :class:`~camel.normalization.NetworkPolicy`, connects to the
approved IP literal while preserving the original Host header and TLS SNI,
rejects redirects (authorization never inherits across a 3xx) and rejects a
changed DNS answer as rebinding. Response bodies are size-bounded.
"""

import httpx

from camel.broker.credentials import InjectedCredential
from camel.normalization.net import NetworkPolicy, Resolver, resolve_dns

ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})


class EgressError(Exception):
    """Egress could not be performed within the approved boundary (fail closed)."""


class PinnedSyncTransport(httpx.BaseTransport):
    """Recheck DNS before every request, then connect to the approved address."""

    def __init__(
        self,
        policy: NetworkPolicy,
        *,
        resolver: Resolver = resolve_dns,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._policy, self._resolver = policy, resolver
        self._inner = transport or httpx.HTTPTransport(retries=0, trust_env=False)
        self._targets: dict[tuple[str, int], tuple[str, ...]] = {}

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        target = self._policy.target(str(request.url), self._resolver)
        key = (target.host, target.port)
        if key in self._targets:
            if self._targets[key] != target.addresses:
                raise EgressError("dns_rebinding")
        else:
            self._targets[key] = target.addresses
        pinned = request.url.copy_with(host=target.addresses[0])
        headers = request.headers.copy()
        headers["host"] = request.url.netloc.decode("ascii")
        forwarded = httpx.Request(
            request.method,
            pinned,
            headers=headers,
            stream=request.stream,
            extensions={**request.extensions, "sni_hostname": target.host},
        )
        response = self._inner.handle_request(forwarded)
        if 300 <= response.status_code < 400:
            response.close()
            raise EgressError("egress_redirect_requires_new_authorization")
        return response

    def close(self) -> None:
        self._inner.close()


class EgressClient:
    """One bounded HTTP client per broker; executes a single approved request per call."""

    def __init__(
        self,
        policy: NetworkPolicy,
        *,
        resolver: Resolver = resolve_dns,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
        max_response_bytes: int = 1_048_576,
    ) -> None:
        self._policy = policy
        self._resolver = resolver
        self._client = httpx.Client(
            transport=PinnedSyncTransport(policy, resolver=resolver, transport=transport),
            trust_env=False,
            follow_redirects=False,
            timeout=timeout,
        )
        self._max_response_bytes = max_response_bytes

    def validate(self, url: str) -> None:
        """Pre-ticket static check: allowlist + DNS + private/metadata address rejection."""
        self._policy.target(url, self._resolver)

    def send(
        self,
        *,
        url: str,
        method: str,
        content: bytes | None,
        credential: InjectedCredential | None,
    ) -> bytes:
        headers = (
            {"Authorization": "Bearer " + credential.secret.get_secret_value().hex()}
            if credential is not None
            else None
        )
        try:
            with self._client.stream(method, url, content=content, headers=headers) as response:
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > self._max_response_bytes:
                        raise EgressError("egress_response_size_limit")
                    chunks.append(chunk)
                return b"".join(chunks)
        except httpx.HTTPError as err:
            raise EgressError(f"egress_request_failed: {type(err).__name__}") from err

    def close(self) -> None:
        self._client.close()
