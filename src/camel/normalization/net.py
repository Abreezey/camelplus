"""Network normalization and DNS validation (arch.md §6.4).

Allowlisting names is insufficient: every DNS answer is checked and actual
HTTP connections must use the validated IP, preserving TLS hostname checks.
Metadata, mapped private addresses and redirects never inherit authorization.
"""

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import quote, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field

from camel.core.effect import EffectType
from camel.normalization.ingress import structural_text
from camel.normalization.models import NormalizationContext, NormalizationError, NormalizationResult, make_effect

Resolver = Callable[[str, int], tuple[str, ...]]


def resolve_dns(host: str, port: int) -> tuple[str, ...]:
    try:
        return tuple(sorted({str(record[4][0]) for record in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}))
    except OSError as err:
        raise NormalizationError("dns_resolution_failed") from err


class NetworkTarget(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    url: str
    host: str
    port: int
    addresses: tuple[str, ...]


class NetworkPolicy(BaseModel):
    """Exact host/port allowlists; private networks require an explicit deployment exception.

    ``allowed_networks`` is intended for local MCP deployments/tests. Link-local
    metadata addresses stay forbidden even when a network is explicitly allowed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed_hosts: frozenset[str] = Field(default_factory=frozenset)
    allowed_ports: frozenset[int] = frozenset({80, 443})
    allowed_networks: tuple[str, ...] = ()

    def target(self, url: str, resolver: Resolver = resolve_dns) -> NetworkTarget:
        structural_text(url)
        if any(c.isspace() for c in url) or "\\" in url or "%" in urlsplit(url).netloc:
            raise NormalizationError("ambiguous_url")
        try:
            parts = urlsplit(url)
            if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
                raise NormalizationError("unsupported_url")
            host = parts.hostname.rstrip(".").encode("idna").decode("ascii").lower()
            port = parts.port or (443 if parts.scheme == "https" else 80)
            if host not in self.allowed_hosts or port not in self.allowed_ports:
                raise NormalizationError("egress_not_allowlisted")
            addresses = resolver(host, port)
            if not addresses:
                raise NormalizationError("empty_dns_answer")
            for address in addresses:
                ip = ipaddress.ip_address(address)
                if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
                    ip = ip.ipv4_mapped
                if ip.is_link_local or ip.is_unspecified or ip.is_multicast or str(ip) == "100.100.100.200":
                    raise NormalizationError("metadata_or_special_address")
                allowed_private = any(ip in ipaddress.ip_network(n) for n in self.allowed_networks)
                if not ip.is_global and not allowed_private:
                    raise NormalizationError("private_network_address")
            authority = f"[{host}]" if ":" in host else host
            if port != (443 if parts.scheme == "https" else 80):
                authority += f":{port}"
            path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
            normalized = urlunsplit((parts.scheme, authority, path, parts.query, ""))
            return NetworkTarget(url=normalized, host=host, port=port, addresses=tuple(sorted(set(addresses))))
        except (ValueError, UnicodeError) as err:
            if isinstance(err, NormalizationError):
                raise
            raise NormalizationError("invalid_url_or_address") from err

    def revalidate(self, target: NetworkTarget, resolver: Resolver = resolve_dns) -> NetworkTarget:
        current = self.target(target.url, resolver)
        if current.addresses != target.addresses:
            raise NormalizationError("dns_rebinding")
        return current


def normalize_net(
    method: str,
    url: str,
    context: NormalizationContext,
    policy: NetworkPolicy,
    resolver: Resolver = resolve_dns,
    redirects: tuple[str, ...] = (),
) -> NormalizationResult:
    if method.upper() not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise NormalizationError("unsupported_http_method")
    targets = [policy.target(u, resolver) for u in (url, *redirects)]
    return NormalizationResult(
        effects=tuple(
            make_effect(context, EffectType.EGRESS, f"http_{method.lower()}", destination=t.url) for t in targets
        )
    )
