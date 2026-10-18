"""SPF (RFC 7208) record resolution and IP mechanism matching.

``check_spf(client_ip, mail_from, helo)`` implements the RFC 7208 ``check_host()`` function:

* DNS TXT lookup of the ``v=spf1`` record (exactly one record allowed, else ``permerror``);
* mechanisms ``all``, ``include``, ``a``, ``mx``, ``ptr``, ``ip4``, ``ip6``, ``exists`` with
  qualifiers ``+ - ~ ?`` and dual CIDR lengths;
* modifiers ``redirect=`` (``exp=`` is parsed but never fetched - it is attacker-controlled);
* macro expansion (``%{s} %{l} %{o} %{d} %{i} %{v} %{h}`` with transformers);
* the DNS-lookup limit (10) and void-lookup limit (2) that protect against SPF-based DoS.

DNS access goes through the small :class:`DNSResolver` interface so tests (and the attack
simulations) can run offline with :class:`FakeResolver`, as required by PLAN.md "Test mode".
:class:`DnsPythonResolver` is the real implementation. The same resolver classes are reused
by ``dkim_check`` (key lookup) and ``dmarc_check`` (policy lookup).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import quote

# SPF result codes (RFC 7208 section 2.6)
PASS = "pass"
FAIL = "fail"
SOFTFAIL = "softfail"
NEUTRAL = "neutral"
NONE = "none"
TEMPERROR = "temperror"
PERMERROR = "permerror"

_QUALIFIER_RESULT = {"+": PASS, "-": FAIL, "~": SOFTFAIL, "?": NEUTRAL}


# --------------------------------------------------------------------------------------
# DNS abstraction
# --------------------------------------------------------------------------------------
class DNSTemporaryError(Exception):
    """DNS lookup failed in a way that may succeed later (timeout, SERVFAIL, no servers)."""


class DNSResolver(Protocol):
    """Minimal DNS interface. NXDOMAIN / NODATA must return ``[]``; transient failures raise
    :class:`DNSTemporaryError`."""

    def txt(self, name: str) -> list[str]:
        """TXT strings for *name*; the character-strings of one record are concatenated."""

    def a(self, name: str) -> list[str]: ...

    def aaaa(self, name: str) -> list[str]: ...

    def mx(self, name: str) -> list[str]:
        """MX exchange host names ordered by preference."""

    def ptr(self, ip: str) -> list[str]:
        """Host names from the reverse (PTR) lookup of *ip*."""


def _norm(name: str) -> str:
    return name.strip().rstrip(".").lower()


class DnsPythonResolver:
    """Real resolver built on ``dnspython``."""

    def __init__(
        self,
        nameservers: list[str] | None = None,
        timeout: float = 3.0,
        lifetime: float = 6.0,
    ) -> None:
        import dns.resolver

        self._resolver = dns.resolver.Resolver()
        if nameservers:
            self._resolver.nameservers = nameservers
        self._resolver.timeout = timeout
        self._resolver.lifetime = lifetime

    def _query(self, name: str, rdtype: str) -> list:
        import dns.exception
        import dns.name
        import dns.resolver

        try:
            return list(self._resolver.resolve(_norm(name), rdtype))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.name.NameTooLong, dns.name.LabelTooLong, dns.name.EmptyLabel):
            return []  # syntactically impossible name: it simply does not exist
        except dns.exception.DNSException as exc:  # Timeout, NoNameservers (SERVFAIL), ...
            raise DNSTemporaryError(f"{rdtype} lookup of {name!r} failed: {exc}") from exc

    def txt(self, name: str) -> list[str]:
        return [
            b"".join(rdata.strings).decode("utf-8", "replace") for rdata in self._query(name, "TXT")
        ]

    def a(self, name: str) -> list[str]:
        return [rdata.address for rdata in self._query(name, "A")]

    def aaaa(self, name: str) -> list[str]:
        return [rdata.address for rdata in self._query(name, "AAAA")]

    def mx(self, name: str) -> list[str]:
        records = sorted(self._query(name, "MX"), key=lambda r: r.preference)
        return [_norm(str(r.exchange)) for r in records]

    def ptr(self, ip: str) -> list[str]:
        reverse = ipaddress.ip_address(ip).reverse_pointer
        return [_norm(str(r.target)) for r in self._query(reverse, "PTR")]


class FakeResolver:
    """In-memory resolver for tests and offline simulations (PLAN.md "Test mode").

    >>> r = FakeResolver(txt={"example.com": "v=spf1 ip4:192.0.2.0/24 -all"})
    >>> r.txt("EXAMPLE.com.")
    ['v=spf1 ip4:192.0.2.0/24 -all']

    Names put in *temp_fail* raise :class:`DNSTemporaryError` for every record type.
    Every lookup is appended to ``queries`` as ``(rdtype, name)``.
    """

    def __init__(
        self,
        txt: dict[str, str | list[str]] | None = None,
        a: dict[str, list[str]] | None = None,
        aaaa: dict[str, list[str]] | None = None,
        mx: dict[str, list[str]] | None = None,
        ptr: dict[str, list[str]] | None = None,
        temp_fail: set[str] | None = None,
    ) -> None:
        self._txt = {_norm(k): [v] if isinstance(v, str) else list(v) for k, v in (txt or {}).items()}
        self._a = {_norm(k): list(v) for k, v in (a or {}).items()}
        self._aaaa = {_norm(k): list(v) for k, v in (aaaa or {}).items()}
        self._mx = {_norm(k): list(v) for k, v in (mx or {}).items()}
        self._ptr = {k: list(v) for k, v in (ptr or {}).items()}
        self._temp_fail = {_norm(n) for n in (temp_fail or set())}
        self.queries: list[tuple[str, str]] = []

    def _get(self, table: dict[str, list[str]], rdtype: str, name: str) -> list[str]:
        key = _norm(name)
        self.queries.append((rdtype, key))
        if key in self._temp_fail:
            raise DNSTemporaryError(f"simulated DNS failure for {key}")
        return list(table.get(key, []))

    def txt(self, name: str) -> list[str]:
        return self._get(self._txt, "TXT", name)

    def a(self, name: str) -> list[str]:
        return self._get(self._a, "A", name)

    def aaaa(self, name: str) -> list[str]:
        return self._get(self._aaaa, "AAAA", name)

    def mx(self, name: str) -> list[str]:
        return [_norm(h) for h in self._get(self._mx, "MX", name)]

    def ptr(self, ip: str) -> list[str]:
        self.queries.append(("PTR", ip))
        return [_norm(h) for h in self._ptr.get(ip, [])]


# --------------------------------------------------------------------------------------
# Result type
# --------------------------------------------------------------------------------------
@dataclass
class SPFResult:
    result: str  # pass / fail / softfail / neutral / none / temperror / permerror
    domain: str  # domain whose SPF policy was evaluated first (MAIL FROM or HELO domain)
    sender: str  # identity that was checked
    client_ip: str
    explanation: str = ""
    mechanism: str | None = None  # the mechanism that matched, e.g. "ip4:192.0.2.0/24"
    record: str | None = None  # the top-level SPF record text
    dns_lookups: int = 0

    @property
    def passed(self) -> bool:
        return self.result == PASS

    def to_dict(self) -> dict[str, object]:
        return {
            "result": self.result,
            "domain": self.domain,
            "sender": self.sender,
            "client_ip": self.client_ip,
            "explanation": self.explanation,
            "mechanism": self.mechanism,
            "record": self.record,
            "dns_lookups": self.dns_lookups,
        }


class _SPFError(Exception):
    """Aborts evaluation with a final result (permerror / temperror)."""

    def __init__(self, result: str, reason: str) -> None:
        super().__init__(reason)
        self.result = result
        self.reason = reason


# --------------------------------------------------------------------------------------
# Evaluator
# --------------------------------------------------------------------------------------
_MODIFIER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9\-_.]*)=(.*)$")
_MECH_RE = re.compile(r"^([+\-~?])?([A-Za-z0-9]+)(.*)$")
_CIDR_RE = re.compile(r"(?:/(\d{1,3}))?(?://(\d{1,3}))?$")
_MACRO_RE = re.compile(r"%\{([A-Za-z])(\d*)(r?)([.\-+,/_=]*)\}|%%|%_|%-")
_BAD_PERCENT_RE = re.compile(r"%(?![{%_\-])")
_DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9_\-]{0,61}[A-Za-z0-9_])?$")


class _Evaluator:
    def __init__(
        self,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
        helo: str,
        resolver: DNSResolver,
        max_lookups: int,
        max_void_lookups: int,
    ) -> None:
        self.ip = ip
        self.helo = helo
        self.resolver = resolver
        self.max_lookups = max_lookups
        self.max_void = max_void_lookups
        self.lookups = 0
        self.voids = 0
        self.top_record: str | None = None

    # ---- bookkeeping ---------------------------------------------------------------
    def _count_lookup(self) -> None:
        self.lookups += 1
        if self.lookups > self.max_lookups:
            raise _SPFError(PERMERROR, f"too many DNS lookups (limit {self.max_lookups})")

    def _void(self, records: list) -> list:
        if not records:
            self.voids += 1
            if self.voids > self.max_void:
                raise _SPFError(PERMERROR, f"too many void DNS lookups (limit {self.max_void})")
        return records

    def _dns(self, func, name: str) -> list:  # noqa: ANN001
        try:
            return func(name)
        except DNSTemporaryError as exc:
            raise _SPFError(TEMPERROR, str(exc)) from exc

    # ---- macros ----------------------------------------------------------------------
    def expand(self, spec: str, domain: str, sender: str) -> str:
        if _BAD_PERCENT_RE.search(spec):
            raise _SPFError(PERMERROR, f"invalid macro syntax in {spec!r}")
        local, _, sender_domain = sender.rpartition("@")
        local = local or "postmaster"

        def value_of(letter: str) -> str:
            lower = letter.lower()
            if lower == "s":
                return sender
            if lower == "l":
                return local
            if lower == "o":
                return sender_domain
            if lower == "d":
                return domain
            if lower == "i":
                if isinstance(self.ip, ipaddress.IPv6Address):
                    return ".".join(self.ip.exploded.replace(":", ""))
                return str(self.ip)
            if lower == "v":
                return "ip6" if isinstance(self.ip, ipaddress.IPv6Address) else "in-addr"
            if lower == "h":
                return self.helo or "unknown"
            if lower in ("p", "r"):
                return "unknown"  # never trigger PTR lookups just to expand a macro
            raise _SPFError(PERMERROR, f"macro letter %{{{letter}}} not allowed here")

        def repl(match: re.Match[str]) -> str:
            token = match.group(0)
            if token == "%%":
                return "%"
            if token == "%_":
                return " "
            if token == "%-":
                return "%20"
            letter, digits, reverse, delims = match.groups()
            value = value_of(letter)
            if digits or reverse or delims:
                parts = re.split("[" + re.escape(delims or ".") + "]", value)
                if reverse:
                    parts.reverse()
                if digits:
                    if int(digits) == 0:
                        raise _SPFError(PERMERROR, "macro digit transformer of 0")
                    parts = parts[-int(digits) :]
                value = ".".join(parts)
            return quote(value, safe="") if letter.isupper() else value

        expanded = _MACRO_RE.sub(repl, spec)
        if "%{" in expanded:
            raise _SPFError(PERMERROR, f"invalid macro syntax in {spec!r}")
        labels = expanded.rstrip(".").split(".")
        while len(".".join(labels)) > 253 and len(labels) > 1:
            labels.pop(0)  # RFC 7208 7.3: truncate from the left
        return ".".join(labels)

    # ---- core --------------------------------------------------------------------------
    def check_host(self, domain: str, sender: str, depth: int = 0) -> tuple[str, str | None]:
        """Returns ``(result, matched_mechanism)``. May raise :class:`_SPFError`."""
        if depth > 20:
            raise _SPFError(PERMERROR, "SPF evaluation nested too deeply")
        domain = domain.rstrip(".")
        if not self._valid_domain(domain):
            return NONE, None

        records = [
            t
            for t in self._dns(self.resolver.txt, domain)
            if re.match(r"^v=spf1(\s|$)", t, re.IGNORECASE)
        ]
        if not records:
            return NONE, None
        if len(records) > 1:
            raise _SPFError(PERMERROR, f"multiple SPF records published for {domain}")
        record = records[0]
        if depth == 0:
            self.top_record = record

        terms = record.split()[1:]
        redirect: str | None = None
        seen_modifiers: set[str] = set()
        mechanisms: list[tuple[str, str, str]] = []  # (qualifier, name, argument-with-cidr)
        for term in terms:
            mod = _MODIFIER_RE.match(term)
            if mod:
                name, value = mod.group(1).lower(), mod.group(2)
                if name in ("redirect", "exp"):
                    if name in seen_modifiers:
                        raise _SPFError(PERMERROR, f"duplicate {name}= modifier")
                    seen_modifiers.add(name)
                    if name == "redirect":
                        redirect = value
                continue  # unknown modifiers are ignored (RFC 7208 6)
            m = _MECH_RE.match(term)
            if not m or m.group(2).lower() not in (
                "all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"
            ):
                raise _SPFError(PERMERROR, f"unknown mechanism or syntax error: {term!r}")
            mechanisms.append((m.group(1) or "+", m.group(2).lower(), m.group(3)))

        for qualifier, name, argument in mechanisms:
            matched = self._eval_mechanism(name, argument, domain, sender, depth)
            if matched:
                label = f"{qualifier if qualifier != '+' else ''}{name}{argument}"
                return _QUALIFIER_RESULT[qualifier], matched if matched != name else label
        if redirect is not None:
            self._count_lookup()
            target = self.expand(redirect, domain, sender)
            if not target:
                raise _SPFError(PERMERROR, "empty redirect target")
            result, mech = self.check_host(target, sender, depth + 1)
            if result == NONE:
                raise _SPFError(PERMERROR, f"redirect target {target} has no SPF record")
            return result, mech
        return NEUTRAL, None

    @staticmethod
    def _valid_domain(domain: str) -> bool:
        if not domain or "." not in domain or len(domain) > 253:
            return False
        return all(_DOMAIN_LABEL_RE.match(label) for label in domain.split("."))

    # ---- mechanisms --------------------------------------------------------------------
    def _split_cidr(self, argument: str) -> tuple[str, int | None, int | None]:
        """``':spec/24//64'`` -> ``(spec, 24, 64)`` (spec may be empty)."""
        if argument.startswith(":"):
            argument = argument[1:]
        elif argument and not argument.startswith("/"):
            raise _SPFError(PERMERROR, f"malformed mechanism argument {argument!r}")
        m = _CIDR_RE.search(argument)
        assert m is not None
        spec = argument[: m.start()]
        v4 = int(m.group(1)) if m.group(1) is not None else None
        v6 = int(m.group(2)) if m.group(2) is not None else None
        if (v4 is not None and v4 > 32) or (v6 is not None and v6 > 128):
            raise _SPFError(PERMERROR, "CIDR prefix length out of range")
        return spec, v4, v6

    def _network_contains(self, address: str, v4: int | None, v6: int | None) -> bool:
        try:
            addr = ipaddress.ip_address(address)
        except ValueError:
            return False
        if addr.version != self.ip.version:
            return False
        prefix = (v4 if v4 is not None else 32) if addr.version == 4 else (
            v6 if v6 is not None else 128
        )
        return self.ip in ipaddress.ip_network(f"{addr}/{prefix}", strict=False)

    def _addresses(self, name: str) -> list[str]:
        func = self.resolver.aaaa if self.ip.version == 6 else self.resolver.a
        return self._void(self._dns(func, name))

    def _eval_mechanism(
        self, name: str, argument: str, domain: str, sender: str, depth: int
    ) -> str | None:
        """Return a description of the match, or ``None`` if the mechanism does not match."""
        if name == "all":
            if argument:
                raise _SPFError(PERMERROR, "'all' takes no argument")
            return "all"

        if name in ("ip4", "ip6"):
            if not argument.startswith(":"):
                raise _SPFError(PERMERROR, f"{name} requires an address")
            try:
                net = ipaddress.ip_network(argument[1:], strict=False)
            except ValueError as exc:
                raise _SPFError(PERMERROR, f"invalid {name} argument {argument[1:]!r}") from exc
            if (name == "ip4") != (net.version == 4):
                raise _SPFError(PERMERROR, f"{name} given a version-{net.version} address")
            if net.version == self.ip.version and self.ip in net:
                return f"{name}{argument}"
            return None

        if name == "include":
            spec = argument[1:] if argument.startswith(":") else ""
            if not spec:
                raise _SPFError(PERMERROR, "include requires a domain")
            self._count_lookup()
            target = self.expand(spec, domain, sender)
            result, mech = self.check_host(target, sender, depth + 1)
            if result == PASS:
                return f"include:{target}" + (f" ({mech})" if mech else "")
            if result in (FAIL, SOFTFAIL, NEUTRAL):
                return None
            if result == TEMPERROR:
                raise _SPFError(TEMPERROR, f"include:{target} temporary error")
            raise _SPFError(PERMERROR, f"include:{target} returned {result}")

        if name == "exists":
            spec = argument[1:] if argument.startswith(":") else ""
            if not spec:
                raise _SPFError(PERMERROR, "exists requires a domain")
            self._count_lookup()
            target = self.expand(spec, domain, sender)
            hits = self._void(self._dns(self.resolver.a, target))
            return f"exists:{spec}" if hits else None

        if name == "a":
            spec, v4, v6 = self._split_cidr(argument)
            self._count_lookup()
            target = self.expand(spec, domain, sender) if spec else domain
            for address in self._addresses(target):
                if self._network_contains(address, v4, v6):
                    return f"a:{target}"
            return None

        if name == "mx":
            spec, v4, v6 = self._split_cidr(argument)
            self._count_lookup()
            target = self.expand(spec, domain, sender) if spec else domain
            hosts = self._void(self._dns(self.resolver.mx, target))
            if len(hosts) > 10:
                raise _SPFError(PERMERROR, "more than 10 MX records")
            for host in hosts:
                func = self.resolver.aaaa if self.ip.version == 6 else self.resolver.a
                for address in self._dns(func, host):
                    if self._network_contains(address, v4, v6):
                        return f"mx:{target}"
            return None

        if name == "ptr":  # discouraged by RFC 7208 5.5, but still supported
            spec = argument[1:] if argument.startswith(":") else ""
            self._count_lookup()
            target = (self.expand(spec, domain, sender) if spec else domain).lower()
            validated = []
            for host in self._dns(self.resolver.ptr, str(self.ip))[:10]:
                forward = self._dns(
                    self.resolver.aaaa if self.ip.version == 6 else self.resolver.a, host
                )
                if any(self._network_contains(f, None, None) for f in forward):
                    validated.append(host.lower())
            if any(h == target or h.endswith("." + target) for h in validated):
                return f"ptr:{target}"
            return None

        raise _SPFError(PERMERROR, f"unsupported mechanism {name!r}")  # pragma: no cover


# --------------------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------------------
def check_spf(
    client_ip: str,
    mail_from: str | None,
    helo: str = "",
    resolver: DNSResolver | None = None,
    *,
    max_lookups: int = 10,
    max_void_lookups: int = 2,
) -> SPFResult:
    """Evaluate SPF for a message received from *client_ip*.

    Args:
        client_ip: IP address of the SMTP client that delivered the message (taken from the
            socket, **not** from any header).
        mail_from: the envelope sender (``MAIL FROM``). For bounces (empty / ``<>``) the
            identity ``postmaster@<helo>`` is checked, as RFC 7208 section 2.4 requires.
        helo: the HELO/EHLO name given by the client.
        resolver: DNS backend; defaults to :class:`DnsPythonResolver`.
    """
    ip_text = (client_ip or "").strip()
    sender = (mail_from or "").strip().strip("<>").strip()
    helo = (helo or "").strip().rstrip(".")

    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return SPFResult(PERMERROR, "", sender, ip_text, f"invalid client IP {ip_text!r}")
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:1.2.3.4 is evaluated as IPv4

    if not sender:
        sender = f"postmaster@{helo}" if helo else ""
    elif "@" not in sender:
        sender = f"postmaster@{sender}"  # RFC 7208 4.3: missing local-part -> "postmaster"
    elif sender.startswith("@"):
        sender = f"postmaster{sender}"
    domain = sender.rpartition("@")[2].lower()

    if not domain:
        return SPFResult(NONE, "", sender, str(ip), "no sender or HELO domain to check")

    evaluator = _Evaluator(ip, helo, resolver or DnsPythonResolver(), max_lookups, max_void_lookups)
    try:
        result, mechanism = evaluator.check_host(domain, sender)
        reason = _explain(result, str(ip), domain, mechanism)
    except _SPFError as err:
        result, mechanism, reason = err.result, None, err.reason
    return SPFResult(
        result=result,
        domain=domain,
        sender=sender,
        client_ip=str(ip),
        explanation=reason,
        mechanism=mechanism,
        record=evaluator.top_record,
        dns_lookups=evaluator.lookups,
    )


def _explain(result: str, ip: str, domain: str, mechanism: str | None) -> str:
    if result == NONE:
        return f"{domain} publishes no SPF record"
    if mechanism:
        return f"{ip} matched '{mechanism}' in the SPF policy of {domain} -> {result}"
    return f"{ip} matched no mechanism in the SPF policy of {domain} -> {result}"
