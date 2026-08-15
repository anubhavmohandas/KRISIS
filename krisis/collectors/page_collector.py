"""
Page / redirect collector — observes what a URL actually *does*: where it
redirects, and whether the page it lands on collects credentials while
claiming to be an organization its own domain doesn't match.

This is evidence collection, not verdict-making, same as every other
collector: a login form is not inherently malicious, a redirect is not
inherently malicious, a page whose title doesn't match its domain is not
inherently malicious (blogs, hosted docs, and news sites do this constantly).
Each becomes one Evidence item; correlation/risk decide what the combination
means (see krisis/core/risk.py's interaction bonus for the credential-form +
brand-impersonation case).

Safety properties, all enforced on every redirect hop, not just the first:
  - only http(s) schemes are ever requested (manual redirect walking bypasses
    requests' own scheme dispatch, so this has to be re-checked by hand)
  - the resolved host must not be a private/loopback/link-local/reserved
    address (SSRF guard)
  - a hard redirect-depth cap and loop detection
  - a connect+read timeout per hop
  - a response-size cap, enforced while streaming (never buffer an unbounded body)

Any failure anywhere in this chain returns CollectorResult(available=False,
note=...) — never silently "clean". See PageCollector.collect().
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

from ..core.identity import label_similarity
from ..core.indicators import registrable_domain, same_organization
from ..core.models import Entity, Evidence, Independence, Polarity
from ..core.url_intent import classify as classify_url_intent
from .base import CollectorResult, EvidenceCollector

CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 3.0
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 512 * 1024   # plenty for title/meta/forms; not a page mirror
ALLOWED_SCHEMES = ("http", "https")
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

# How similar a page's claimed name must be to its own domain's name before
# KRISIS stops calling it a mismatch. Below this, the page is naming an
# organization its domain does not resemble at all.
BRAND_MISMATCH_THRESHOLD = 0.45

# Page chrome that isn't a claimed organization name ("Login", "404", ...).
# Generic vocabulary about *page structure*, not a brand list.
_GENERIC_PAGE_WORDS = frozenset({
    "login", "log in", "sign in", "signin", "home", "welcome", "dashboard",
    "account", "portal", "page not found", "404", "error", "untitled",
    "please wait", "loading",
})

_PAYMENT_FIELD_HINTS = ("card", "cc-number", "ccnumber", "cvv", "cvc", "cardnumber")
_CRED_FIELD_HINTS = ("user", "email", "login", "username")
_TITLE_SPLIT_RE = re.compile(r"\s*[-|:]{1,2}\s*|\s*—\s*")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]")


class _SSRFError(Exception):
    pass


class _SchemeError(Exception):
    pass


def _is_safe_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def _resolve_and_check(host: str) -> None:
    """Raise _SSRFError if `host` resolves to any non-public address.

    occam: resolve-then-connect, checked separately from the request `requests`
    itself makes a moment later — a DNS answer could in principle change
    between this check and that connection (rebinding). Full protection needs
    pinning the validated IP into the connection via a custom transport
    adapter; add that if this is ever exposed to a threat model beyond "an
    operator investigates an attacker-supplied URL with their own CLI."
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise _SSRFError(f"host does not resolve: {exc}") from exc
    for info in infos:
        addr = info[4][0]
        if not _is_safe_ip(addr):
            raise _SSRFError(f"host resolves to a non-public address ({addr})")


def _check_hop(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise _SchemeError(f"unsupported scheme '{parsed.scheme}'")
    if not parsed.hostname:
        raise _SchemeError("no host in URL")
    _resolve_and_check(parsed.hostname)


@dataclass
class _Hop:
    url: str
    status: Optional[int] = None


@dataclass
class FetchResult:
    hops: list[_Hop] = field(default_factory=list)
    final_url: str = ""
    status: Optional[int] = None
    body: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and self.status is not None


def safe_fetch(start_url: str) -> FetchResult:
    """Manually follow redirects with a safety check on every hop.

    Deliberately does not use requests' allow_redirects=True: that would hide
    the chain (host/scheme changes, hop count) that is itself the evidence.
    """
    result = FetchResult()
    seen: set[str] = set()
    url = start_url

    for _ in range(MAX_REDIRECTS + 1):
        if url in seen:
            result.error = f"redirect loop detected at {url}"
            return result
        seen.add(url)

        try:
            _check_hop(url)
        except (_SSRFError, _SchemeError) as exc:
            result.error = str(exc)
            return result

        try:
            resp = requests.get(
                url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), allow_redirects=False, stream=True
            )
        except requests.RequestException as exc:
            result.error = f"request failed: {exc}"
            return result

        result.hops.append(_Hop(url=url, status=resp.status_code))

        if resp.status_code in REDIRECT_STATUSES:
            location = resp.headers.get("Location")
            resp.close()
            if not location:
                result.error = "redirect response with no Location header"
                return result
            url = urljoin(url, location)
            continue

        chunks: list[bytes] = []
        total = 0
        try:
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_BODY_BYTES:
                    break
                chunks.append(chunk)
        finally:
            resp.close()

        result.final_url = url
        result.status = resp.status_code
        result.body = b"".join(chunks).decode(resp.encoding or "utf-8", errors="ignore")
        return result

    result.error = f"exceeded max redirect depth ({MAX_REDIRECTS})"
    return result


@dataclass
class _FormState:
    action: str = ""
    method: str = "get"
    has_password: bool = False
    has_cred_field: bool = False
    has_payment_field: bool = False


class _PageParser(HTMLParser):
    """Flat SAX-style parse: title/meta/h1, plus PER-FORM field tracking.

    Forms must stay scoped to the currently-open <form> — a page can have an
    unrelated form (e.g. a newsletter signup with an external action)
    alongside a real login form, and misattributing one form's fields to
    another would manufacture exactly the credential_form + external action
    combination the risk engine treats as strong evidence.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.site_name = ""
        self.h1 = ""
        self.forms: list[_FormState] = []
        self._current_form: Optional[_FormState] = None
        self._in_title = False
        self._in_h1 = False
        self._h1_seen = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attrs_d = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "h1" and not self._h1_seen:
            self._in_h1 = True
        elif tag == "meta":
            prop = attrs_d.get("property", "").lower() or attrs_d.get("name", "").lower()
            if prop == "og:site_name":
                self.site_name = attrs_d.get("content", "").strip()
        elif tag == "form":
            self._current_form = _FormState(
                action=attrs_d.get("action", ""), method=attrs_d.get("method", "get").lower()
            )
            self.forms.append(self._current_form)
        elif tag in ("input", "button") and self._current_form is not None:
            itype = attrs_d.get("type", "text").lower()
            name = attrs_d.get("name", "").lower()
            if itype == "password":
                self._current_form.has_password = True
            elif itype in ("email", "text") and any(h in name for h in _CRED_FIELD_HINTS):
                self._current_form.has_cred_field = True
            if any(h in name for h in _PAYMENT_FIELD_HINTS):
                self._current_form.has_payment_field = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "h1":
            self._in_h1 = False
            self._h1_seen = True
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        elif self._in_h1:
            self.h1 += data


def _claimed_org_name(parsed: _PageParser) -> str:
    """Best-effort org/site name the page claims for itself, strongest source
    first. "" means nothing usable was found — never guessed."""
    if parsed.site_name.strip():
        return parsed.site_name.strip()

    title = parsed.title.strip()
    if title:
        segments = [s.strip() for s in _TITLE_SPLIT_RE.split(title) if s.strip()]
        candidates = [s for s in segments if s.lower() not in _GENERIC_PAGE_WORDS and len(s) >= 3]
        if candidates:
            return candidates[-1]

    h1 = parsed.h1.strip()
    if h1 and h1.lower() not in _GENERIC_PAGE_WORDS and len(h1) >= 3:
        return h1
    return ""


def _normalized_label(name: str) -> str:
    return _NON_ALNUM_RE.sub("", name.lower())


class PageCollector(EvidenceCollector):
    name = "page"
    supports = ("url",)

    def collect(self, entity: Entity) -> CollectorResult:
        try:
            result = safe_fetch(entity.value)
        except Exception as exc:
            return CollectorResult(evidence=[], available=False, note=f"page fetch failed: {exc}")

        if result.error:
            return CollectorResult(evidence=[], available=False, note=result.error)

        evidence: list[Evidence] = []
        seed_host = urlparse(entity.value).hostname or ""
        final_host = urlparse(result.final_url).hostname or seed_host

        evidence.extend(self._redirect_evidence(entity, result, seed_host, final_host))
        evidence.extend(self._intent_evidence(entity, result.final_url or entity.value))

        parser = _PageParser()
        try:
            parser.feed(result.body)
        except Exception:
            pass  # HTMLParser is lenient by design; guard anyway — never raise out of collect()

        cred_forms = [f for f in parser.forms if f.has_password or f.has_payment_field]
        evidence.extend(self._credential_evidence(entity, cred_forms, result.final_url, final_host))
        evidence.extend(
            self._brand_mismatch_evidence(entity, parser, final_host, has_credential_form=bool(cred_forms))
        )

        return CollectorResult(evidence=evidence, available=True)

    # -- internals ---------------------------------------------------------

    def _redirect_evidence(
        self, entity: Entity, result: FetchResult, seed_host: str, final_host: str
    ) -> list[Evidence]:
        if len(result.hops) <= 1:
            return []
        chain = [h.url for h in result.hops]
        if result.final_url and result.final_url not in chain:
            chain.append(result.final_url)

        items = [
            Evidence(
                source=self.name, entity_id=entity.id, signal="redirect_chain",
                value=chain, evidence_type="behavior", polarity=Polarity.NEUTRAL,
                confidence=0.7, independence=Independence.INDEPENDENT,
                provenance=(
                    f"{len(result.hops)} redirect hop(s) observed from {entity.value} "
                    f"to {result.final_url}"
                ),
            ),
            # Feeds pivot_engine.PIVOT_RULES["redirect_target"], defined but
            # unused until now.
            Evidence(
                source=self.name, entity_id=entity.id, signal="redirect_target",
                value=result.final_url, evidence_type="behavior", polarity=Polarity.NEUTRAL,
                confidence=0.6, independence=Independence.INDEPENDENT,
                provenance=f"final redirect destination of {entity.value}",
            ),
        ]
        if seed_host and final_host and not same_organization(seed_host, final_host):
            items.append(Evidence(
                source=self.name, entity_id=entity.id, signal="cross_domain_redirect",
                value=final_host, evidence_type="behavior", polarity=Polarity.SUPPORTS_THREAT,
                confidence=0.55, independence=Independence.INDEPENDENT,
                provenance=(
                    f"redirect chain leaves {seed_host} and lands on a different "
                    f"organization's domain, {final_host}"
                ),
            ))
        return items

    def _intent_evidence(self, entity: Entity, url: str) -> list[Evidence]:
        intents = classify_url_intent(url)
        return [
            Evidence(
                source=self.name, entity_id=entity.id, signal=category,
                value=tokens, evidence_type="behavior", polarity=Polarity.NEUTRAL,
                confidence=0.4, independence=Independence.DERIVED,
                provenance=f"URL path/query contains {category} token(s): {', '.join(tokens)}",
            )
            for category, tokens in intents.items()
        ]

    def _credential_evidence(
        self, entity: Entity, cred_forms: list[_FormState], final_url: str, final_host: str
    ) -> list[Evidence]:
        if not cred_forms:
            return []
        items = [Evidence(
            source=self.name, entity_id=entity.id, signal="credential_form",
            value={
                "password": any(f.has_password for f in cred_forms),
                "payment": any(f.has_payment_field for f in cred_forms),
            },
            evidence_type="behavior", polarity=Polarity.SUPPORTS_THREAT, confidence=0.5,
            independence=Independence.INDEPENDENT,
            provenance="page contains a form requesting a password and/or payment field",
        )]

        external_reasons: list[str] = []
        for f in cred_forms:
            if not f.action:
                continue
            action_host = urlparse(urljoin(final_url, f.action)).hostname
            if action_host and final_host and not same_organization(action_host, final_host):
                external_reasons.append(f"form action points to {action_host}")
        if external_reasons:
            items.append(Evidence(
                source=self.name, entity_id=entity.id, signal="external_form_action",
                value=external_reasons, evidence_type="behavior", polarity=Polarity.SUPPORTS_THREAT,
                confidence=0.6, independence=Independence.INDEPENDENT,
                provenance="; ".join(external_reasons),
            ))
        return items

    def _brand_mismatch_evidence(
        self, entity: Entity, parser: _PageParser, final_host: str, has_credential_form: bool
    ) -> list[Evidence]:
        claimed = _claimed_org_name(parser)
        if not claimed:
            return []
        domain_label = registrable_domain(final_host).partition(".")[0]
        claimed_label = _normalized_label(claimed)
        if not claimed_label or not domain_label:
            return []

        similarity = label_similarity(claimed_label, domain_label)
        if similarity >= BRAND_MISMATCH_THRESHOLD:
            return []

        # Gated on co-occurring credential collection, not on emission: this is
        # always reported (everything is evidence), but a page whose title
        # merely doesn't match its domain — true of countless ordinary sites —
        # stays neutral. It only supports the threat hypothesis combined with
        # an actual credential-collecting form, which is the corequisite the
        # risk engine's interaction bonus (risk.py) also keys on.
        return [Evidence(
            source=self.name, entity_id=entity.id, signal="brand_domain_mismatch",
            value=claimed, evidence_type="behavior",
            polarity=Polarity.SUPPORTS_THREAT if has_credential_form else Polarity.NEUTRAL,
            confidence=0.55 if has_credential_form else 0.3,
            independence=Independence.DERIVED,
            provenance=(
                f"page identifies itself as '{claimed}', which does not resemble this "
                f"domain's own name ('{domain_label}')"
                + (" and the page also collects credentials" if has_credential_form else "")
            ),
        )]
