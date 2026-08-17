from __future__ import annotations

from typing import Any
from urllib.parse import quote

from packageurl import PackageURL


class IdentityError(ValueError):
    """Raised when a component identifier cannot be represented safely."""


def _encode(value: str) -> str:
    """Apply the ECMA-427 component allowed set (colon is always unescaped)."""
    return quote(str(value), safe=".-_~:")


def _serialize(package: PackageURL) -> str:
    path = package.type.lower()
    if package.namespace:
        path += "/" + "/".join(_encode(segment) for segment in package.namespace.split("/"))
    path += "/" + _encode(package.name)
    if package.version:
        path += "@" + _encode(package.version)
    qualifiers = package.qualifiers or {}
    encoded_qualifiers = [
        f"{key.lower()}={_encode(value)}"
        for key, value in sorted(qualifiers.items())
        if value not in (None, "")
    ]
    if encoded_qualifiers:
        path += "?" + "&".join(encoded_qualifiers)
    if package.subpath:
        path += "#" + "/".join(_encode(segment) for segment in package.subpath.split("/"))
    return "pkg:" + path


def canonicalize_purl(value: str) -> str:
    """Parse/type-normalize with packageurl-python and serialize per ECMA-427."""
    raw = (value or "").strip()
    if not raw:
        raise IdentityError("Package URL must not be empty")
    try:
        return _serialize(PackageURL.from_string(raw))
    except ValueError as exc:
        raise IdentityError(f"Invalid Package URL {raw!r}: {exc}") from exc


def infer_ecosystem(purl: str | None, group: str | None = None) -> str:
    if purl:
        try:
            return PackageURL.from_string(purl.strip()).type
        except ValueError as exc:
            raise IdentityError(f"Invalid Package URL {purl!r}: {exc}") from exc
    if group and group.count(".") >= 1:
        return "maven"
    return "generic"


def _from_parts(name: str, version: str, ecosystem: str) -> PackageURL:
    package_type = (ecosystem or "generic").strip().lower()
    package_name = (name or "unknown").strip()
    namespace = None
    if package_type == "npm" and package_name.startswith("@") and "/" in package_name:
        namespace, package_name = package_name.split("/", 1)
    try:
        return PackageURL(
            type=package_type,
            namespace=namespace,
            name=package_name,
            version=(version or None),
        )
    except ValueError as exc:
        raise IdentityError(
            f"Cannot construct a {package_type!r} Package URL for {name!r}@{version!r}: {exc}"
        ) from exc


def canonical_component(
    name: str,
    version: str = "",
    purl: str = "",
    ecosystem: str = "",
) -> str:
    """Return an ECMA-427/type-definition-aware component identity.

    Supplied PURLs are never whole-string lowercased. When a source has no
    PURL, the official implementation applies the registered type's rules to
    the available package name and version. Unknown inputs remain `generic`,
    whose name, namespace, and version are case-sensitive.
    """
    if purl:
        return canonicalize_purl(purl)
    return _serialize(_from_parts(name, version, ecosystem or "generic"))


def canonical_reference(value: str) -> str:
    """Canonicalize PURL references while preserving opaque source IDs."""
    raw = str(value or "").strip()
    return canonicalize_purl(raw) if raw.lower().startswith("pkg:") else raw


def register_component(
    components: dict[str, dict[str, Any]],
    key: str,
    metadata: dict[str, Any],
) -> None:
    """Register a component without erasing original identifiers.

    A canonical identity may legitimately have multiple spellings (for
    example, PyPI's `_`/`-` normalization). Those aliases are retained. An
    opaque non-PURL key is never allowed to collapse distinct name/version
    pairs because there is no standard equivalence rule supporting that merge.
    """
    incoming = dict(metadata)
    aliases = set(incoming.get("identity_aliases", [])) | {
        str(value)
        for value in (
            incoming.get("purl"),
            incoming.get("source_ref"),
            incoming.get("name"),
        )
        if value not in (None, "")
    }
    existing = components.get(key)
    if existing is None:
        incoming["canonical_purl"] = key if key.startswith("pkg:") else ""
        incoming["identity_aliases"] = sorted(aliases)
        components[key] = incoming
        return

    if not key.startswith("pkg:"):
        before = (existing.get("name"), existing.get("version"))
        after = (incoming.get("name"), incoming.get("version"))
        if before != after:
            raise IdentityError(
                f"Ambiguous opaque component identity {key!r} refers to both {before!r} and {after!r}"
            )

    merged_aliases = set(existing.get("identity_aliases", [])) | aliases
    existing["identity_aliases"] = sorted(merged_aliases)
    existing.setdefault("canonical_purl", key if key.startswith("pkg:") else "")
