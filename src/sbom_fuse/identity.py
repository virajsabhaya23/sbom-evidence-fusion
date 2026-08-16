from __future__ import annotations
import re
from urllib.parse import quote


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def infer_ecosystem(purl: str | None, group: str | None = None) -> str:
    if purl and purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0].split("@", 1)[0].lower()
    if group and group.count(".") >= 1:
        return "maven"
    return "generic"


def canonical_component(name: str, version: str = "", purl: str = "", ecosystem: str = "") -> str:
    if purl:
        return purl.strip().lower()
    eco = ecosystem or infer_ecosystem(purl)
    return f"pkg:{eco}/{quote(normalize_name(name), safe='@/')}{('@' + version) if version else ''}".lower()
