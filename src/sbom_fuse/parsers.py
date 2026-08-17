from __future__ import annotations
import json
import pathlib
import re
from typing import Any
from urllib.parse import quote
from .identity import (
    canonical_component,
    canonical_reference,
    infer_ecosystem,
    register_component,
)
from .model import SourceGraph


def _load(path: pathlib.Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_cyclonedx(path: pathlib.Path, source_id: str) -> SourceGraph:
    data = _load(path)
    graph = SourceGraph(source_id=source_id, source_type="cyclonedx", metadata={"path": str(path)})
    ref_to_key: dict[str, str] = {}
    for comp in data.get("components", []):
        ref = comp.get("bom-ref") or comp.get("purl") or f"{comp.get('name','')}@{comp.get('version','')}"
        key = canonical_component(comp.get("name", "unknown"), comp.get("version", ""), comp.get("purl", ""), infer_ecosystem(comp.get("purl")))
        ref_to_key[ref] = key
        register_component(graph.components, key, {"name": comp.get("name", ""), "version": comp.get("version", ""), "purl": comp.get("purl", ""), "source_ref": ref})
    root_ref = (data.get("metadata") or {}).get("component", {}).get("bom-ref")
    if root_ref and root_ref in ref_to_key:
        graph.roots.add(ref_to_key[root_ref])
    for dep in data.get("dependencies", []):
        raw_parent = dep.get("ref")
        parent = ref_to_key.get(raw_parent, canonical_reference(raw_parent))
        if not parent:
            continue
        if parent not in graph.components:
            register_component(graph.components, parent, {"name": parent, "version": "", "purl": parent if str(parent).startswith("pkg:") else ""})
        for child_ref in dep.get("dependsOn", []) or []:
            child = ref_to_key.get(child_ref, canonical_reference(child_ref))
            if child:
                if child not in graph.components:
                    register_component(graph.components, child, {"name": child, "version": "", "purl": child if str(child).startswith("pkg:") else ""})
                graph.edges.add((parent, child))
    return graph


def parse_spdx(path: pathlib.Path, source_id: str) -> SourceGraph:
    data = _load(path)
    graph = SourceGraph(source_id=source_id, source_type="spdx", metadata={"path": str(path)})
    id_to_key: dict[str, str] = {}
    for pkg in data.get("packages", []):
        purl = ""
        for ext in pkg.get("externalRefs", []) or []:
            if str(ext.get("referenceType", "")).lower().endswith("purl"):
                purl = ext.get("referenceLocator", "")
                break
        key = canonical_component(pkg.get("name", "unknown"), pkg.get("versionInfo", ""), purl)
        sid = pkg.get("SPDXID") or key
        id_to_key[sid] = key
        register_component(graph.components, key, {"name": pkg.get("name", ""), "version": pkg.get("versionInfo", ""), "purl": purl, "source_ref": sid})
    for rel in data.get("relationships", []) or []:
        kind = str(rel.get("relationshipType", "")).upper()
        if kind in {"DEPENDS_ON", "DEPENDENCY_OF"}:
            a = id_to_key.get(rel.get("spdxElementId"), rel.get("spdxElementId"))
            b = id_to_key.get(rel.get("relatedSpdxElement"), rel.get("relatedSpdxElement"))
            if not a or not b:
                continue
            parent, child = (a, b) if kind == "DEPENDS_ON" else (b, a)
            graph.edges.add((parent, child))
    return graph


def parse_package_lock(path: pathlib.Path, source_id: str) -> SourceGraph:
    data = _load(path)
    graph = SourceGraph(source_id=source_id, source_type="npm-lock", metadata={"path": str(path)})
    packages = data.get("packages", {})
    path_to_key: dict[str, str] = {}
    for pkg_path, meta in packages.items():
        if pkg_path == "":
            name = meta.get("name") or data.get("name", "root")
            version = meta.get("version") or data.get("version", "")
        else:
            name = pkg_path.rsplit("node_modules/", 1)[-1]
            version = meta.get("version", "")
        key = canonical_component(name, version, ecosystem="npm")
        path_to_key[pkg_path] = key
        register_component(graph.components, key, {"name": name, "version": version, "purl": key})
    if "" in path_to_key:
        graph.roots.add(path_to_key[""])
    for pkg_path, meta in packages.items():
        parent = path_to_key.get(pkg_path)
        if not parent:
            continue
        for dep_name in (meta.get("dependencies") or {}):
            candidates = []
            cur = pkg_path
            while True:
                prefix = f"{cur}/node_modules/{dep_name}" if cur else f"node_modules/{dep_name}"
                candidates.append(prefix)
                if not cur:
                    break
                if "/node_modules/" in cur:
                    cur = cur.rsplit("/node_modules/", 1)[0]
                else:
                    cur = ""
            child_path = next((x for x in candidates if x in path_to_key), None)
            if child_path:
                graph.edges.add((parent, path_to_key[child_path]))
    return graph



def parse_pip_inspect(path: pathlib.Path, source_id: str) -> SourceGraph:
    data = _load(path)
    graph = SourceGraph(source_id=source_id, source_type="pip-resolution", metadata={"path": str(path)})
    installed = data.get("installed", [])
    name_to_key = {}
    for item in installed:
        meta = item.get("metadata") or {}
        name = meta.get("name", "unknown")
        version = meta.get("version", "")
        key = canonical_component(name, version, ecosystem="pypi")
        name_to_key[name.lower()] = key
        register_component(graph.components, key, {"name": name, "version": version, "purl": key})
    for item in installed:
        meta = item.get("metadata") or {}
        parent = name_to_key.get(str(meta.get("name", "")).lower())
        if not parent:
            continue
        for req in meta.get("requires_dist") or []:
            dep_name = re.split(r"[ ;(<>=!~\[]", str(req), maxsplit=1)[0].strip().lower()
            child = name_to_key.get(dep_name)
            if child:
                graph.edges.add((parent, child))
    return graph


def parse_node_tree(path: pathlib.Path, source_id: str, source_type: str) -> SourceGraph:
    data = _load(path)
    graph = SourceGraph(source_id=source_id, source_type=source_type, metadata={"path": str(path)})
    roots = data if isinstance(data, list) else [data]
    def walk(node, parent=None):
        if not isinstance(node, dict):
            return
        name = node.get("name") or node.get("package") or "unknown"
        version = node.get("version") or ""
        key = canonical_component(name, version, ecosystem="npm")
        register_component(graph.components, key, {"name": name, "version": version, "purl": key})
        if parent:
            graph.edges.add((parent, key))
        else:
            graph.roots.add(key)
        deps = node.get("dependencies") or node.get("children") or {}
        if isinstance(deps, dict):
            children = []
            for dep_name, dep_meta in deps.items():
                if isinstance(dep_meta, dict):
                    child = {**dep_meta}
                    child.setdefault("name", dep_name)
                    children.append(child)
        elif isinstance(deps, list):
            children = deps
        else:
            children = []
        for child in children:
            walk(child, key)
    for root in roots:
        walk(root)
    return graph


def parse_poetry_lock(path: pathlib.Path, source_id: str) -> SourceGraph:
    text = path.read_text(encoding="utf-8")
    graph = SourceGraph(source_id=source_id, source_type="poetry-lock", metadata={"path": str(path)})
    blocks = re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]
    entries = []
    for block in blocks:
        name_m = re.search(r'(?m)^name\s*=\s*"([^"]+)"', block)
        ver_m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', block)
        if not name_m:
            continue
        name = name_m.group(1); version = ver_m.group(1) if ver_m else ""
        deps = []
        dep_sec = re.search(r'(?ms)^\[package.dependencies\]\s*(.*?)(?=^\[|\Z)', block)
        if dep_sec:
            for line in dep_sec.group(1).splitlines():
                m = re.match(r'\s*([A-Za-z0-9_.-]+)\s*=', line)
                if m: deps.append(m.group(1))
        entries.append((name, version, deps))
    name_to_key = {}
    for name, version, _ in entries:
        key = canonical_component(name, version, ecosystem="pypi")
        name_to_key[name.lower()] = key
        register_component(graph.components, key, {"name": name, "version": version, "purl": key})
    for name, _, deps in entries:
        parent = name_to_key[name.lower()]
        for dep in deps:
            child = name_to_key.get(dep.lower())
            if child: graph.edges.add((parent, child))
    return graph


MAVEN_SCOPES = {"compile", "provided", "runtime", "test", "system", "import"}


def _maven_key(group: str, artifact: str, version: str, packaging: str = "jar", classifier: str = "") -> str:
    qualifiers = []
    if classifier:
        qualifiers.append("classifier=" + quote(classifier, safe=""))
    if packaging and packaging != "jar":
        qualifiers.append("type=" + quote(packaging, safe=""))
    raw = f"pkg:maven/{quote(group, safe='.')}/{quote(artifact, safe='.-_~')}@{quote(version, safe='.-_~')}"
    if qualifiers:
        raw += "?" + "&".join(sorted(qualifiers))
    return canonical_component(artifact, version, raw)


def _register_maven_edge(graph: SourceGraph, parent: str, child: str, relationship: dict[str, Any]) -> None:
    graph.edges.add((parent, child))
    graph.edge_metadata.setdefault((parent, child), []).append(relationship)


def _parse_maven_json(data: dict[str, Any], graph: SourceGraph) -> None:
    def visit(node: dict[str, Any], parent: str | None = None, depth: int = 0) -> None:
        group = str(node.get("groupId", ""))
        artifact = str(node.get("artifactId", ""))
        version = str(node.get("version", ""))
        if not group or not artifact or not version:
            raise ValueError("Maven dependency-tree JSON node requires groupId, artifactId, and version")
        packaging = str(node.get("type") or "jar")
        classifier = str(node.get("classifier") or "")
        scope = str(node.get("scope") or ("compile" if depth else "")).lower()
        optional = str(node.get("optional", "false")).lower() == "true"
        key = _maven_key(group, artifact, version, packaging, classifier)
        register_component(graph.components, key, {"name": artifact, "version": version, "purl": key, "group": group, "classifier": classifier, "packaging": packaging})
        if parent is None:
            graph.roots.add(key)
        else:
            _register_maven_edge(graph, parent, key, {"scope": scope, "optional": optional, "classifier": classifier, "type": packaging, "depth": depth})
        for child in node.get("children") or []:
            visit(child, key, depth + 1)
    visit(data)


def _parse_maven_coordinate(token: str) -> tuple[str, str, str, str, str, str]:
    parts = token.split(":")
    if len(parts) < 4:
        raise ValueError(f"Invalid Maven coordinate {token!r}")
    group, artifact, packaging = parts[:3]
    classifier = ""
    scope = ""
    if len(parts) == 4:
        version = parts[3]
    elif len(parts) == 5 and parts[-1].lower() in MAVEN_SCOPES:
        version, scope = parts[3], parts[4].lower()
    elif len(parts) == 5:
        classifier, version = parts[3], parts[4]
    else:
        classifier, version, scope = parts[3], parts[4], parts[5].lower()
    return group, artifact, packaging, classifier, version, scope


def parse_maven_tree(path: pathlib.Path, source_id: str) -> SourceGraph:
    graph = SourceGraph(source_id=source_id, source_type="maven-resolution", metadata={"path": str(path)})
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict) and {"groupId", "artifactId", "version"} <= data.keys():
        graph.metadata["maven_format"] = "dependency-tree-json"
        _parse_maven_json(data, graph)
        return graph

    graph.metadata["maven_format"] = "dependency-tree-text"
    stack = {}
    for raw in text.splitlines():
        line = re.sub(r"^\[INFO\]\s*", "", raw)
        m = re.match(r"((?:[| ]{3})*)([+\\]- )?([^ ]+)", line)
        if not m: continue
        depth = len(m.group(1)) // 3 + (1 if m.group(2) else 0)
        try:
            group, artifact, packaging, classifier, version, scope = _parse_maven_coordinate(m.group(3))
        except ValueError:
            continue
        optional = "(optional)" in line.lower()
        key = _maven_key(group, artifact, version, packaging, classifier)
        register_component(graph.components, key, {"name": artifact, "version": version, "purl": key, "group": group, "classifier": classifier, "packaging": packaging})
        if depth == 0: graph.roots.add(key)
        elif depth - 1 in stack: _register_maven_edge(graph, stack[depth-1], key, {"scope": scope or "compile", "optional": optional, "classifier": classifier, "type": packaging, "depth": depth})
        stack[depth] = key
        for d in list(stack):
            if d > depth: del stack[d]
    return graph


def parse_evidence_json(path: pathlib.Path, source_id: str, source_type: str = "runtime") -> SourceGraph:
    data = _load(path)
    actual_type = data.get("source_type", source_type)
    if actual_type not in {"runtime", "build-graph"}:
        raise ValueError("evidence-json source_type must be runtime or build-graph")
    graph = SourceGraph(source_id=source_id, source_type=actual_type, metadata={"path": str(path)})
    for comp in data.get("components", []):
        key = canonical_component(comp.get("name", "unknown"), comp.get("version", ""), comp.get("purl", ""), ecosystem=comp.get("ecosystem", "generic"))
        register_component(graph.components, key, {"name": comp.get("name", key), "version": comp.get("version", ""), "purl": comp.get("purl", key if key.startswith("pkg:") else "")})
    for edge in data.get("edges", []):
        parent = canonical_reference(edge.get("parent", "")); child = canonical_reference(edge.get("child", ""))
        if parent and child:
            graph.edges.add((parent, child))
            register_component(graph.components, parent, {"name": parent, "version": "", "purl": parent if parent.startswith("pkg:") else ""})
            register_component(graph.components, child, {"name": child, "version": "", "purl": child if child.startswith("pkg:") else ""})
    for root in data.get("roots", []): graph.roots.add(canonical_reference(root))
    return graph

def parse_input(path: pathlib.Path, source_id: str, forced_type: str | None = None) -> SourceGraph:
    typ = forced_type
    if not typ:
        lower = path.name.lower()
        if lower == "poetry.lock":
            typ = "poetry-lock"
        else:
            try:
                data = _load(path)
            except json.JSONDecodeError as exc:
                if "maven-tree" in lower or lower.startswith("dependency-tree"):
                    typ = "maven-tree"
                else:
                    raise ValueError(f"Unable to detect input type for {path}; use --type path=TYPE") from exc
            else:
                # Semantic JSON signatures take precedence over filenames. This
                # prevents a valid SBOM/lock file with a Maven-looking name from
                # being silently routed to the Maven text parser.
                if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
                    typ = "cyclonedx"
                elif isinstance(data, dict) and "spdxVersion" in data:
                    typ = "spdx"
                elif isinstance(data, dict) and "lockfileVersion" in data and "packages" in data:
                    typ = "npm-lock"
                elif isinstance(data, dict) and "installed" in data and "pip_version" in data:
                    typ = "pip-inspect"
                elif isinstance(data, dict) and data.get("format") == "sbom-fuse-evidence/v1":
                    typ = "evidence-json"
                elif isinstance(data, dict) and {"groupId", "artifactId", "version"} <= data.keys():
                    typ = "maven-tree"
                elif isinstance(data, (dict, list)) and (lower.startswith("pnpm") or "pnpm" in lower):
                    typ = "pnpm-tree"
                elif isinstance(data, (dict, list)) and (lower.startswith("yarn") or "yarn" in lower):
                    typ = "yarn-tree"
                else:
                    raise ValueError(f"Unable to detect input type for {path}; use --type path=TYPE")
    parsers = {
        "cyclonedx": parse_cyclonedx, "spdx": parse_spdx, "npm-lock": parse_package_lock,
        "pip-inspect": parse_pip_inspect, "pnpm-tree": lambda p,s: parse_node_tree(p,s,"pnpm-resolution"),
        "yarn-tree": lambda p,s: parse_node_tree(p,s,"yarn-resolution"),
        "poetry-lock": parse_poetry_lock, "maven-tree": parse_maven_tree,
        "evidence-json": parse_evidence_json,
    }
    if typ not in parsers:
        raise ValueError(f"Unsupported input type: {typ}")
    return parsers[typ](path, source_id)
