"""Heuristics for stripped binaries without debug symbols."""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Iterable, Optional

from app.models.artifact import FunctionArtifact

_SOURCE_EXT_RE = re.compile(r"\.(c|cc|cpp|cxx|h|hh|hpp|inl|ipp)$", re.I)
_SOURCE_PATH_RE = re.compile(
    r"((?:[A-Za-z]:)?[\\/][^\"'\r\n]*?\.(?:c|cc|cpp|cxx|h|hh|hpp|inl|ipp))",
    re.I,
)
_REL_SOURCE_PATH_RE = re.compile(
    r"((?:[A-Za-z0-9_.-]+[\\/])+[A-Za-z0-9_.-]+\.(?:c|cc|cpp|cxx|h|hh|hpp|inl|ipp))",
    re.I,
)
_STRING_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\])*)"')
_QUALIFIED_NAME_RE = re.compile(r"([A-Za-z_]\w*)::([~A-Za-z_]\w*)")
_MSVC_RTTI_RE = re.compile(r"\.\?A[VU]([A-Za-z_]\w*)@@")
_PATH_ANCHORS = ("src", "source", "sources", "lib", "libs", "app", "include")
_GENERATED_NAME_RE = re.compile(r"^(lambda|lva_t)_[0-9a-z_]{16,}$", re.I)


def dedupe_preserve(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def extract_string_literals(text: Optional[str]) -> list[str]:
    if not text:
        return []
    return dedupe_preserve(match.group(1) for match in _STRING_LITERAL_RE.finditer(text))


def normalize_source_path(raw: str) -> Optional[str]:
    if not raw:
        return None
    cleaned = raw.strip().strip("\"'").replace("\\", "/")
    if not _SOURCE_EXT_RE.search(cleaned):
        return None

    parts = [part for part in cleaned.split("/") if part not in ("", ".")]
    if not parts:
        return None

    lower_parts = [part.lower() for part in parts]
    for anchor in _PATH_ANCHORS:
        if anchor in lower_parts:
            parts = parts[lower_parts.index(anchor) :]
            break
    else:
        if len(parts) > 4:
            parts = parts[-4:]

    if parts and re.fullmatch(r"[A-Za-z]:", parts[0]):
        parts = parts[1:]
    if not parts:
        return None
    if any(len(part) > 48 for part in parts):
        return None
    if len(PurePosixPath(*parts).stem) < 2:
        return None
    return PurePosixPath(*parts).as_posix()


def extract_source_candidates(values: Iterable[str]) -> list[str]:
    results: list[str] = []
    for value in values:
        if not value:
            continue
        for pattern in (_SOURCE_PATH_RE, _REL_SOURCE_PATH_RE):
            for match in pattern.finditer(value):
                normalized = normalize_source_path(match.group(1))
                if normalized:
                    results.append(normalized)
        normalized = normalize_source_path(value)
        if normalized:
            results.append(normalized)
    return dedupe_preserve(results)


def guess_class_name(display_name: Optional[str], strings: Iterable[str] = ()) -> Optional[str]:
    haystacks = [display_name or "", *strings]
    for text in haystacks:
        if not text:
            continue
        match = _QUALIFIED_NAME_RE.search(text)
        if match:
            candidate = match.group(1)
            if _is_reasonable_symbol_token(candidate):
                return candidate
        match = _MSVC_RTTI_RE.search(text)
        if match:
            candidate = match.group(1)
            if _is_reasonable_symbol_token(candidate):
                return candidate
    return None


def sanitize_identifier(value: str) -> str:
    ident = re.sub(r"[^0-9A-Za-z_]+", "_", value).strip("_")
    ident = re.sub(r"_+", "_", ident)
    if not ident:
        return "sub"
    if ident[0].isdigit():
        return f"fn_{ident}"
    return ident


def _is_reasonable_symbol_token(value: str) -> bool:
    if not value:
        return False
    if len(value) > 40:
        return False
    if _GENERATED_NAME_RE.match(value):
        return False
    return True


def guess_function_name(
    name: str,
    demangled_name: Optional[str],
    source_candidates: Iterable[str],
    class_hint: Optional[str],
) -> Optional[str]:
    if demangled_name or (name and not name.startswith("sub_")):
        return None

    prefix = sanitize_identifier(class_hint) if class_hint else ""

    candidate_path = next(iter(source_candidates), None)
    stem = sanitize_identifier(PurePosixPath(candidate_path).stem) if candidate_path else ""

    if prefix and stem and prefix.lower() != stem.lower():
        base = f"{prefix}_{stem}"
    else:
        base = prefix or stem
    if not base:
        return None

    suffix = name[4:] if name.startswith("sub_") else name
    return f"{base}_{sanitize_identifier(suffix).lower()}"


def derive_module_path(source_hint: str) -> str:
    path = PurePosixPath(source_hint).with_suffix("")
    parts = list(path.parts)
    if parts and parts[0].lower() in {"src", "source", "sources"}:
        parts = parts[1:]
    if not parts:
        return path.name
    return PurePosixPath(*parts).as_posix()


def enrich_artifact_metadata(artifact: FunctionArtifact) -> None:
    literal_strings = extract_string_literals(artifact.decompiled_code)
    artifact.string_refs = dedupe_preserve([*artifact.string_refs, *literal_strings])

    source_candidates = extract_source_candidates(
        [
            artifact.name,
            artifact.demangled_name or "",
            *artifact.string_refs,
        ]
    )
    artifact.source_candidates = dedupe_preserve([*artifact.source_candidates, *source_candidates])

    if not artifact.class_hint:
        artifact.class_hint = guess_class_name(artifact.demangled_name or artifact.name, artifact.string_refs)

    if not artifact.guessed_name:
        artifact.guessed_name = guess_function_name(
            artifact.name,
            artifact.demangled_name,
            artifact.source_candidates,
            artifact.class_hint,
        )
