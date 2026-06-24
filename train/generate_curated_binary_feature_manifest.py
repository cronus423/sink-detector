#!/usr/bin/env python3
"""Generate a binary/debug-info feature manifest for curated attack sinks."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PROGRAM_TARGETS = ROOT / "program_targets"
CURATED_MD = PROGRAM_TARGETS / "CURATED_ATTACK_SINKS.md"
ML_DATASET = PROGRAM_TARGETS / "ml_dataset"
UPSTREAM_FEATURE_MANIFEST = (
    ROOT.parent
    / "traning_DATA_generation"
    / "semantic_examples"
    / "sensitive_training_dataset_branch_loop_regions"
    / "features"
    / "sensitive_dataset_manifest.json"
)
BINARY_ONLY_FEATURE_MANIFEST = (
    ROOT.parent
    / "traning_DATA_generation"
    / "semantic_examples"
    / "binary_classifier_binary_only_improved"
    / "features"
    / "manifest_binary_only.json"
)
LAYER3_FEATURE_MANIFEST = (
    ROOT.parent
    / "traning_DATA_generation"
    / "semantic_examples"
    / "binary_classifier_layer3_features"
    / "features"
    / "manifest_layer3.json"
)
ANTIPATTERN_FEATURE_MANIFEST = (
    ROOT.parent
    / "traning_DATA_generation"
    / "semantic_examples"
    / "binary_classifier_antipattern_improved"
    / "features"
    / "manifest_antipattern.json"
)

OUT_MANIFEST = ML_DATASET / "curated_binary_debug_feature_manifest.json"
OUT_CANDIDATES = ML_DATASET / "curated_binary_sink_candidates.jsonl"
OUT_README = ML_DATASET / "CURATED_BINARY_DEBUG_FEATURE_MANIFEST.md"
OUT_XGBOOST_FEATURES = ML_DATASET / "curated_xgboost_feature_list.json"
OUT_XGBOOST_FEATURES_TXT = ML_DATASET / "curated_xgboost_feature_list.txt"
OUT_XGBOOST_DEBUG_NAME_FEATURES = ML_DATASET / "curated_xgboost_feature_list_debug_names.json"
OUT_XGBOOST_DEBUG_NAME_FEATURES_TXT = ML_DATASET / "curated_xgboost_feature_list_debug_names.txt"

DEBUG_NAME_SHAPE_FEATURES = [
    "debug_name_length",
    "debug_name_num_tokens",
    "debug_name_num_underscores",
    "debug_name_has_digit",
    "debug_name_has_plt_suffix",
]

DEBUG_NAME_TOKEN_FEATURES = [
    "debug_name_tok_auth",
    "debug_name_tok_authorize",
    "debug_name_tok_policy",
    "debug_name_tok_check",
    "debug_name_tok_verify",
    "debug_name_tok_login",
    "debug_name_tok_user",
    "debug_name_tok_passwd",
    "debug_name_tok_pam",
    "debug_name_tok_exec",
    "debug_name_tok_spawn",
    "debug_name_tok_command",
    "debug_name_tok_shell",
    "debug_name_tok_uid",
    "debug_name_tok_gid",
    "debug_name_tok_chroot",
    "debug_name_tok_group",
    "debug_name_tok_priv",
    "debug_name_tok_open",
    "debug_name_tok_file",
    "debug_name_tok_path",
    "debug_name_tok_stat",
    "debug_name_tok_unlink",
    "debug_name_tok_rename",
    "debug_name_tok_chmod",
    "debug_name_tok_chown",
    "debug_name_tok_mkdir",
    "debug_name_tok_rmdir",
    "debug_name_tok_connect",
    "debug_name_tok_listen",
    "debug_name_tok_accept",
    "debug_name_tok_upstream",
    "debug_name_tok_proxy",
    "debug_name_tok_dispatch",
    "debug_name_tok_handler",
    "debug_name_tok_phase",
    "debug_name_tok_callback",
    "debug_name_tok_request",
    "debug_name_tok_parse",
    "debug_name_tok_uri",
    "debug_name_tok_body",
    "debug_name_tok_header",
    "debug_name_tok_length",
    "debug_name_tok_send",
    "debug_name_tok_output",
    "debug_name_tok_write",
    "debug_name_tok_finalize",
    "debug_name_tok_response",
    "debug_name_tok_cache",
    "debug_name_tok_session",
]

DEBUG_NAME_HASH_BUCKET_FEATURES = [
    f"debug_name_token_hash_bucket_{i:02d}" for i in range(64)
]


PROGRAM_MAP = {
    "sudo 1.8.31": {
        "target_id": "sudo_1_8_31",
        "program_family": "sudo",
        "program_role": "privileged command runner",
        "is_suid_or_privileged_design": True,
        "network_daemon": False,
        "auth_boundary_present": True,
    },
    "Cherry HTTP 4b877df": {
        "target_id": "cherry_http_4b877df",
        "program_family": "http",
        "program_role": "HTTP static file server",
        "is_suid_or_privileged_design": False,
        "network_daemon": True,
        "auth_boundary_present": False,
    },
    "ProFTPD 1.3.3c": {
        "target_id": "proftpd_1_3_3c",
        "program_family": "ftp",
        "program_role": "FTP daemon",
        "is_suid_or_privileged_design": True,
        "network_daemon": True,
        "auth_boundary_present": True,
    },
    "polkit 0.105 / pkexec": {
        "target_id": "polkit_0_105_31",
        "program_family": "polkit",
        "program_role": "privileged authorization runner",
        "is_suid_or_privileged_design": True,
        "network_daemon": False,
        "auth_boundary_present": True,
    },
    "vsftpd 3.0.5": {
        "target_id": "vsftpd_3_0_5",
        "program_family": "ftp",
        "program_role": "FTP daemon",
        "is_suid_or_privileged_design": True,
        "network_daemon": True,
        "auth_boundary_present": True,
    },
    "OpenSSH 9.7p1": {
        "target_id": "openssh_9_7p1",
        "program_family": "ssh",
        "program_role": "SSH daemon",
        "is_suid_or_privileged_design": True,
        "network_daemon": True,
        "auth_boundary_present": True,
    },
    "wu-ftpd 2.6.1": {
        "target_id": "wu_ftpd_2_6_1",
        "program_family": "ftp",
        "program_role": "FTP daemon",
        "is_suid_or_privileged_design": True,
        "network_daemon": True,
        "auth_boundary_present": True,
    },
    "MicroHttpServer 4398570": {
        "target_id": "microhttpserver_4398570",
        "program_family": "http",
        "program_role": "embedded HTTP server",
        "is_suid_or_privileged_design": False,
        "network_daemon": True,
        "auth_boundary_present": False,
    },
    "nginx 1.4.0 validation target": {
        "target_id": "nginx_1_4_0_validation",
        "program_family": "http",
        "program_role": "HTTP reverse proxy/static server",
        "is_suid_or_privileged_design": True,
        "network_daemon": True,
        "auth_boundary_present": True,
        "binary_relpath": "nginx_1_4_0_validation/target/bin/nginx",
        "target_root_relpath": "nginx_1_4_0_validation",
        "stage02_relpath": "nginx_1_4_0_validation/artifacts/stage_02_static_ir_cfg",
        "stage03_relpath": "nginx_1_4_0_validation/artifacts/stage_03_attack_goals",
        "source_available": False,
        "source_line_level": False,
    },
}

TRAINING_CATEGORY_MAP = {
    "process_execution_goal": ["execution_dispatch_like"],
    "authorization_goal": ["auth_policy_like"],
    "identity_goal": ["privilege_state_like"],
    "permission_goal": ["resource_modify_like", "privilege_state_like"],
    "ownership_goal": ["resource_modify_like", "privilege_state_like"],
    "file_access_goal": ["resource_open_like"],
    "file_mutation_goal": ["resource_modify_like"],
    "network_goal": ["resource_open_like", "network_endpoint_like"],
    "dispatch_goal": ["execution_dispatch_like", "dispatch_control_like"],
    "dispatch_state_goal": ["execution_dispatch_like", "dispatch_control_like"],
    "branch_policy_goal": ["parser_policy_like"],
    "memory_transfer_goal": ["memory_region_like"],
    "output_goal": ["output_like"],
    "format_goal": ["output_like"],
    "allocation_goal": ["memory_region_like"],
    "allocator_state_goal": ["memory_region_like"],
    "framework_sensitive_goal": ["framework_sensitive_like"],
    "metadata_mutation_goal": ["resource_modify_like"],
}


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def elf_sections(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        proc = subprocess.run(
            ["readelf", "-S", str(path)],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError):
        return set()
    return set(re.findall(r"\]\s+(\.[A-Za-z0-9_.$-]+)\s+", proc.stdout))


def split_cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def parse_curated_sinks() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    current_program = None
    table_headers: list[str] | None = None
    for line in CURATED_MD.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            current_program = line[3:].strip()
            table_headers = None
            continue
        if not current_program or not line.startswith("|"):
            continue
        cells = split_cells(line)
        if not cells:
            continue
        if cells[0] == "Priority":
            table_headers = cells
            continue
        if cells[0].startswith("---") or cells[0] not in {"Critical", "High", "Medium", "Low"}:
            continue
        if not table_headers or len(cells) != len(table_headers):
            continue
        rec = dict(zip(table_headers, cells))
        sink_kinds = [
            part.strip().strip("`")
            for part in re.split(r"\s*/\s*", rec["Kind"])
            if part.strip()
        ]
        target_meta = PROGRAM_MAP[current_program]
        row_index = sum(1 for r in rows if r["target_id"] == target_meta["target_id"]) + 1
        sink_slug = re.sub(r"[^a-z0-9]+", "_", rec["Sink"].lower()).strip("_")[:48]
        rows.append(
            {
                "candidate_id": f"{target_meta['target_id']}:{row_index:02d}:{sink_slug}",
                "program_name": current_program,
                "target_id": target_meta["target_id"],
                "priority": rec["Priority"].lower(),
                "sink_kinds": sink_kinds,
                "source_hint": rec.get("Location", ""),
                "sink_summary": rec.get("Sink", ""),
                "why_keep": rec.get("Why keep", ""),
            }
        )
    return rows


def program_binary_info(target_id: str, meta: dict[str, Any]) -> dict[str, Any]:
    if target_id == "nginx_1_4_0_validation":
        binary = ROOT / meta["binary_relpath"]
        target_root = ROOT / meta["target_root_relpath"]
        stage02 = ROOT / meta["stage02_relpath"]
        stage03 = ROOT / meta["stage03_relpath"]
        manifest_data = {
            "target": target_id,
            "binary_basename": binary.name,
            "build_mode": "validation_debug_analysis",
            "cflags": "debug validation binary",
            "source": "real_program/nginx140-docker/analysis_nginx140",
            "version": "1.4.0",
        }
    else:
        target_root = PROGRAM_TARGETS / target_id
        manifest_data = read_json(target_root / "target" / "MANIFEST.json")
        binary = target_root / "target" / manifest_data["binary_basename"]
        stage02 = target_root / "artifacts" / "stage_02_static_ir_cfg"
        stage03 = target_root / "artifacts" / "stage_03_attack_goals"

    sections = elf_sections(binary)
    return {
        "target_id": target_id,
        "program_family": meta["program_family"],
        "program_role": meta["program_role"],
        "is_suid_or_privileged_design": meta["is_suid_or_privileged_design"],
        "network_daemon": meta["network_daemon"],
        "auth_boundary_present": meta["auth_boundary_present"],
        "source_available": meta.get("source_available", (target_root / "source").exists()),
        "source_line_level": meta.get("source_line_level", True),
        "target_root": rel(target_root),
        "binary": rel(binary),
        "binary_basename": manifest_data.get("binary_basename", binary.name),
        "binary_sha256": sha256(binary),
        "build_mode": manifest_data.get("build_mode"),
        "cflags": manifest_data.get("cflags"),
        "source": manifest_data.get("source"),
        "version": manifest_data.get("version"),
        "debug_info_available": ".debug_info" in sections and ".debug_line" in sections,
        "symtab_available": ".symtab" in sections,
        "debug_sections": sorted(s for s in sections if s.startswith(".debug_")),
        "stage02_artifacts": {
            "dwarf_facts": rel(stage02 / "dwarf_facts.json"),
            "disassembly_jsonl": rel(stage02 / "nginx_disassembly.jsonl"),
            "cfg": rel(stage02 / "nginx_cfg.json"),
            "icfg": rel(stage02 / "nginx_icfg.json"),
            "ir": rel(stage02 / "nginx_ir.json"),
            "ir_graphs": rel(stage02 / "nginx_ir_graphs.json"),
        },
        "stage03_artifacts": {
            "attack_goals": rel(stage03 / "attack_goals.json"),
            "raw_binary_attack_targets": rel(stage03 / "raw_binary_attack_targets.json"),
        },
    }


def candidate_categories(sink_kinds: list[str]) -> list[str]:
    cats: list[str] = []
    for kind in sink_kinds:
        for cat in TRAINING_CATEGORY_MAP.get(kind, []):
            if cat not in cats:
                cats.append(cat)
    return cats


def extract_symbol_hints(text: str) -> list[str]:
    hints: list[str] = []
    for token in re.findall(r"`([^`]+)`", text):
        token = token.strip()
        if not token:
            continue
        for piece in re.split(r"\s*->\s*|,\s*", token):
            piece = piece.strip()
            func_match = re.match(r"^([A-Za-z_][A-Za-z0-9_@.]*)\s*\(", piece)
            if func_match:
                hints.append(func_match.group(1).replace("@plt", ""))
            if re.match(r"^[A-Za-z_][A-Za-z0-9_@.()/-]*$", piece):
                hints.append(piece.replace("()", ""))
    for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", text):
        if token.startswith(("ngx_", "vsf_", "pr_", "ssh", "userauth_", "handle_", "core_")):
            hints.append(token)
    return sorted(set(hints))


def source_hint_records(source_hint: str) -> list[dict[str, Any]]:
    records = []
    for item in source_hint.split(","):
        item = item.strip().strip("`")
        if not item or item == "external libc/glibc" or item.startswith("stage "):
            continue
        m = re.match(r"(?P<file>[^:]+):(?P<start>\d+)(?:-(?P<end>\d+))?$", item)
        if m:
            records.append(
                {
                    "file_hint": m.group("file"),
                    "line_start": int(m.group("start")),
                    "line_end": int(m.group("end") or m.group("start")),
                }
            )
        else:
            records.append({"file_hint": item, "line_start": None, "line_end": None})
    return records


def load_stage03_goals(path: str) -> list[dict[str, Any]]:
    full = ROOT / path
    if not full.exists():
        return []
    data = read_json(full)
    return data.get("goals", [])


def file_hint_matches(goal_file: str, file_hint: str) -> bool:
    if not goal_file or not file_hint:
        return False
    goal_file = goal_file.replace("\\", "/").replace("/./", "/")
    file_hint = file_hint.replace("\\", "/").replace("/./", "/")
    return goal_file.endswith(file_hint) or goal_file.endswith("/" + file_hint)


def match_stage03_goals(
    goals: list[dict[str, Any]],
    source_records: list[dict[str, Any]],
    symbol_hints: list[str],
    sink_kinds: list[str],
) -> tuple[str, list[dict[str, Any]]]:
    matches: list[tuple[int, dict[str, Any]]] = []
    symbol_set = {s.replace("@plt", "") for s in symbol_hints}
    for goal in goals:
        score = 0
        loc = goal.get("source_location") or {}
        goal_line = loc.get("line")
        goal_file = loc.get("file") or ""
        for rec in source_records:
            if file_hint_matches(goal_file, str(rec.get("file_hint", ""))):
                score += 2
                start, end = rec.get("line_start"), rec.get("line_end")
                if goal_line is not None and start is not None and start <= int(goal_line) <= int(end):
                    score += 5
        function = goal.get("function") or ""
        target_name = (goal.get("target_name") or "").replace("@plt", "")
        if function in symbol_set:
            score += 3
        if target_name in symbol_set:
            score += 4
        if goal.get("kind") in sink_kinds:
            score += 1
        if score > 0:
            matches.append((score, goal))
    matches.sort(key=lambda item: (-item[0], str(item[1].get("pc", ""))))
    compact = []
    for score, goal in matches[:8]:
        loc = goal.get("source_location") or {}
        compact.append(
            {
                "match_score": score,
                "goal_id": goal.get("id"),
                "pc": goal.get("pc"),
                "function": goal.get("function"),
                "target_name": goal.get("target_name"),
                "target_kind": goal.get("target_kind"),
                "kind": goal.get("kind"),
                "category": goal.get("category"),
                "source_location": {
                    "file": loc.get("file"),
                    "line": loc.get("line"),
                    "raw": loc.get("raw"),
                },
            }
        )
    if compact and compact[0]["match_score"] >= 7:
        return "stage03_debug_line_aligned", compact
    if compact and compact[0]["match_score"] >= 4:
        return "stage03_symbol_or_kind_aligned", compact
    if compact:
        return "stage03_weak_candidate_match", compact
    return "requires_debug_line_or_stage03_alignment", compact


def write_outputs() -> None:
    ML_DATASET.mkdir(parents=True, exist_ok=True)
    upstream = read_json(UPSTREAM_FEATURE_MANIFEST)
    binary_only_manifest = read_json(BINARY_ONLY_FEATURE_MANIFEST)
    layer3_manifest = read_json(LAYER3_FEATURE_MANIFEST)
    antipattern_manifest = read_json(ANTIPATTERN_FEATURE_MANIFEST)
    candidates = parse_curated_sinks()
    program_infos = {
        meta["target_id"]: program_binary_info(meta["target_id"], meta)
        for meta in PROGRAM_MAP.values()
    }

    category_names = list(upstream["category_names"])
    for extra in [
        "auth_policy_like",
        "dispatch_control_like",
        "parser_policy_like",
        "network_endpoint_like",
        "framework_sensitive_like",
    ]:
        if extra not in category_names:
            category_names.append(extra)

    candidate_rows = []
    for rec in candidates:
        pinfo = program_infos[rec["target_id"]]
        cats = candidate_categories(rec["sink_kinds"])
        source_records = source_hint_records(rec["source_hint"])
        symbol_hints = extract_symbol_hints(rec["sink_summary"])
        goals = load_stage03_goals(pinfo["stage03_artifacts"]["attack_goals"])
        resolution_status, stage03_matches = match_stage03_goals(
            goals,
            source_records,
            symbol_hints,
            rec["sink_kinds"],
        )
        row = {
            "schema": "dfb-curated-binary-sink-candidate/v1",
            "candidate_id": rec["candidate_id"],
            "target_id": rec["target_id"],
            "program_name": rec["program_name"],
            "program_family": pinfo["program_family"],
            "program_role": pinfo["program_role"],
            "binary": pinfo["binary"],
            "binary_sha256": pinfo["binary_sha256"],
            "debug_info_available": pinfo["debug_info_available"],
            "symtab_available": pinfo["symtab_available"],
            "label": {
                "worth_attack": 1,
                "priority": rec["priority"],
                "sink_kinds": rec["sink_kinds"],
                "training_categories": cats,
                "category_onehot": {name: int(name in cats) for name in category_names},
            },
            "curation": {
                "source": rel(CURATED_MD),
                "source_hint": rec["source_hint"],
                "sink_summary": rec["sink_summary"],
                "why_keep": rec["why_keep"],
                "source_hint_records": source_records,
            },
            "binary_resolution": {
                "resolution_status": resolution_status,
                "stage02_artifacts": pinfo["stage02_artifacts"],
                "stage03_artifacts": pinfo["stage03_artifacts"],
                "symbol_hints": symbol_hints,
                "stage03_matches": stage03_matches,
                "primary_binary_pc": stage03_matches[0]["pc"] if stage03_matches else None,
                "primary_binary_function": stage03_matches[0]["function"] if stage03_matches else None,
                "source_hints_are_labels_not_model_features": True,
            },
        }
        candidate_rows.append(row)

    with OUT_CANDIDATES.open("w", encoding="utf-8") as f:
        for row in candidate_rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")

    xgboost_feature_groups = {
        "binary_only_numeric_asm_cfg": binary_only_manifest["numeric_feature_names"],
    }
    ordered_xgboost_features: list[str] = []
    for names in xgboost_feature_groups.values():
        for name in names:
            if name not in ordered_xgboost_features:
                ordered_xgboost_features.append(name)

    xgboost_feature_manifest = {
        "schema": "dfb-curated-xgboost-feature-list/v1",
        "task": "binary-only sink_like vs unsink_like feature contract for curated real-program sinks",
        "feature_source_manifest": rel(OUT_MANIFEST),
        "candidate_rows": rel(OUT_CANDIDATES),
        "reference_manifests": {
            "selected_binary_only": os.path.relpath(BINARY_ONLY_FEATURE_MANIFEST, ROOT),
            "branch_loop_asm": os.path.relpath(UPSTREAM_FEATURE_MANIFEST, ROOT),
            "layer3_experiment_optional": os.path.relpath(LAYER3_FEATURE_MANIFEST, ROOT),
            "antipattern_experiment_optional": os.path.relpath(ANTIPATTERN_FEATURE_MANIFEST, ROOT),
        },
        "reference_extraction_code": {
            "base_asm_cfg_extractor": "../traning_DATA_generation/semantic_examples/sensitive_training_dataset_branch_loop_regions/scripts/extract_asm_features.py",
            "binary_only_dataset_builder": "../traning_DATA_generation/semantic_examples/binary_classifier_binary_only_improved/scripts/build_dataset.py",
            "layer3_optional_extractor": "../traning_DATA_generation/semantic_examples/binary_classifier_layer3_features/scripts/extract_layer3_features.py",
            "antipattern_optional_extractor": "../traning_DATA_generation/semantic_examples/binary_classifier_antipattern_improved/scripts/antipattern_features.py",
        },
        "label_columns": [
            "worth_attack",
            "priority",
            "sink_kinds",
            "training_categories",
        ],
        "primary_key_columns": ["target_id", "binary_sha256", "candidate_id"],
        "feature_count": len(ordered_xgboost_features),
        "feature_groups": xgboost_feature_groups,
        "ordered_feature_names": ordered_xgboost_features,
        "feature_source_policy": {
            "binary_only": True,
            "source": binary_only_manifest.get("token_source")
            or "GCC .s / binary-derived function bodies and CFG only",
            "numeric_only": True,
            "text_features_enabled": False,
            "selected_because": "binary_classifier_binary_only_improved/WORK_LOG.md selected numeric-only 125 as the safer binary gate; token and extra hand features did not improve external generalization.",
        },
        "optional_experimental_feature_sets_not_in_default": {
            "layer3_feature_names": layer3_manifest.get("layer3_feature_names", []),
            "antipattern_feature_names": antipattern_manifest.get("antipattern_feature_names", []),
        },
        "excluded_from_model_features": [
            "candidate_id",
            "target_id",
            "binary",
            "binary_sha256",
            "debug_info_available",
            "symtab_available",
            "program_name",
            "program_family",
            "program_role raw string",
            "function_name raw string",
            "callee_name raw string",
            "source_file raw string",
            "source_line raw text",
            "curation.source_hint",
            "curation.sink_summary",
            "curation.why_keep",
            "label.priority",
            "label.sink_kinds",
            "label.training_categories",
            "manual taxonomy categories such as output_like/resource_open_like/auth_policy_like",
            "binary_resolution.resolution_status",
            "stage03_matches raw JSON",
        ],
        "notes": [
            "This list is the 125 numeric binary-only feature columns from the previously selected binary classifier manifest.",
            "Source hints, function names, labels, manual categories, and Stage3 alignment metadata are not model features.",
            "Debug info is used to align curated sinks to functions/PCs before feature extraction, not as feature input.",
            "Current candidate rows are all positive curated sinks; sample negatives from non-curated Stage3 candidates in the same binaries.",
        ],
    }
    OUT_XGBOOST_FEATURES.write_text(
        json.dumps(xgboost_feature_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    OUT_XGBOOST_FEATURES_TXT.write_text(
        "\n".join(ordered_xgboost_features) + "\n",
        encoding="utf-8",
    )

    debug_name_feature_groups = {
        **xgboost_feature_groups,
        "debug_function_name_shape": DEBUG_NAME_SHAPE_FEATURES,
        "debug_function_name_token_flags": DEBUG_NAME_TOKEN_FEATURES,
        "debug_function_name_hash_buckets": DEBUG_NAME_HASH_BUCKET_FEATURES,
    }
    ordered_debug_name_features: list[str] = []
    for names in debug_name_feature_groups.values():
        for name in names:
            if name not in ordered_debug_name_features:
                ordered_debug_name_features.append(name)
    xgboost_debug_name_manifest = {
        **xgboost_feature_manifest,
        "schema": "dfb-curated-xgboost-feature-list-debug-names/v1",
        "task": "debug-info binary sink_like vs unsink_like feature contract for curated real-program sinks",
        "feature_count": len(ordered_debug_name_features),
        "feature_groups": debug_name_feature_groups,
        "ordered_feature_names": ordered_debug_name_features,
        "feature_source_policy": {
            **xgboost_feature_manifest["feature_source_policy"],
            "debug_function_names_enabled": True,
            "debug_name_source": "DWARF function name, symtab symbol, or Stage3 function recovered from debug-enabled ELF",
            "requires_debug_or_symbols": True,
        },
        "debug_name_encoding": {
            "name_shape": "numeric counts and boolean 0/1 columns",
            "token_flags": "case-normalized substring/token presence from function/symbol names",
            "hash_buckets": "stable hash of normalized function-name tokens into 64 numeric count buckets",
            "raw_name_not_used": True,
        },
        "excluded_from_model_features": [
            x
            for x in xgboost_feature_manifest["excluded_from_model_features"]
            if x != "function_name raw string"
        ]
        + [
            "raw function name string; only encoded debug_name_* numeric columns are model inputs"
        ],
        "notes": [
            "This augmented profile is appropriate only when training and inference both have debug symbols or recoverable symbol names.",
            "The strict 125-column profile remains available in curated_xgboost_feature_list.json for stripped-binary or no-name settings.",
            "Function names are encoded as numeric debug_name_* columns, not passed as raw strings.",
        ],
    }
    OUT_XGBOOST_DEBUG_NAME_FEATURES.write_text(
        json.dumps(xgboost_debug_name_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    OUT_XGBOOST_DEBUG_NAME_FEATURES_TXT.write_text(
        "\n".join(ordered_debug_name_features) + "\n",
        encoding="utf-8",
    )

    priority_counts: dict[str, int] = {}
    per_target_counts: dict[str, int] = {}
    resolution_counts: dict[str, int] = {}
    for row in candidate_rows:
        priority_counts[row["label"]["priority"]] = priority_counts.get(row["label"]["priority"], 0) + 1
        per_target_counts[row["target_id"]] = per_target_counts.get(row["target_id"], 0) + 1
        status = row["binary_resolution"]["resolution_status"]
        resolution_counts[status] = resolution_counts.get(status, 0) + 1

    manifest = {
        "schema": "dfb-curated-binary-debug-feature-manifest/v1",
        "sample_unit": "curated_binary_sink_candidate",
        "generated_from": {
            "curated_sinks": rel(CURATED_MD),
            "upstream_training_manifest": os.path.relpath(UPSTREAM_FEATURE_MANIFEST, ROOT),
            "upstream_schema": upstream.get("category_names"),
        },
        "primary_key": ["target_id", "binary_sha256", "candidate_id"],
        "label": {
            "name": "worth_attack",
            "type": "binary",
            "positive_value": 1,
            "negative_value": 0,
            "positive_definition": "curated sink is a security-relevant binary-level attack sink worth DFB analysis",
            "current_manifest_rows": "all rows are positive curated sinks; negatives must be sampled separately from non-curated Stage3 candidates",
            "auxiliary_labels": ["priority", "sink_kinds", "training_categories"],
        },
        "binary_debug_scope": {
            "binary_level_only": True,
            "debug_info_required_for_source_line_alignment": True,
            "debug_info_available_for_all_targets": all(p["debug_info_available"] for p in program_infos.values()),
            "source_text_not_required_as_model_input": True,
            "source_locations_are_alignment_hints": True,
        },
        "programs": program_infos,
        "candidate_inventory": {
            "candidate_count": len(candidate_rows),
            "priority_counts": priority_counts,
            "per_target_counts": per_target_counts,
            "resolution_counts": resolution_counts,
            "candidate_jsonl": rel(OUT_CANDIDATES),
        },
        "category_names": category_names,
        "sensitive_function_categories": {
            **upstream["sensitive_function_categories"],
            "auth_policy_like": [
                "sudoers_lookup",
                "check_user",
                "verify_user",
                "polkit_authority_check_authorization_sync",
                "pam_authenticate",
                "sshkey_verify",
                "user_key_allowed",
                "vsf_sysdep_check_auth",
                "pr_auth_check",
                "crypt",
            ],
            "dispatch_control_like": [
                "command table",
                "handler table",
                "route table",
                "session request dispatch",
                "indirect call",
            ],
            "parser_policy_like": [
                "request line parser",
                "method parser",
                "uri parser",
                "content-length parser",
                "policy branch",
            ],
            "network_endpoint_like": [
                "listen",
                "accept",
                "connect",
                "bind",
                "PASV",
                "PORT",
                "upstream connect",
            ],
            "framework_sensitive_like": [
                "gconv module loading",
                "polkit agent/session",
                "nginx phase handler",
            ],
        },
        "feature_groups": {
            "upstream_asm_function_features": upstream["feature_names"],
            "upstream_ranker_category_onehot_features": upstream["ranker_category_onehot_features"],
            "upstream_ranker_feature_names": upstream["ranker_feature_names"],
            "binary_candidate_identity_features": [
                "candidate_kind",
                "binary_pc",
                "function_name",
                "callee_name",
                "target_kind",
                "instruction_opcode",
                "is_plt_call",
                "is_internal_call",
                "is_indirect_control_transfer",
                "tracked_arg_count",
                "critical_use_operand_roles",
            ],
            "binary_debug_features": [
                "debug_info_available",
                "symtab_available",
                "dwarf_function_name",
                "dwarf_decl_file",
                "dwarf_decl_line",
                "dwarf_call_file",
                "dwarf_call_line",
                "addr2line_file",
                "addr2line_line",
                "dwarf_function_arity",
                "dwarf_param_pointer_count",
                "dwarf_param_scalar_count",
                "dwarf_access_has_field_key",
                "dwarf_access_field_offset",
                "dwarf_access_field_size",
                "dwarf_inline_array_size_nearby",
                "dwarf_neighbor_field_distance",
            ],
            "stage_pipeline_features": [
                "stage03_kind",
                "stage03_category",
                "stage03_weight",
                "stage04_critical_use_count",
                "stage05_slice_node_count",
                "stage06_static_rd_count",
                "stage06_precise_rd_count",
                "stage06_rdr_count",
                "stage06_has_field_insensitive_rdr",
                "stage06_has_context_insensitive_rdr",
                "stage06_has_array_oob_rdr",
            ],
            "manual_seed_features": [
                "manual_priority_seed",
                "curated_sink_kind_onehot",
                "curated_training_category_onehot",
                "program_family",
                "program_role",
                "is_suid_or_privileged_design",
                "network_daemon",
                "auth_boundary_present",
            ],
        },
        "negative_sampling_policy": {
            "source": "same program Stage3 attack_goals not present in curated_binary_sink_candidates.jsonl",
            "exclude": [
                "curated positives",
                "exact duplicate PCs",
                "same semantic wrapper when a higher-level curated sink is already labeled positive",
            ],
            "prefer_negatives": [
                "CRT/init/fini dispatch noise",
                "logging/format/output-only calls with no security effect",
                "ordinary allocation/free",
                "generic memory copies without a later sensitive consumer",
                "constant cleanup helpers",
            ],
        },
        "split_policy": {
            "unit": "whole target/program",
            "default_train": [
                "sudo_1_8_31",
                "proftpd_1_3_3c",
                "vsftpd_3_0_5",
                "cherry_http_4b877df",
                "microhttpserver_4398570",
            ],
            "default_validation": ["polkit_0_105_31", "wu_ftpd_2_6_1", "nginx_1_4_0_validation"],
            "default_test": ["openssh_9_7p1"],
            "no_candidate_level_random_split": True,
        },
    }
    OUT_MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    rows = [
        ["artifact", "path"],
        ["manifest", rel(OUT_MANIFEST)],
        ["candidate rows", rel(OUT_CANDIDATES)],
        ["XGBoost feature list", rel(OUT_XGBOOST_FEATURES)],
        ["XGBoost feature columns", rel(OUT_XGBOOST_FEATURES_TXT)],
        ["XGBoost debug-name feature list", rel(OUT_XGBOOST_DEBUG_NAME_FEATURES)],
        ["XGBoost debug-name feature columns", rel(OUT_XGBOOST_DEBUG_NAME_FEATURES_TXT)],
        ["curated sinks", rel(CURATED_MD)],
        ["upstream training manifest", os.path.relpath(UPSTREAM_FEATURE_MANIFEST, ROOT)],
    ]
    summary = [
        "# Curated Binary Debug Feature Manifest",
        "",
        "This manifest defines binary-level, debug-info-aware features for the manually",
        "curated attack sinks. It is based on the upstream branch/loop-region ASM",
        "feature manifest and extends it with DWARF, Stage3, and curated sink labels.",
        "",
        "All candidate rows are positive `worth_attack = 1` curated sinks. Negative",
        "rows should be sampled from non-curated Stage3 candidates in the same binaries.",
        "",
        f"- candidates: {len(candidate_rows)}",
        f"- XGBoost feature columns: {len(ordered_xgboost_features)}",
        f"- XGBoost debug-name feature columns: {len(ordered_debug_name_features)}",
        f"- priorities: {priority_counts}",
        f"- Stage3/debug alignment: {resolution_counts}",
        f"- all debug ELFs have `.debug_info` and `.debug_line`: {manifest['binary_debug_scope']['debug_info_available_for_all_targets']}",
        "",
        "## Artifacts",
        "",
    ]
    for artifact, path in rows[1:]:
        summary.append(f"- {artifact}: `{path}`")
    summary.extend(
        [
            "",
            "## Extraction Contract",
            "",
            "- Use `target_id`, `binary_sha256`, and `candidate_id` as the row key.",
            "- Resolve source hints to binary PCs through DWARF/addr2line or align to",
            "  `artifacts/stage_03_attack_goals/attack_goals.json`.",
            "- Do not feed source text as a model feature; source hints are labels and",
            "  alignment metadata only.",
            "- Use whole-program splits; do not randomly split sinks from the same binary.",
            "",
        ]
    )
    OUT_README.write_text("\n".join(summary), encoding="utf-8")


if __name__ == "__main__":
    write_outputs()
