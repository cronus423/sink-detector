#!/usr/bin/env python3
"""Build feature rows and splits for curated sink/non-sink functions."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from generate_curated_binary_feature_manifest import (
    DEBUG_NAME_HASH_BUCKET_FEATURES,
    DEBUG_NAME_SHAPE_FEATURES,
    DEBUG_NAME_TOKEN_FEATURES,
    ML_DATASET,
    PROGRAM_MAP,
    PROGRAM_TARGETS,
    ROOT,
)


CURATED_SINKS_JSONL = ML_DATASET / "curated_binary_sink_candidates.jsonl"
CURATED_NON_SINKS_MD = PROGRAM_TARGETS / "CURATED_NON_SINK_FUNCTIONS.md"
STRICT_FEATURE_LIST = ML_DATASET / "curated_xgboost_feature_list.json"
DEBUG_FEATURE_LIST = ML_DATASET / "curated_xgboost_feature_list_debug_names.json"

OUT_JSONL = ML_DATASET / "curated_function_features.jsonl"
OUT_STRICT_CSV = ML_DATASET / "curated_function_features_binary_only.csv"
OUT_DEBUG_CSV = ML_DATASET / "curated_function_features_debug_names.csv"
OUT_SKIPPED = ML_DATASET / "curated_function_features_skipped.jsonl"
OUT_MANIFEST = ML_DATASET / "curated_function_feature_dataset_manifest.json"
OUT_README = ML_DATASET / "CURATED_FUNCTION_FEATURE_DATASET.md"
OUT_SPLIT_DIR = ML_DATASET / "splits"

META_FIELDS = [
    "sample_id",
    "target_id",
    "program_name",
    "function",
    "worth_attack",
    "label_source",
    "split",
    "resolution_method",
    "candidate_id",
]

COND_JUMPS = {
    "ja",
    "jae",
    "jb",
    "jbe",
    "jc",
    "jcxz",
    "je",
    "jecxz",
    "jg",
    "jge",
    "jl",
    "jle",
    "jna",
    "jnae",
    "jnb",
    "jnbe",
    "jnc",
    "jne",
    "jng",
    "jnge",
    "jnl",
    "jnle",
    "jno",
    "jnp",
    "jns",
    "jnz",
    "jo",
    "jp",
    "jpe",
    "jpo",
    "js",
    "jz",
}
UNCOND_JUMPS = {"jmp", "jmpq"}
RETURNS = {"ret", "retq", "iret", "iretq"}
ARG_BASE_REGS = {
    "rdi",
    "edi",
    "di",
    "dil",
    "rsi",
    "esi",
    "si",
    "sil",
    "rdx",
    "edx",
    "dx",
    "dl",
    "rcx",
    "ecx",
    "cx",
    "cl",
    "r8",
    "r8d",
    "r8w",
    "r8b",
    "r9",
    "r9d",
    "r9w",
    "r9b",
}
STACK_REGS = {"rsp", "esp", "sp", "spl", "rbp", "ebp", "bp", "bpl"}

REGION_SUFFIXES = [
    "num_instructions",
    "num_successors",
    "num_predecessors",
    "num_calls",
    "num_cond_jumps",
    "num_mem_reads",
    "num_mem_writes",
    "num_stack_writes",
    "num_non_stack_writes",
    "num_rip_relative_accesses",
    "num_arg_based_mem_accesses",
    "num_small_constants",
    "num_power2_constants",
    "has_page_constant_0xfff",
    "has_page_size_0x1000",
    "has_negative_one",
    "num_cmp",
    "num_test",
    "num_and_or_xor",
    "num_add_sub",
    "num_lea",
    "num_shifts",
    "has_call",
    "has_mem_write",
    "has_return_zero",
    "has_return_negative",
    "num_indirect_calls",
    "num_indirect_jumps",
    "num_scaled_index_memory_accesses",
]

TITLE_TO_TARGET = {name: meta["target_id"] for name, meta in PROGRAM_MAP.items()}
TARGET_TO_TITLE = {meta["target_id"]: name for name, meta in PROGRAM_MAP.items()}

AUXILIARY_STAGE02_DIRS = {
    "sudo_1_8_31": [
        ("sudoers_plugin", PROGRAM_TARGETS / "sudo_1_8_31" / "artifacts" / "stage_02_sudoers_plugin"),
    ],
}

POSITIVE_FUNCTION_OVERRIDES = {
    "polkit_0_105_31:02:polkit_authority_get_sync_polkit_authority_check": "main",
    "polkit_0_105_31:04:g_find_program_in_path_path_access_path_f_ok_exe": "main",
    "polkit_0_105_31:05:polkit_details_insert_for_user_program_command_l": "main",
    "proftpd_1_3_3c:04:pr_fsio_mkdir_rmdir_rename_unlink_open": "pr_fsio_mkdir",
    "proftpd_1_3_3c:05:command_table_for_cwd_mkd_rmd_dele_rnfr_rnto": "pr_cmd_dispatch",
    "proftpd_1_3_3c:06:ftpusers_and_valid_shell_checks": "pr_auth_banned_by_ftpusers",
    "proftpd_1_3_3c:07:site_command_table_and_handler_invocation": "site_dispatch",
    "microhttpserver_4398570:03:method_and_header_parser": "_ParseHeader",
    "microhttpserver_4398570:04:content_length_via_atoi_capped_body_read": "_GetBody",
    "wu_ftpd_2_6_1:07:ftp_site_command_tables": "yylex",
}


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def target_artifact_dir(target_id: str) -> Path:
    if target_id == "nginx_1_4_0_validation":
        return ROOT / "nginx_1_4_0_validation" / "artifacts" / "stage_02_static_ir_cfg"
    return PROGRAM_TARGETS / target_id / "artifacts" / "stage_02_static_ir_cfg"


def load_cfg_functions_from_dir(stage02_dir: Path) -> dict[str, dict[str, Any]]:
    path = stage02_dir / "nginx_cfg.json"
    data = read_json(path)
    out: dict[str, dict[str, Any]] = {}
    for fn in data.get("functions", []):
        name = fn.get("name")
        if name and "@" not in name and not name.startswith("."):
            out.setdefault(name, fn)
    return out


def load_cfg_sources(target_id: str) -> list[tuple[str, dict[str, dict[str, Any]]]]:
    sources = [("primary", load_cfg_functions_from_dir(target_artifact_dir(target_id)))]
    for source_name, stage02_dir in AUXILIARY_STAGE02_DIRS.get(target_id, []):
        if (stage02_dir / "nginx_cfg.json").exists():
            sources.append((source_name, load_cfg_functions_from_dir(stage02_dir)))
    return sources


def load_dwarf_names_from_dir(stage02_dir: Path) -> set[str]:
    path = stage02_dir / "dwarf_facts.json"
    data = read_json(path)
    return {
        rec.get("name")
        for rec in data.get("functions", {}).values()
        if rec.get("name")
    }


def load_dwarf_sources(target_id: str) -> list[tuple[str, set[str]]]:
    sources = [("primary", load_dwarf_names_from_dir(target_artifact_dir(target_id)))]
    for source_name, stage02_dir in AUXILIARY_STAGE02_DIRS.get(target_id, []):
        if (stage02_dir / "dwarf_facts.json").exists():
            sources.append((source_name, load_dwarf_names_from_dir(stage02_dir)))
    return sources


def merged_cfg_names(sources: list[tuple[str, dict[str, dict[str, Any]]]]) -> set[str]:
    names: set[str] = set()
    for _, cfg in sources:
        names.update(cfg)
    return names


def find_cfg_function(
    sources: list[tuple[str, dict[str, dict[str, Any]]]],
    function: str,
) -> tuple[str | None, dict[str, Any] | None]:
    for source_name, cfg in sources:
        if function in cfg:
            return source_name, cfg[function]
    return None, None


def has_dwarf_name(sources: list[tuple[str, set[str]]], function: str) -> bool:
    return any(function in names for _, names in sources)


def clean_symbol(text: str) -> str | None:
    text = text.strip().strip("`")
    text = text.split("->", 1)[0].strip()
    text = text.split("(", 1)[0].strip()
    text = text.strip("\"' ")
    if not text or text in {"SITE", "CWD", "MKD", "RMD", "DELE", "RNFR", "RNTO"}:
        return None
    if "/" in text:
        return None
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", text):
        return text
    return None


def symbols_from_summary(summary: str) -> list[str]:
    out: list[str] = []
    for chunk in re.findall(r"`([^`]+)`", summary):
        sym = clean_symbol(chunk)
        if sym:
            out.append(sym)
    return out


def resolve_positive_function(row: dict[str, Any], cfg_names: set[str]) -> tuple[str | None, str]:
    override = POSITIVE_FUNCTION_OVERRIDES.get(row["candidate_id"])
    if override and override in cfg_names:
        return override, "manual_curated_function_override"

    summary = row["curation"]["sink_summary"]
    for sym in symbols_from_summary(summary):
        if sym in cfg_names:
            return sym, "sink_summary_function"

    hints = row.get("binary_resolution", {}).get("symbol_hints", [])
    for hint in hints:
        sym = clean_symbol(str(hint))
        if sym and sym in cfg_names:
            return sym, "symbol_hint_function"

    br = row.get("binary_resolution", {})
    primary = br.get("primary_binary_function")
    status = br.get("resolution_status")
    if (
        primary in cfg_names
        and primary not in {"_init", "_fini"}
        and status in {"stage03_debug_line_aligned", "stage03_symbol_or_kind_aligned"}
    ):
        return primary, status

    return None, "unresolved_or_weak_positive"


def parse_non_sinks() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    current_target: str | None = None
    for line in CURATED_NON_SINKS_MD.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            current_target = TITLE_TO_TARGET.get(line[3:].strip())
            continue
        if not current_target or not line.startswith("| `"):
            continue
        function = line.split("`", 2)[1]
        rows.append(
            {
                "target_id": current_target,
                "program_name": TARGET_TO_TITLE[current_target],
                "function": function,
                "worth_attack": 0,
                "label_source": "curated_non_sink",
                "candidate_id": "",
                "resolution_method": "curated_dwarf_function",
            }
        )
    return rows


def normalize_operand(opnd: str) -> str:
    return opnd.lower().replace("qword ptr", "").replace("dword ptr", "").replace("word ptr", "").replace("byte ptr", "").strip()


def is_mem_operand(opnd: str) -> bool:
    opnd = normalize_operand(opnd)
    return "[" in opnd and "]" in opnd


def regs_in_operand(opnd: str) -> list[str]:
    return re.findall(r"\b(?:r(?:1[0-5]|[0-9]|[abcd]x|[sd]i|[sb]p)|e(?:[abcd]x|[sd]i|[sb]p)|[abcd][lh]|[abcd]x|[sd]i|[sb]p|r(?:8|9|1[0-5])[dwb]?)\b", opnd.lower())


def is_stack_mem(opnd: str) -> bool:
    return is_mem_operand(opnd) and any(reg in STACK_REGS for reg in regs_in_operand(opnd))


def is_arg_based_mem(opnd: str) -> bool:
    return is_mem_operand(opnd) and any(reg in ARG_BASE_REGS for reg in regs_in_operand(opnd))


def is_rip_relative(opnd: str) -> bool:
    return is_mem_operand(opnd) and "rip" in opnd.lower()


def is_scaled_index_mem(opnd: str) -> bool:
    return bool(re.search(r"\[[^\]]*\*[248][^\]]*\]", opnd.lower()))


def parse_int(text: str) -> int | None:
    text = text.strip().rstrip(",")
    try:
        if text.lower().startswith("-0x"):
            return -int(text[3:], 16)
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def immediate_constants(text: str) -> list[int]:
    vals: list[int] = []
    for match in re.finditer(r"(?<![A-Za-z_])[-+]?(?:0x[0-9A-Fa-f]+|\d+)\b", text):
        val = parse_int(match.group(0))
        if val is not None:
            vals.append(val)
    return vals


def is_power2(value: int) -> bool:
    value = abs(value)
    return value > 0 and (value & (value - 1)) == 0


def is_call(insn: dict[str, Any]) -> bool:
    return str(insn.get("opcode", "")).startswith("call") or insn.get("kind") == "call"


def is_indirect_control(insn: dict[str, Any]) -> bool:
    operands = insn.get("operands", [])
    if insn.get("target"):
        return False
    if not operands:
        return False
    first = normalize_operand(str(operands[0]))
    return is_mem_operand(first) or bool(re.match(r"^[re]?[abcd]x$|^r(?:[0-9]|1[0-5])$", first))


def mem_read_write_counts(op: str, operands: list[str]) -> tuple[int, int, int, int]:
    mems = [o for o in operands if is_mem_operand(o)]
    if not mems or op.startswith("lea"):
        return 0, 0, 0, 0

    reads = 0
    writes = 0
    stack_writes = 0
    non_stack_writes = 0
    dst = operands[0] if operands else ""

    if op.startswith("pop") and is_mem_operand(dst):
        writes = 1
    elif op.startswith("push"):
        reads = len(mems)
    else:
        write_dst = is_mem_operand(dst) and (
            op.startswith(("mov", "stos"))
            or op
            in {
                "add",
                "sub",
                "and",
                "or",
                "xor",
                "sal",
                "sar",
                "shl",
                "shr",
                "inc",
                "dec",
                "xchg",
            }
            or op.startswith("set")
        )
        read_modify_write = write_dst and not op.startswith(("mov", "set"))
        for mem in mems:
            if mem == dst and write_dst:
                writes += 1
                if read_modify_write:
                    reads += 1
            else:
                reads += 1

    if writes:
        if is_stack_mem(dst):
            stack_writes += writes
        else:
            non_stack_writes += writes
    return reads, writes, stack_writes, non_stack_writes


def zero_region_features(prefix: str = "region_max_") -> dict[str, int]:
    return {f"{prefix}{suffix}": 0 for suffix in REGION_SUFFIXES}


def bool_to_int(value: Any) -> int:
    return int(bool(value))


def block_instruction_map(function: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {insn["address"]: insn for insn in function.get("instructions", [])}


def block_insns(function: dict[str, Any], block: dict[str, Any]) -> list[dict[str, Any]]:
    by_addr = block_instruction_map(function)
    return [by_addr[addr] for addr in block.get("instructions", []) if addr in by_addr]


def edge_kind(function: dict[str, Any], edge: dict[str, Any]) -> str:
    src = edge.get("source") or edge.get("src")
    block = next((b for b in function.get("basic_blocks", []) if b.get("id") == src), None)
    insns = block_insns(function, block) if block else []
    if insns and insns[-1].get("kind") == "conditional":
        return "cond_true" if edge.get("type") == "taken" else "cond_false"
    return "jump"


def cfg_edges(function: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for edge in function.get("cfg_edges", []):
        src = edge.get("source") or edge.get("src")
        dst_addr = edge.get("target_address") or edge.get("target")
        dst = edge.get("target")
        if dst and not str(dst).startswith("bb_"):
            dst = f"bb_{dst}"
        if dst_addr and not dst:
            dst = f"bb_{dst_addr}"
        if src and dst:
            out.append({"src": str(src), "dst": str(dst), "kind": edge_kind(function, edge)})
    return out


def block_incoming_cond(edges: list[dict[str, str]]) -> set[str]:
    return {edge["dst"] for edge in edges if edge["kind"] in {"cond_true", "cond_false"}}


def sets_return_zero(insn: dict[str, Any]) -> bool:
    asm = str(insn.get("asm", "")).lower()
    return bool(re.search(r"\bmov\s+e?ax,0x?0\b", asm) or re.search(r"\bxor\s+[re]?ax,[re]?ax\b", asm))


def sets_return_negative(insn: dict[str, Any]) -> bool:
    asm = str(insn.get("asm", "")).lower()
    return bool(re.search(r"\bmov\s+[re]?ax,-", asm) or "0xffffffff" in asm or "0xffffffffffffffff" in asm)


def terminal_value_markers(function: dict[str, Any], edges: list[dict[str, str]]) -> tuple[int, int]:
    blocks = function.get("basic_blocks", [])
    ret_blocks = {
        block["id"]
        for block in blocks
        if (insns := block_insns(function, block)) and str(insns[-1].get("opcode")) in RETURNS
    }
    jumps_to_ret = {edge["src"] for edge in edges if edge["kind"] == "jump" and edge["dst"] in ret_blocks}
    has_zero = False
    has_neg = False
    for block in blocks:
        insns = block_insns(function, block)
        if not insns:
            continue
        if str(insns[-1].get("opcode")) not in RETURNS and block["id"] not in jumps_to_ret:
            continue
        for insn in insns[-8:]:
            has_zero = has_zero or sets_return_zero(insn)
            has_neg = has_neg or sets_return_negative(insn)
    return int(has_zero), int(has_neg)


def region_features_for_insns(
    insns: list[dict[str, Any]],
    successors: int,
    predecessors: int,
) -> dict[str, int]:
    out = zero_region_features()
    out["region_max_num_instructions"] = len(insns)
    out["region_max_num_successors"] = successors
    out["region_max_num_predecessors"] = predecessors
    for insn in insns:
        op = str(insn.get("opcode", ""))
        operands = [str(x) for x in insn.get("operands", [])]
        reads, writes, stack_writes, non_stack_writes = mem_read_write_counts(op, operands)
        out["region_max_num_mem_reads"] += reads
        out["region_max_num_mem_writes"] += writes
        out["region_max_num_stack_writes"] += stack_writes
        out["region_max_num_non_stack_writes"] += non_stack_writes
        out["region_max_num_rip_relative_accesses"] += sum(1 for o in operands if is_rip_relative(o))
        out["region_max_num_arg_based_mem_accesses"] += sum(1 for o in operands if is_arg_based_mem(o))
        out["region_max_num_scaled_index_memory_accesses"] += sum(1 for o in operands if is_scaled_index_mem(o))
        consts = immediate_constants(str(insn.get("asm", "")))
        out["region_max_num_small_constants"] += sum(1 for v in consts if -16 <= v <= 16)
        out["region_max_num_power2_constants"] += sum(1 for v in consts if is_power2(v))
        out["region_max_has_page_constant_0xfff"] |= int(any(v in {0xFFF, 4095} for v in consts))
        out["region_max_has_page_size_0x1000"] |= int(any(v in {0x1000, 4096} for v in consts))
        out["region_max_has_negative_one"] |= int(-1 in consts)
        out["region_max_num_cmp"] += int(op.startswith("cmp"))
        out["region_max_num_test"] += int(op.startswith("test"))
        out["region_max_num_and_or_xor"] += int(op.startswith(("and", "or", "xor")))
        out["region_max_num_add_sub"] += int(op.startswith(("add", "sub")))
        out["region_max_num_lea"] += int(op.startswith("lea"))
        out["region_max_num_shifts"] += int(op.startswith(("shl", "shr", "sal", "sar")))
        if is_call(insn):
            out["region_max_has_call"] = 1
            out["region_max_num_calls"] += 1
            out["region_max_num_indirect_calls"] += int(is_indirect_control(insn))
        out["region_max_num_cond_jumps"] += int(op in COND_JUMPS or insn.get("kind") == "conditional")
        out["region_max_num_indirect_jumps"] += int(op in UNCOND_JUMPS and is_indirect_control(insn))
        out["region_max_has_return_zero"] |= int(sets_return_zero(insn))
        out["region_max_has_return_negative"] |= int(sets_return_negative(insn))
    out["region_max_has_mem_write"] = int(out["region_max_num_mem_writes"] > 0)
    return out


def max_region_features(function: dict[str, Any], edges: list[dict[str, str]]) -> dict[str, int]:
    blocks = function.get("basic_blocks", [])
    out = zero_region_features()
    succ = Counter(edge["src"] for edge in edges)
    pred = Counter(edge["dst"] for edge in edges)
    for block in blocks:
        features = region_features_for_insns(
            block_insns(function, block),
            succ.get(block["id"], 0),
            pred.get(block["id"], 0),
        )
        for key, value in features.items():
            out[key] = max(out[key], int(value))
    return out


def build_successors(edges: list[dict[str, str]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        out[edge["src"]].append(edge["dst"])
    return out


def branch_region_sets(function: dict[str, Any], edges: list[dict[str, str]]) -> list[set[str]]:
    blocks = function.get("basic_blocks", [])
    block_names = {block["id"] for block in blocks}
    pred = Counter(edge["dst"] for edge in edges)
    succ = build_successors(edges)
    regions: list[set[str]] = []
    for edge in edges:
        if edge["kind"] not in {"cond_true", "cond_false"} or edge["dst"] not in block_names:
            continue
        region = {edge["dst"]}
        stack = [edge["dst"]]
        while stack:
            cur = stack.pop()
            for nxt in succ.get(cur, []):
                if nxt not in block_names or nxt in region or pred.get(nxt, 0) > 1:
                    continue
                region.add(nxt)
                stack.append(nxt)
        regions.append(region)
    return regions


def loop_region_sets(function: dict[str, Any], edges: list[dict[str, str]]) -> list[set[str]]:
    blocks = function.get("basic_blocks", [])
    order = {block["id"]: i for i, block in enumerate(blocks)}
    regions: list[set[str]] = []
    for edge in edges:
        src = edge["src"]
        dst = edge["dst"]
        if src in order and dst in order and order[dst] <= order[src]:
            lo, hi = order[dst], order[src]
            regions.append({block["id"] for block in blocks[lo : hi + 1]})
    return regions


def prefixed_region_max(function: dict[str, Any], edges: list[dict[str, str]], regions: list[set[str]], prefix: str) -> dict[str, int]:
    blocks_by_id = {block["id"]: block for block in function.get("basic_blocks", [])}
    out = {f"{prefix}{suffix}": 0 for suffix in REGION_SUFFIXES}
    for region in regions:
        insns: list[dict[str, Any]] = []
        for block_id in region:
            block = blocks_by_id.get(block_id)
            if block:
                insns.extend(block_insns(function, block))
        succ = sum(1 for edge in edges if edge["src"] in region and edge["dst"] not in region)
        pred = sum(1 for edge in edges if edge["dst"] in region and edge["src"] not in region)
        features = region_features_for_insns(insns, succ, pred)
        for suffix in REGION_SUFFIXES:
            out[f"{prefix}{suffix}"] = max(out[f"{prefix}{suffix}"], int(features[f"region_max_{suffix}"]))
    return out


def extract_binary_features(function: dict[str, Any], feature_names: list[str]) -> dict[str, int]:
    insns = function.get("instructions", [])
    blocks = function.get("basic_blocks", [])
    edges = cfg_edges(function)
    incoming_cond = block_incoming_cond(edges)
    out = {name: 0 for name in feature_names}

    out["num_instructions"] = len(insns)
    out["num_blocks"] = len(blocks)
    out["num_edges"] = len(edges)
    out["has_loop"] = int(bool(loop_region_sets(function, edges)))
    out["num_block_regions"] = len(blocks)
    out["has_block_region"] = int(bool(blocks))

    for insn in insns:
        op = str(insn.get("opcode", ""))
        operands = [str(x) for x in insn.get("operands", [])]
        reads, writes, stack_writes, non_stack_writes = mem_read_write_counts(op, operands)
        out["num_mem_reads"] += reads
        out["num_mem_writes"] += writes
        out["num_stack_writes"] += stack_writes
        out["num_non_stack_writes"] += non_stack_writes
        out["num_rip_relative_accesses"] += sum(1 for o in operands if is_rip_relative(o))
        out["num_arg_based_mem_accesses"] += sum(1 for o in operands if is_arg_based_mem(o))
        out["num_scaled_index_memory_accesses"] += sum(1 for o in operands if is_scaled_index_mem(o))
        consts = immediate_constants(str(insn.get("asm", "")))
        out["num_small_constants"] += sum(1 for v in consts if -16 <= v <= 16)
        out["num_power2_constants"] += sum(1 for v in consts if is_power2(v))
        out["has_page_constant_0xfff"] |= int(any(v in {0xFFF, 4095} for v in consts))
        out["has_page_size_0x1000"] |= int(any(v in {0x1000, 4096} for v in consts))
        out["has_negative_one"] |= int(-1 in consts)
        out["num_cmp"] += int(op.startswith("cmp"))
        out["num_test"] += int(op.startswith("test"))
        out["num_and_or_xor"] += int(op.startswith(("and", "or", "xor")))
        out["num_add_sub"] += int(op.startswith(("add", "sub")))
        out["num_lea"] += int(op.startswith("lea"))
        out["num_shifts"] += int(op.startswith(("shl", "shr", "sal", "sar")))
        if is_call(insn):
            out["num_calls"] += 1
            out["num_indirect_calls"] += int(is_indirect_control(insn))
        out["num_cond_jumps"] += int(op in COND_JUMPS or insn.get("kind") == "conditional")
        out["num_indirect_jumps"] += int(op in UNCOND_JUMPS and is_indirect_control(insn))

    for block in blocks:
        if block["id"] not in incoming_cond:
            continue
        binsns = block_insns(function, block)
        out["has_call_under_branch"] |= int(any(is_call(insn) for insn in binsns))
        out["has_write_under_branch"] |= int(any(mem_read_write_counts(str(insn.get("opcode", "")), [str(x) for x in insn.get("operands", [])])[1] for insn in binsns))

    out["has_return_zero"], out["has_return_negative"] = terminal_value_markers(function, edges)
    out["has_short_error_return"] = int(any(
        block["id"] in incoming_cond
        and len(block_insns(function, block)) <= 4
        and any(sets_return_negative(insn) for insn in block_insns(function, block))
        for block in blocks
    ))
    out["has_jump_table_like_pattern"] = int(
        out["num_indirect_jumps"] > 0
        and out["num_scaled_index_memory_accesses"] > 0
        and out["num_rip_relative_accesses"] > 0
    )

    branch_sets = branch_region_sets(function, edges)
    loop_sets = loop_region_sets(function, edges)
    out["num_branch_regions"] = len(branch_sets)
    out["has_branch_region"] = int(bool(branch_sets))
    out["num_loop_regions"] = len(loop_sets)
    out["has_loop_region"] = int(bool(loop_sets))
    out.update(max_region_features(function, edges))
    out.update(prefixed_region_max(function, edges, branch_sets, "branch_region_max_"))
    out.update(prefixed_region_max(function, edges, loop_sets, "loop_region_max_"))
    return {name: int(out.get(name, 0)) for name in feature_names}


def debug_name_tokens(name: str) -> list[str]:
    parts = re.split(r"[^A-Za-z0-9]+", name)
    tokens: list[str] = []
    for part in parts:
        if not part:
            continue
        tokens.extend(x.lower() for x in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|\d+", part))
    return [tok for tok in tokens if tok]


def extract_debug_name_features(name: str) -> dict[str, int]:
    tokens = debug_name_tokens(name)
    token_set = set(tokens)
    out: dict[str, int] = {feature: 0 for feature in DEBUG_NAME_SHAPE_FEATURES + DEBUG_NAME_TOKEN_FEATURES + DEBUG_NAME_HASH_BUCKET_FEATURES}
    out["debug_name_length"] = len(name)
    out["debug_name_num_tokens"] = len(tokens)
    out["debug_name_num_underscores"] = name.count("_")
    out["debug_name_has_digit"] = int(any(ch.isdigit() for ch in name))
    out["debug_name_has_plt_suffix"] = int("@plt" in name)
    for feature in DEBUG_NAME_TOKEN_FEATURES:
        tok = feature.removeprefix("debug_name_tok_")
        out[feature] = int(tok in token_set)
    for tok in tokens:
        digest = hashlib.sha256(tok.encode("utf-8")).digest()
        bucket = int.from_bytes(digest[:2], "big") % 64
        out[f"debug_name_token_hash_bucket_{bucket:02d}"] += 1
    return out


def split_rows(rows: list[dict[str, Any]]) -> None:
    groups: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[(row["target_id"], int(row["worth_attack"]))].append(row)

    for group_rows in groups.values():
        group_rows.sort(key=lambda r: hashlib.sha256(str(r["sample_id"]).encode("utf-8")).hexdigest())
        n = len(group_rows)
        if n == 1:
            cuts = ("train",)
        elif n == 2:
            cuts = ("train", "test")
        else:
            n_train = max(1, math.floor(n * 0.6))
            n_val = max(1, math.floor(n * 0.2))
            if n_train + n_val >= n:
                n_train = n - 2
                n_val = 1
            cuts = tuple(["train"] * n_train + ["validation"] * n_val + ["test"] * (n - n_train - n_val))
        for row, split in zip(group_rows, cuts):
            row["split"] = split


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]], feature_names: list[str]) -> None:
    fields = META_FIELDS + feature_names
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            flat = {field: row.get(field, "") for field in META_FIELDS}
            flat.update({name: int(row["features"].get(name, 0)) for name in feature_names})
            writer.writerow(flat)


def main() -> int:
    strict_features = read_json(STRICT_FEATURE_LIST)["ordered_feature_names"]
    debug_features = read_json(DEBUG_FEATURE_LIST)["ordered_feature_names"]
    cfg_cache = {target_id: load_cfg_sources(target_id) for target_id in TARGET_TO_TITLE}
    dwarf_cache = {target_id: load_dwarf_sources(target_id) for target_id in TARGET_TO_TITLE}

    rows: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for line in CURATED_SINKS_JSONL.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        target_id = rec["target_id"]
        cfg_sources = cfg_cache[target_id]
        function, method = resolve_positive_function(rec, merged_cfg_names(cfg_sources))
        source_name, function_cfg = find_cfg_function(cfg_sources, function) if function else (None, None)
        if not function or function_cfg is None:
            skipped.append(
                {
                    "candidate_id": rec["candidate_id"],
                    "target_id": target_id,
                    "worth_attack": 1,
                    "reason": method,
                    "sink_summary": rec["curation"]["sink_summary"],
                }
            )
            continue
        if source_name and source_name != "primary":
            method = f"{method}:{source_name}"
        features = extract_binary_features(function_cfg, strict_features)
        features.update(extract_debug_name_features(function))
        rows.append(
            {
                "sample_id": f"{target_id}:pos:{rec['candidate_id'].split(':', 1)[1]}",
                "target_id": target_id,
                "program_name": rec["program_name"],
                "function": function,
                "worth_attack": 1,
                "label_source": "curated_sink",
                "split": "",
                "resolution_method": method,
                "candidate_id": rec["candidate_id"],
                "features": features,
            }
        )

    for rec in parse_non_sinks():
        target_id = rec["target_id"]
        function = rec["function"]
        cfg_sources = cfg_cache[target_id]
        source_name, function_cfg = find_cfg_function(cfg_sources, function)
        if function_cfg is None or not has_dwarf_name(dwarf_cache[target_id], function):
            skipped.append(
                {
                    "candidate_id": "",
                    "target_id": target_id,
                    "function": function,
                    "worth_attack": 0,
                    "reason": "non_sink_missing_from_cfg_or_dwarf",
                }
            )
            continue
        features = extract_binary_features(function_cfg, strict_features)
        features.update(extract_debug_name_features(function))
        rec["sample_id"] = f"{target_id}:neg:{function}"
        rec["split"] = ""
        rec["features"] = features
        rows.append(rec)

    rows.sort(key=lambda r: (r["target_id"], int(r["worth_attack"]), r["sample_id"]))
    split_rows(rows)

    OUT_SPLIT_DIR.mkdir(parents=True, exist_ok=True)
    write_jsonl(OUT_JSONL, rows)
    write_jsonl(OUT_SKIPPED, skipped)
    write_csv(OUT_STRICT_CSV, rows, strict_features)
    write_csv(OUT_DEBUG_CSV, rows, debug_features)
    for split in ("train", "validation", "test"):
        split_rows_only = [row for row in rows if row["split"] == split]
        write_csv(OUT_SPLIT_DIR / f"{split}_binary_only.csv", split_rows_only, strict_features)
        write_csv(OUT_SPLIT_DIR / f"{split}_debug_names.csv", split_rows_only, debug_features)

    manifest = {
        "schema": "dfb-curated-function-feature-dataset/v1",
        "sample_unit": "function",
        "label": {"worth_attack": {"sink": 1, "non_sink": 0}},
        "feature_profiles": {
            "binary_only": {
                "feature_count": len(strict_features),
                "csv": OUT_STRICT_CSV.relative_to(ROOT).as_posix(),
                "split_csvs": {
                    split: (OUT_SPLIT_DIR / f"{split}_binary_only.csv").relative_to(ROOT).as_posix()
                    for split in ("train", "validation", "test")
                },
            },
            "debug_names": {
                "feature_count": len(debug_features),
                "csv": OUT_DEBUG_CSV.relative_to(ROOT).as_posix(),
                "split_csvs": {
                    split: (OUT_SPLIT_DIR / f"{split}_debug_names.csv").relative_to(ROOT).as_posix()
                    for split in ("train", "validation", "test")
                },
            },
        },
        "rows": {
            "total": len(rows),
            "positives": sum(1 for row in rows if row["worth_attack"] == 1),
            "negatives": sum(1 for row in rows if row["worth_attack"] == 0),
            "skipped": len(skipped),
            "by_split": Counter(row["split"] for row in rows),
            "by_split_and_label": Counter(f"{row['split']}:label_{row['worth_attack']}" for row in rows),
            "by_target_and_label": Counter(f"{row['target_id']}:label_{row['worth_attack']}" for row in rows),
        },
        "inputs": {
            "positive_labels": CURATED_SINKS_JSONL.relative_to(ROOT).as_posix(),
            "negative_labels": CURATED_NON_SINKS_MD.relative_to(ROOT).as_posix(),
            "strict_feature_list": STRICT_FEATURE_LIST.relative_to(ROOT).as_posix(),
            "debug_feature_list": DEBUG_FEATURE_LIST.relative_to(ROOT).as_posix(),
            "auxiliary_stage02_artifacts": {
                target_id: [
                    {"name": name, "stage02_dir": stage02_dir.relative_to(ROOT).as_posix()}
                    for name, stage02_dir in stage02_dirs
                    if (stage02_dir / "nginx_cfg.json").exists()
                ]
                for target_id, stage02_dirs in AUXILIARY_STAGE02_DIRS.items()
            },
        },
        "skipped_jsonl": OUT_SKIPPED.relative_to(ROOT).as_posix(),
    }
    OUT_MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    OUT_README.write_text(
        "\n".join(
            [
                "# Curated Function Feature Dataset",
                "",
                "Binary/debug-info function-level dataset built from curated sink and non-sink labels.",
                "",
                f"- Rows: {len(rows)}",
                f"- Positives: {manifest['rows']['positives']}",
                f"- Negatives: {manifest['rows']['negatives']}",
                f"- Skipped unresolved labels: {len(skipped)}",
                f"- Binary-only features: {len(strict_features)}",
                f"- Debug-name augmented features: {len(debug_features)}",
                "",
                "## Splits",
                "",
                "| Split | Rows | Positives | Negatives |",
                "| --- | ---: | ---: | ---: |",
            ]
            + [
                f"| {split} | {sum(1 for row in rows if row['split'] == split)} | "
                f"{sum(1 for row in rows if row['split'] == split and row['worth_attack'] == 1)} | "
                f"{sum(1 for row in rows if row['split'] == split and row['worth_attack'] == 0)} |"
                for split in ("train", "validation", "test")
            ]
            + [
                "",
                "## Outputs",
                "",
                f"- `{OUT_JSONL.relative_to(ROOT).as_posix()}`",
                f"- `{OUT_STRICT_CSV.relative_to(ROOT).as_posix()}`",
                f"- `{OUT_DEBUG_CSV.relative_to(ROOT).as_posix()}`",
                f"- `{OUT_MANIFEST.relative_to(ROOT).as_posix()}`",
                f"- `{OUT_SKIPPED.relative_to(ROOT).as_posix()}`",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    print(json.dumps(manifest["rows"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
