#!/usr/bin/env python3
"""Append extra hand-labeled programs (HTTP siblings for nginx) to the integrated
dataset. Idempotent: removes prior rows for these programs before appending.
Run AFTER build_integrated_dataset.py.
"""
import csv, json, sys
from pathlib import Path
SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import build_curated_function_feature_dataset as B
import build_integrated_dataset as I

LABELS = {
 "thttpd_2_29": {
  "pos": ["cgi_child","cgi","make_envp","make_argp","build_env","auth_check","auth_check2",
          "really_start_request","httpd_start_request","mmc_map","really_check_referrer",
          "check_referrer","main"],
  "neg": ["httpd_parse_request","de_dotdot","expand_symlinks","figure_mime","init_mime",
          "b64_decode","strdecode","strencode","hexit","defang","my_snprintf","httpd_realloc_str",
          "bufgets","tdate_parse","match","match_one","ext_compare","name_compare","add_hash",
          "find_hash","check_hash_size","httpd_method_str","httpd_ntoa","send_mime","add_response",
          "make_log_entry","tmr_create","tmr_run","tmr_timeout","fdwatch_add_fd","poll_add_fd",
          "scan_mon","scan_wday"],
 },
 "lighttpd_1_4_59": {
  "pos": ["fdevent_fork_execve","gw_spawn_connection","server_main_setup","plugins_load",
          "server_graceful_state_bg","fdevent_rename","main","chunkqueue_append_file_fd",
          "chunkqueue_append_file","chunk_open_file_chunk","chunkqueue_open_file_chunk",
          "chunkqueue_get_append_tempfile","chunkqueue_append_mem_to_tempfile","http_auth_match_rules",
          "http_auth_backend_get","http_auth_const_time_memeq","http_auth_setenv","connection_handle_write",
          "chunkqueue_write_chunk","connection_handle_response_end_state","network_server_init",
          "http_chunk_append_file","http_chunk_append_file_fd","http_chunk_append_file_ref"],
  "neg": ["http_request_parse","http_request_parse_header","http_request_parse_headers",
          "http_request_parse_reqline","http_request_parse_target","http_request_host_normalize",
          "buffer_append_string","buffer_copy_string","buffer_init","buffer_free","array_get_element_klen",
          "array_insert_value","array_init","config_insert","config_check_cond","stat_cache_get_entry",
          "request_check_hostname","http_chunk_append_buffer","burl_normalize","splaytree_splay",
          "fdevent_init","fdevent_poll","log_error","http_status_append","sock_addr_inet_ntop",
          "data_string_init","data_integer_init"],
 },
}


def main():
    cols = I.STRICT + I.EFF_COLS + I.REACH_COLS + I.ST_COLS
    csv_path = B.ML_DATASET / "integrated_function_features.csv"
    existing = csv_path.read_text().splitlines()
    keep = [existing[0]] + [l for l in existing[1:]
                            if not any(l.startswith(t+",") for t in LABELS)]
    all_rows = []
    for tgt, lab in LABELS.items():
        stage02 = B.PROGRAM_TARGETS / tgt / "artifacts" / "stage_02_static_ir_cfg"
        cfg = B.load_cfg_functions_from_dir(stage02)
        dw = {v["name"] for v in json.loads((stage02/"dwarf_facts.json").read_text())["functions"].values()
              if isinstance(v,dict) and v.get("name")}
        npos = nneg = 0
        for label, fns in ((1,lab["pos"]),(0,lab["neg"])):
            for fn in fns:
                if fn not in cfg or fn not in dw: continue
                f = B.extract_binary_features(cfg[fn], I.STRICT)
                f.update(I.eff_feats(tgt,fn))
                f.update(I.reach_feats(tgt,fn)); f.update(I.st_feats(tgt,fn))
                all_rows.append([tgt,fn,label]+[f[k] for k in cols])
                if label: npos+=1
                else: nneg+=1
        print(f"{tgt:18s} +{npos} pos / +{nneg} neg")
    with csv_path.open("w", newline="") as fh:
        fh.write("\n".join(keep)+"\n")
        w=csv.writer(fh)
        for r in all_rows: w.writerow(r)
    print(f"total extra rows: {len(all_rows)}")


if __name__=="__main__":
    main()
