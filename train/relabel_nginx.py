#!/usr/bin/env python3
"""Apply SINK_LABELING_STANDARD v1 to nginx: re-label from handler granularity to
the concrete effect-issuing granularity used by the other programs. Then swap
nginx's rows in the integrated dataset and we re-test its LOPO recall.

POS = concrete effect/decision functions (audited per standard §3/§4).
NEG = demoted handlers/dispatch/output + self-cleanup + prior negatives.
"""
import csv, json, sys
from pathlib import Path
SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import build_curated_function_feature_dataset as B
import build_integrated_dataset as I

TGT = "nginx_1_4_0_validation"

# concrete effect-issuing / decision functions (standard §3 granularity)
POS = [
 # exec
 "ngx_execute_proc","ngx_execute","ngx_exec_new_binary",
 # privilege / capability
 "ngx_worker_process_init",
 # network endpoint
 "ngx_open_listening_sockets",
 # file effects on attacker-influenced paths (cache/temp/upload/serve)
 "ngx_copy_file","ngx_create_temp_file","ngx_ext_rename_file","ngx_create_file_mapping",
 "ngx_write_chain_to_temp_file","ngx_event_pipe_write_chain_to_temp_file",
 "ngx_http_write_request_body","ngx_http_file_cache_update","ngx_http_file_cache_delete_file",
 "ngx_create_path","ngx_create_full_path","ngx_create_paths",
 # authz decision (reads htpasswd + decides)
 "ngx_http_auth_basic_handler",
]

# explicitly demoted (were handler-level positives) -> negative
DEMOTE = [
 "ngx_http_memcached_handler","ngx_http_upstream_process_upgraded","ngx_http_upstream_send_request",
 "ngx_http_uwsgi_create_request","ngx_http_scgi_create_request","ngx_http_fastcgi_create_request",
 "ngx_http_log_write","ngx_start_cache_manager_processes","ngx_http_header_filter",
 "ngx_http_upstream_process_downstream","ngx_http_upstream_process_non_buffered_request",
 "ngx_http_send_response","ngx_http_cache_send","ngx_http_fastcgi_handler","ngx_http_scgi_handler",
 "ngx_http_uwsgi_handler","ngx_http_map_uri_to_path","ngx_http_access_handler",
 "ngx_http_core_find_location","ngx_http_internal_redirect","ngx_http_named_location",
 "ngx_http_set_virtual_server","ngx_http_memcached_create_request","ngx_event_accept",
 "ngx_configure_listening_sockets","ngx_start_worker_processes","ngx_master_process_cycle",
 "ngx_create_pidfile","ngx_delete_pidfile","ngx_init_cycle","ngx_conf_parse",
]


def main():
    csv_path = B.ML_DATASET/"integrated_function_features.csv"
    lines = csv_path.read_text().splitlines()
    header = lines[0]
    # current nginx negatives (keep as neg)
    cur_neg = [l.split(",")[1] for l in lines[1:]
               if l.startswith(TGT+",") and l.split(",")[2]=="0"]
    neg = sorted(set(cur_neg) | set(DEMOTE))
    pos = POS

    cfg_cache = {TGT: B.load_cfg_sources(TGT)}
    cols = I.STRICT + I.EFF_COLS + I.REACH_COLS + I.ST_COLS
    out, miss = [], []
    for label, fns in ((1,pos),(0,neg)):
        for fn in fns:
            f = I.feats(TGT, fn, cfg_cache)
            if f is None: miss.append((label,fn)); continue
            out.append([TGT,fn,label]+[f[k] for k in cols])
    seen=set()
    dedup=[]
    for r in out:                      # function appears once (pos wins)
        if r[1] in seen: continue
        seen.add(r[1]); dedup.append(r)
    keep = [header] + [l for l in lines[1:] if not l.startswith(TGT+",")]
    with csv_path.open("w", newline="") as fh:
        fh.write("\n".join(keep)+"\n")
        w=csv.writer(fh)
        for r in dedup: w.writerow(r)
    np=sum(1 for r in dedup if r[2]==1); nn=sum(1 for r in dedup if r[2]==0)
    print(f"nginx re-labeled: {np} pos / {nn} neg (was 68 pos / 24 neg)")
    print(f"unresolved (not in cfg/dwarf): {miss}")


if __name__=="__main__":
    main()
