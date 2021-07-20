# IDA Python script to annotate all eBPF call instructions
# which call eBPF helpers with the helper function's name
# Developed against Python3 and IDA 7.6

# started with the instruction enumeration example from the IDA Book

from idaapi import *
import idautils
import idc

# 'manually' crafted from include/uapi/linux/bpf.h header from kernel v5.13
# will need to periodically update this as new helpers are added.
#
# run just the preprocessor (gcc -E) on the snippet defining the `bpf_func_id` enum,
# then format the names into an array, preserving order (some search/replace in vim)
# this makes the `helper_names` array, which we then use for everything else.
# It's critical the order of names is not changed from how they appear in the processed
# source, because enums assign integer values in order.

helper_names = [ "BPF_FUNC_unspec", "map_lookup_elem", "map_update_elem", "map_delete_elem", "probe_read", "ktime_get_ns", "trace_printk", "get_prandom_u32", "get_smp_processor_id", "skb_store_bytes", "l3_csum_replace", "l4_csum_replace", "tail_call", "clone_redirect", "get_current_pid_tgid", "get_current_uid_gid", "get_current_comm", "get_cgroup_classid", "skb_vlan_push", "skb_vlan_pop", "skb_get_tunnel_key", "skb_set_tunnel_key", "perf_event_read", "redirect", "get_route_realm", "perf_event_output", "skb_load_bytes", "get_stackid", "csum_diff", "skb_get_tunnel_opt", "skb_set_tunnel_opt", "skb_change_proto", "skb_change_type", "skb_under_cgroup", "get_hash_recalc", "get_current_task", "probe_write_user", "current_task_under_cgroup", "skb_change_tail", "skb_pull_data", "csum_update", "set_hash_invalid", "get_numa_node_id", "skb_change_head", "xdp_adjust_head", "probe_read_str", "get_socket_cookie", "get_socket_uid", "set_hash", "setsockopt", "skb_adjust_room", "redirect_map", "sk_redirect_map", "sock_map_update", "xdp_adjust_meta", "perf_event_read_value", "perf_prog_read_value", "getsockopt", "override_return", "sock_ops_cb_flags_set", "msg_redirect_map", "msg_apply_bytes", "msg_cork_bytes", "msg_pull_data", "bind", "xdp_adjust_tail", "skb_get_xfrm_state", "get_stack", "skb_load_bytes_relative", "fib_lookup", "sock_hash_update", "msg_redirect_hash", "sk_redirect_hash", "lwt_push_encap", "lwt_seg6_store_bytes", "lwt_seg6_adjust_srh", "lwt_seg6_action", "rc_repeat", "rc_keydown", "skb_cgroup_id", "get_current_cgroup_id", "get_local_storage", "sk_select_reuseport", "skb_ancestor_cgroup_id", "sk_lookup_tcp", "sk_lookup_udp", "sk_release", "map_push_elem", "map_pop_elem", "map_peek_elem", "msg_push_data", "msg_pop_data", "rc_pointer_rel", "spin_lock", "spin_unlock", "sk_fullsock", "tcp_sock", "skb_ecn_set_ce", "get_listener_sock", "skc_lookup_tcp", "tcp_check_syncookie", "sysctl_get_name", "sysctl_get_current_value", "sysctl_get_new_value", "sysctl_set_new_value", "strtol", "strtoul", "sk_storage_get", "sk_storage_delete", "send_signal", "tcp_gen_syncookie", "skb_output", "probe_read_user", "probe_read_kernel", "probe_read_user_str", "probe_read_kernel_str", "tcp_send_ack", "send_signal_thread", "jiffies64", "read_branch_records", "get_ns_current_pid_tgid", "xdp_output", "get_netns_cookie", "get_current_ancestor_cgroup_id", "sk_assign", "ktime_get_boot_ns", "seq_printf", "seq_write", "sk_cgroup_id", "sk_ancestor_cgroup_id", "ringbuf_output", "ringbuf_reserve", "ringbuf_submit", "ringbuf_discard", "ringbuf_query", "csum_level", "skc_to_tcp6_sock", "skc_to_tcp_sock", "skc_to_tcp_timewait_sock", "skc_to_tcp_request_sock", "skc_to_udp6_sock", "get_task_stack", "load_hdr_opt", "store_hdr_opt", "reserve_hdr_opt", "inode_storage_get", "inode_storage_delete", "d_path", "copy_from_user", "snprintf_btf", "seq_printf_btf", "skb_cgroup_classid", "redirect_neigh", "per_cpu_ptr", "this_cpu_ptr", "redirect_peer", "task_storage_get", "task_storage_delete", "get_current_task_btf", "bprm_opts_set", "ktime_get_coarse_ns", "ima_inode_hash", "sock_from_file", "check_mtu", "for_each_map_elem", "snprintf", "__BPF_FUNC_MAX_ID" ]

helper_id_to_name = {i: helper_names[i] for i in range(len(helper_names))}

def dump_helpers():
    print("bpf helpers id -> name")
    for k, v in helper_id_to_name.items():
        print(f"{k} -> {v}")

def lookup_helper(helper_id: int) -> str :
    return helper_id_to_name[helper_id]

print("Scanning all known function instructions for eBPF helper call instructions")
for ea in Functions():
    func = get_func(ea)
    func_name = ida_funcs.get_func_name(func.start_ea)
    print(f"scanning function: {func_name}")
    if func:
        for i in FuncItems(func.start_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, i):
                feature = insn.get_canon_feature()
                if feature & CF_CALL:
                    # TODO: check that we're a helper call, not a bpf tail call
                    try:
                        helper_name = lookup_helper(insn[0].value)
                    except KeyError:
                        helper_name = "UNKONWN. Update list of helpers"
                        Warning(f"Unknown eBPF helper {insn[0].value:#x}. You need to update the processor's list of helper functions using a newer Linux kernel source (include/uapi/linux/bpf.h).")

                    print(f"\tcall detected: {i:#8x} -> {helper_name}")
                    idc.set_cmt(i, helper_name, False)
