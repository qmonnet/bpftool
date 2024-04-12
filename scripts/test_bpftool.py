# This is a test file for bpftool's bash completion.
#
# Usage:
#
#   $ git clone https://github.com/scop/bash-completion.git
#   $ cd bash-completion
#   $ cp /.../bpftool/bash-completion/bpftool bash-completion/completions/
#   $ cp /.../bpftool/scripts/test_bpftool.py test/t/
#   $ pytest-3 -k test_bpftool -vv test/t

import pytest
from conftest import assert_bash_exec
import os, re, psutil, random


class TestBpftool:

    # Helpers

    def is_root(self):
        return os.getuid() == 0

    def all_ints(self, completion):
        # If non-root, list should be empty
        if not self.is_root():
            return True if not completion else False

        # Else, assume we've set up at least one object with id
        if not completion:
            return False
        for id in completion:
            if not id.isdigit():
                return False
        return True

    def all_tags(self, completion):
        # If non-root, completion should be empty
        if not self.is_root():
            return True if not completion else False

        # Else, assume we've set up at least one object with tag
        if not completion:
            return False
        for tag in completion:
            if not re.match(r"[a-f0-9]{16}$", tag):
                return False
        return True

    def all_paths(self, completion):
        for path in completion:
            if not os.path.exists(path):
                return False
        return True

    commands = [
            "batch",
            "btf",
            "cgroup",
            "feature",
            "gen",
            "help",
            "iter",
            "link",
            "map",
            "net",
            "perf",
            "prog",
            "struct_ops",
    ]

    longopts = [
            "--base-btf",
            "--bpffs",
            "--debug",
            "--json",
            "--mapcompat",
            "--pretty",
            "--use-loader",
            "--version",
    ]

    map_types = [
            "array",
            "array_of_maps",
            "bloom_filter",
            "cgroup_array",
            "cgroup_storage",
            "cgrp_storage",
            "cpumap",
            "devmap",
            "devmap_hash",
            "hash",
            "hash_of_maps",
            "inode_storage",
            "lpm_trie",
            "lru_hash",
            "lru_percpu_hash",
            "percpu_array",
            "percpu_cgroup_storage",
            "percpu_hash",
            "perf_event_array",
            "prog_array",
            "queue",
            "reuseport_sockarray",
            "ringbuf",
            "sk_storage",
            "sockhash",
            "sockmap",
            "stack",
            "stack_trace",
            "struct_ops",
            "task_storage",
            "user_ringbuf",
            "xskmap",
    ]

    prog_types = [
            "action",
            "cgroup/bind4",
            "cgroup/bind6",
            "cgroup/connect4",
            "cgroup/connect6",
            "cgroup/dev",
            "cgroup/getpeername4",
            "cgroup/getpeername6",
            "cgroup/getsockname4",
            "cgroup/getsockname6",
            "cgroup/getsockopt",
            "cgroup/post_bind4",
            "cgroup/post_bind6",
            "cgroup/recvmsg4",
            "cgroup/recvmsg6",
            "cgroup/sendmsg4",
            "cgroup/sendmsg6",
            "cgroup/setsockopt",
            "cgroup/skb",
            "cgroup/sock",
            "cgroup/sock_release",
            "cgroup/sysctl",
            "classifier",
            "fentry",
            "fexit",
            "flow_dissector",
            "freplace",
            "kprobe",
            "kretprobe",
            "lirc_mode2",
            "lwt_in",
            "lwt_out",
            "lwt_seg6local",
            "lwt_xmit",
            "perf_event",
            "raw_tracepoint",
            "sk_lookup",
            "sk_msg",
            "sk_skb",
            "socket",
            "sockops",
            "struct_ops",
            "tracepoint",
            "xdp",
    ]

    prog_attach_types = [
            "flow_dissector",
            "sk_msg_verdict",
            "sk_skb_stream_parser",
            "sk_skb_stream_verdict",
            "sk_skb_verdict",
    ]

    cgroup_attach_types = [
            "cgroup_device",
            "cgroup_getsockopt",
            "cgroup_inet4_bind",
            "cgroup_inet4_connect",
            "cgroup_inet4_getpeername",
            "cgroup_inet4_getsockname",
            "cgroup_inet4_post_bind",
            "cgroup_inet6_bind",
            "cgroup_inet6_connect",
            "cgroup_inet6_getpeername",
            "cgroup_inet6_getsockname",
            "cgroup_inet6_post_bind",
            "cgroup_inet_egress",
            "cgroup_inet_ingress",
            "cgroup_inet_sock_create",
            "cgroup_inet_sock_release",
            "cgroup_setsockopt",
            "cgroup_sock_ops",
            "cgroup_sysctl",
            "cgroup_udp4_recvmsg",
            "cgroup_udp4_sendmsg",
            "cgroup_udp6_recvmsg",
            "cgroup_udp6_sendmsg",
    ]

    # Fixtures

    @pytest.fixture(scope="class")
    def ifnames(self):
        return list(psutil.net_if_addrs().keys())

    @pytest.fixture(scope="class")
    def get_objfile(self, bash):
        src_file = "/tmp/bash_comp_test.c"
        obj_file = "/tmp/bash_comp_test.o"
        map_name = "bash_comp_map"
        prog_name = "bash_comp_test"
        f = open(src_file, "w")
        f.write(f"""
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
}} {map_name} SEC(".maps");

int SEC("tracepoint/syscalls/sys_enter_open")
{prog_name}(__attribute__((unused)) void *ctx)
{{
	__u32 key = 0;
	__u32 *value;

	value = bpf_map_lookup_elem(&{map_name}, &key);
	if (!value)
		return 0;

	return *value;
}}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
""")
        f.close()

        assert_bash_exec(
                bash,
                f"clang -g -O2 -fno-asynchronous-unwind-tables -emit-llvm " \
                        f"-c {src_file} -o - | " \
                        f"llc -march=bpf -mcpu=probe -filetype=obj -o {obj_file}",
        )

        yield {
                "path": obj_file,
                "map_name": map_name,
                "prog_name": prog_name,
        }
        try:
            # May fail, I think when distributing the load to multiple CPUs
            # there may be several runs of the fixture.
            os.remove(obj_file)
            os.remove(src_file)
        except:
            pass

    @pytest.fixture(scope="class")
    def get_bpf_link(self, bash, get_objfile):
        if not self.is_root():
            return { "id": None }

        objfile = get_objfile
        obj_path = objfile["path"]
        prog_name = objfile["prog_name"]
        rand = random.randint(1000, 9999)
        link = f"/sys/fs/bpf/{prog_name}-{rand}"

        assert_bash_exec(
                bash,
                f"bpftool prog load {obj_path} {link} autoattach"
        )
        id = assert_bash_exec(
                bash,
                # For each link, hold line with id, go through the list of
                # pinned paths, if we find ours then swap pattern and hold
                # spaces, extract and print id, then quit.
                "bpftool -f link show | sed -n '/^[0-9]\\+:/{{h;b}}; " \
                        f"\\@{link}@ {{x;s/^\\([0-9]\\+\\):.*/\\1/p;q}}'",
                want_output = True
        ).strip()

        yield {
                "path": link,
                "id": id,
        }
        os.remove(link)

    # bpftool and options

    @pytest.mark.complete("bpftool ", require_cmd=True)
    def test_basic(self, completion):
        assert completion == self.commands

    @pytest.mark.complete("bpftool -")
    def test_dash(self, completion):
        assert completion == self.longopts

    @pytest.mark.complete("bpftool --")
    def test_double_dash(self, completion):
        assert completion == self.longopts

    @pytest.mark.complete("bpftool -j")
    def test_json_short(self, completion):
        """Option -j is complete, no completion returned"""
        assert not completion

    @pytest.mark.complete("bpftool --js")
    def test_json(self, completion):
        assert completion == "on"

    @pytest.mark.complete("bpftool --deb")
    def test_debug(self, completion):
        assert completion == "ug"

    @pytest.mark.complete("bpftool --debug -j --version -p -d ", require_cmd=True)
    def test_many_options(self, completion):
        assert completion == self.commands

    @pytest.mark.complete("bpftool --json net ")
    def test_opt_cmd(self, completion):
        assert completion == "attach detach help list show".split()

    @pytest.mark.complete("bpftool net --debug ")
    def test_cmd_opt(self, completion):
        assert completion == "attach detach help list show".split()

    # bpftool btf

    @pytest.mark.complete("bpftool btf ")
    def test_btf(self, completion):
        assert completion == "dump help list show".split()

    @pytest.mark.complete("bpftool btf help ")
    def test_btf_help(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool btf list ")
    def test_btf_list(self, completion):
        assert completion == "id"

    @pytest.mark.complete("bpftool btf show ")
    def test_btf_show(self, completion):
        assert completion == "id"

    @pytest.mark.complete("bpftool btf show id ")
    def test_btf_show_id(self, completion):
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool btf show id 1 ")
    def test_btf_show_id_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool btf dump ")
    def test_btf_dump(self, completion):
        assert completion == "file id map prog".split()

    @pytest.mark.complete("bpftool btf dump id ")
    def test_btf_dump_id(self, completion):
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool btf dump prog ")
    def test_btf_dump_prog(self, completion):
        assert completion == "id name pinned tag".split()

    @pytest.mark.complete("bpftool btf dump prog id ")
    def test_btf_dump_prog_id(self, completion):
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool btf dump prog id 1 ")
    def test_btf_dump_prog_id_xxx(self, completion):
        assert completion == "format"

    @pytest.mark.complete("bpftool btf dump prog name ")
    def test_btf_dump_prog_name(self, completion):
        assert completion

    @pytest.mark.complete("bpftool btf dump prog name some_name ")
    def test_btf_dump_prog_name_xxx(self, completion):
        assert completion == "format"

    @pytest.mark.complete("bpftool btf dump prog pinned ")
    def test_btf_dump_prog_pinned(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool btf dump prog pinned /some_map ")
    def test_btf_dump_prog_pinned_xxx(self, completion):
        assert completion == "format"

    @pytest.mark.complete("bpftool btf dump prog tag ")
    def test_btf_dump_prog_tag(self, completion):
        assert self.all_tags(completion)

    @pytest.mark.complete("bpftool btf dump prog tag some_tag ")
    def test_btf_dump_prog_tag_xxx(self, completion):
        assert completion == "format"

    @pytest.mark.complete("bpftool btf dump map ")
    def test_btf_dump_map(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool btf dump map id ")
    def test_btf_dump_map_id(self, completion):
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool btf dump map id 1 ")
    def test_btf_dump_map_id_xxx(self, completion):
        assert completion == "all format key kv value".split()

    @pytest.mark.complete("bpftool btf dump map pinned ")
    def test_btf_dump_map_pinned(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool btf dump map pinned /some_prog ")
    def test_btf_dump_map_pinned_xxx(self, completion):
        assert completion == "all format key kv value".split()

    @pytest.mark.complete("bpftool btf dump map id 1 key ")
    def test_btf_dump_map_id_xxx_key(self, completion):
        assert completion == "format"

    @pytest.mark.complete("bpftool btf dump map id 1 value ")
    def test_btf_dump_map_id_xxx_value(self, completion):
        assert completion == "format"

    @pytest.mark.complete("bpftool btf dump map id 1 kv ")
    def test_btf_dump_map_id_xxx_kv(self, completion):
        assert completion == "format"

    @pytest.mark.complete("bpftool btf dump map id 1 all ")
    def test_btf_dump_map_id_xxx_all(self, completion):
        assert completion == "format"

    @pytest.mark.complete("bpftool btf dump file ")
    def test_btf_dump_file(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool btf dump file format ")
    def test_btf_dump_file_format(self, completion):
        assert completion == "c raw".split()

    @pytest.mark.complete("bpftool btf dump file format raw ")
    def test_btf_dump_file_format_raw(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool btf dump file format c ")
    def test_btf_dump_file_format_c(self, completion):
        assert not completion

    # bpftool cgroup

    @pytest.mark.complete("bpftool cgroup ")
    def test_cgroup(self, completion):
        assert completion == "attach detach help list show tree".split()

    @pytest.mark.complete("bpftool cgroup help ")
    def test_cgroup_help(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool cgroup list ")
    def test_cgroup_list(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool cgroup show ")
    def test_cgroup_show(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool cgroup show /some_cgroup ")
    def test_cgroup_show_xxx(self, completion):
        assert completion == "effective"

    @pytest.mark.complete("bpftool cgroup show /some_cgroup effective ")
    def test_cgroup_show_xxx_effective(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool cgroup tree ")
    def test_cgroup_tree(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool cgroup tree /some_cgroup_root ")
    def test_cgroup_tree_xxx(self, completion):
        assert completion == "effective"

    @pytest.mark.complete("bpftool cgroup tree /some_cgroup_root effective ")
    def test_cgroup_tree_xxx_effective(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool cgroup attach ")
    def test_cgroup_attach(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool cgroup attach /some_cgroup ")
    def test_cgroup_attach_xxx(self, completion):
        assert completion == self.cgroup_attach_types

    @pytest.mark.complete("bpftool cgroup attach /some_cgroup cgroup_inet_ingress ")
    def test_cgroup_attach_xxx_type(self, completion):
        assert completion == "id name pinned tag".split()

    @pytest.mark.complete("bpftool cgroup attach /some_cgroup cgroup_inet_ingress id ")
    def test_cgroup_attach_xxx_type_id(self, completion):
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool cgroup attach /some_cgroup cgroup_inet_ingress id 1 ")
    def test_cgroup_attach_xxx_type_id_xxx(self, completion):
        assert completion == "multi override".split()

    @pytest.mark.complete("bpftool cgroup attach /some_cgroup cgroup_inet_ingress name ")
    def test_cgroup_attach_xxx_type_name(self, completion):
        assert completion

    @pytest.mark.complete("bpftool cgroup attach /some_cgroup cgroup_inet_ingress name some_name ")
    def test_cgroup_attach_xxx_type_name_xxx(self, completion):
        assert completion == "multi override".split()

    @pytest.mark.complete("bpftool cgroup attach /some_cgroup cgroup_inet_ingress pinned ")
    def test_cgroup_attach_xxx_type_pinned(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool cgroup attach /some_cgroup cgroup_inet_ingress pinned /path ")
    def test_cgroup_attach_xxx_type_pinned_xxx(self, completion):
        assert completion == "multi override".split()

    @pytest.mark.complete("bpftool cgroup attach /some_cgroup cgroup_inet_ingress tag ")
    def test_cgroup_attach_xxx_type_tag(self, completion):
        assert self.all_tags(completion)

    @pytest.mark.complete("bpftool cgroup attach /some_cgroup cgroup_inet_ingress tag some_tag ")
    def test_cgroup_attach_xxx_type_tag_xxx(self, completion):
        assert completion == "multi override".split()

    @pytest.mark.complete("bpftool cgroup attach /some_cgroup cgroup_inet_ingress tag some_tag multi ")
    def test_cgroup_attach_xxx_type_tag_xxx_multi(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool cgroup attach /some_cgroup cgroup_inet_ingress tag some_tag override ")
    def test_cgroup_attach_xxx_type_tag_xxx_override(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool cgroup detach ")
    def test_cgroup_detach(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool cgroup detach /some_cgroup ")
    def test_cgroup_detach_xxx(self, completion):
        assert completion == self.cgroup_attach_types

    @pytest.mark.complete("bpftool cgroup detach /some_cgroup cgroup_inet_ingress ")
    def test_cgroup_detach_xxx_type(self, completion):
        assert completion == "id name pinned tag".split()

    @pytest.mark.complete("bpftool cgroup detach /some_cgroup cgroup_inet_ingress id ")
    def test_cgroup_detach_xxx_type_id(self, completion):
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool cgroup detach /some_cgroup cgroup_inet_ingress id 1 ")
    def test_cgroup_detach_xxx_type_id_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool cgroup detach /some_cgroup cgroup_inet_ingress pinned ")
    def test_cgroup_detach_xxx_type_pinned(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool cgroup detach /some_cgroup cgroup_inet_ingress pinned /path ")
    def test_cgroup_detach_xxx_type_pinned_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool cgroup detach /some_cgroup cgroup_inet_ingress tag ")
    def test_cgroup_detach_xxx_type_tag(self, completion):
        assert self.all_tags(completion)

    @pytest.mark.complete("bpftool cgroup detach /some_cgroup cgroup_inet_ingress tag some_tag ")
    def test_cgroup_detach_xxx_type_tag_xxx(self, completion):
        assert not completion

    # bpftool feature

    @pytest.mark.complete("bpftool feature ")
    def test_feature(self, completion):
        assert completion == "help list_builtins probe".split()

    @pytest.mark.complete("bpftool feature help ")
    def test_feature_help(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool feature probe ")
    def test_feature_probe(self, completion):
        assert completion == "dev full kernel macros unprivileged".split()

    @pytest.mark.complete("bpftool feature probe kernel ")
    def test_feature_probe_kernel(self, completion):
        assert completion == "full macros unprivileged".split()

    @pytest.mark.complete("bpftool feature probe dev ")
    def test_feature_probe_dev(self, ifnames, completion):
        assert all(ifname in completion for ifname in ifnames)

    @pytest.mark.complete("bpftool feature probe dev some_ifname ")
    def test_feature_probe_dev_xxx(self, completion):
        assert completion == "full macros unprivileged".split()

    @pytest.mark.complete("bpftool feature probe full ")
    def test_feature_probe_full(self, completion):
        assert completion == "dev kernel macros unprivileged".split()

    @pytest.mark.complete("bpftool feature probe unprivileged ")
    def test_feature_probe_unprivileged(self, completion):
        assert completion == "dev full kernel macros".split()

    @pytest.mark.complete("bpftool feature probe full unprivileged ")
    def test_feature_probe_full_unprivileged(self, completion):
        assert completion == "dev kernel macros".split()

    @pytest.mark.complete("bpftool feature probe macros ")
    def test_feature_probe_macros(self, completion):
        assert completion == "dev full kernel prefix unprivileged".split()

    @pytest.mark.complete("bpftool feature probe macros prefix ")
    def test_feature_probe_macros_prefix(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool feature probe macros prefix SOME_PREFIX ")
    def test_feature_probe_macros_prefix_xxx(self, completion):
        assert completion == "dev full kernel unprivileged".split()

    @pytest.mark.complete("bpftool feature probe dev some_ifname full unprivileged macros prefix SOME_PREFIX ")
    def test_feature_probe_dev_xxx_full_unprivileged_macros_prefix_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool feature list_builtins ")
    def test_feature_listbuiltins(self, completion):
        assert completion == "attach_types helpers link_types map_types prog_types".split()

    @pytest.mark.complete("bpftool feature list_builtins prog_types ")
    def test_feature_listbuiltins_progtypes(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool feature list_builtins prog_types map_types attach_types link_types helpers ")
    def test_feature_listbuiltins_progtypes_maptypes_attachtypes_linktypes_helpers(self, completion):
        """Note: bpftool will ignore the arguments after "prog_types"."""
        assert not completion

    # bpftool gen

    @pytest.mark.complete("bpftool gen ")
    def test_gen(self, completion):
        assert completion == "help min_core_btf object skeleton subskeleton".split()

    @pytest.mark.complete("bpftool gen help ")
    def test_gen_help(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool gen object ")
    def test_gen_object(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool gen object /some_output ")
    def test_gen_object_xxx(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool gen object /some_output /some_input ")
    def test_gen_object_xxx_xxx(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool gen object /some_output /some_input /some_input ")
    def test_gen_object_xxx_xxx_xxx(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool gen skeleton ")
    def test_gen_skeleton(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool gen skeleton /some_objfile ")
    def test_gen_skeleton_xxx(self, completion):
        assert completion == "name"

    @pytest.mark.complete("bpftool gen skeleton /some_objfile name ")
    def test_gen_skeleton_xxx_name(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool gen skeleton /some_objfile name some_objname ")
    def test_gen_skeleton_xxx_name_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool gen subskeleton ")
    def test_gen_subskeleton(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool gen subskeleton /some_objfile ")
    def test_gen_subskeleton_xxx(self, completion):
        assert completion == "name"

    @pytest.mark.complete("bpftool gen subskeleton /some_objfile name ")
    def test_gen_subskeleton_xxx_name(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool gen subskeleton /some_objfile name some_objname ")
    def test_gen_subskeleton_xxx_name_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool gen min_core_btf ")
    def test_gen_mincorebtf(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool gen min_core_btf /some_input ")
    def test_gen_mincorebtf_xxx(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool gen min_core_btf /some_input /some_output ")
    def test_gen_mincorebtf_xxx_xxx(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool gen min_core_btf /some_input /some_output /some_objfile ")
    def test_gen_mincorebtf_xxx_xxx_xxx(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool gen min_core_btf /some_input /some_output /some_objfile /some_objfile ")
    def test_gen_mincorebtf_xxx_xxx_xxx_xxx(self, completion):
        assert self.all_paths(completion)

    # bpftool iter

    @pytest.mark.complete("bpftool iter ")
    def test_iter(self, completion):
        assert completion == "help pin".split()

    @pytest.mark.complete("bpftool iter help ")
    def test_iter_help(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool iter pin ")
    def test_iter_pin(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool iter pin /some/iterator ")
    def test_iter_pin_xxx(self, completion):
        assert completion == "map"

    @pytest.mark.complete("bpftool iter pin /some/iterator map ")
    def test_iter_pin_xxx_map(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool iter pin /some/iterator map id ")
    def test_iter_pin_xxx_map_id(self, completion):
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool iter pin /some/iterator map id 1 ")
    def test_iter_pin_xxx_map_id_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool iter pin /some/iterator map pinned ")
    def test_iter_pin_xxx_map_pinned(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool iter pin /some/iterator map pinned /some_map ")
    def test_iter_pin_xxx_map_pinned_xxx(self, completion):
        assert not completion

    # bpftool link

    @pytest.mark.complete("bpftool link ")
    def test_link(self, completion):
        assert completion == "detach help list pin show".split()

    @pytest.mark.complete("bpftool link help ")
    def test_link_help(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool link list ")
    def test_link_list(self, completion):
        assert completion == "id pinned".split()

    @pytest.mark.complete("bpftool link show ")
    def test_link_show(self, completion):
        assert completion == "id pinned".split()

    @pytest.mark.complete("bpftool link show id ", require_cmd=True)
    def test_link_show_id(self, get_bpf_link, completion):
        assert self.all_ints(completion)
        link_id = get_bpf_link["id"]
        if link_id is not None:
            assert link_id in completion

    @pytest.mark.complete("bpftool link show id 1 ")
    def test_link_show_id_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool link show pinned ")
    def test_link_show_pinned(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool link show pinned /some_link ")
    def test_link_show_pinned_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool link pin ")
    def test_link_pin(self, completion):
        assert completion == "id pinned".split()

    @pytest.mark.complete("bpftool link pin id ", require_cmd=True)
    def test_link_pin_id(self, get_bpf_link, completion):
        assert self.all_ints(completion)
        link_id = get_bpf_link["id"]
        if link_id is not None:
            assert link_id in completion

    @pytest.mark.complete("bpftool link pin id 1 ")
    def test_link_pin_id_xxx(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool link pin pinned ")
    def test_link_pin_pinned(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool link pin pinned /some_link ")
    def test_link_pin_pinned_xxx(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool link pin pinned /some_link /some_path ")
    def test_link_pin_pinned_xxx_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool link detach ")
    def test_link_detach(self, completion):
        assert completion == "id pinned".split()

    @pytest.mark.complete("bpftool link detach id ", require_cmd=True)
    def test_link_detach_id(self, get_bpf_link, completion):
        assert self.all_ints(completion)
        link_id = get_bpf_link["id"]
        if link_id is not None:
            assert link_id in completion

    @pytest.mark.complete("bpftool link detach id 1 ")
    def test_link_detach_id_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool link detach pinned ")
    def test_link_detach_pinned(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool link detach pinned /some_link ")
    def test_link_detach_pinned_xxx(self, completion):
        assert not completion

    # bpftool map

    @pytest.mark.complete("bpftool map ")
    def test_map(self, completion):
        assert completion == [
                "create",
                "delete",
                "dequeue",
                "dump",
                "enqueue",
                "event_pipe",
                "freeze",
                "getnext",
                "help",
                "list",
                "lookup",
                "peek",
                "pin",
                "pop",
                "push",
                "show",
                "update",
        ]

    @pytest.mark.complete("bpftool map help ")
    def test_map_help(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map create ")
    def test_map_create(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool map create /some_map ")
    def test_map_create_xxx(self, completion):
        assert completion == "dev entries flags key name type value".split()

    @pytest.mark.complete("bpftool map create /some_map type ")
    def test_map_create_xxx_type(self, completion):
        assert completion == self.map_types

    @pytest.mark.complete("bpftool map create /some_map type hash ")
    def test_map_create_xxx_type_xxx(self, completion):
        assert completion == "dev entries flags key name value".split()

    @pytest.mark.complete("bpftool map create /some_map type hash_of_maps ")
    def test_map_create_xxx_type_mom(self, completion):
        """Maps of maps get "inner_map" argument as well"""
        assert completion == "dev entries flags inner_map key name value".split()

    @pytest.mark.complete("bpftool map create /some_map type hash key ")
    def test_map_create_xxx_type_xxx_key(self, completion):
        """No "hex" keyword after "key" for creation, we expect a size."""
        assert not completion

    @pytest.mark.complete("bpftool map create /some_map type hash key 4 ")
    def test_map_create_xxx_type_xxx_key_xxx(self, completion):
        assert completion == "dev entries flags name value".split()

    @pytest.mark.complete("bpftool map create /some_map type hash key 4 value ")
    def test_map_create_xxx_type_xxx_key_xxx_value(self, completion):
        """No "hex" keyword after "value" for creation, we expect a size."""
        assert not completion

    @pytest.mark.complete("bpftool map create /some_map type hash key 4 value 4 ")
    def test_map_create_xxx_type_xxx_key_xxx_value_xxx(self, completion):
        assert completion == "dev entries flags name".split()

    @pytest.mark.complete("bpftool map create /some_map type hash key 4 value 4 entries ")
    def test_map_create_xxx_type_xxx_key_xxx_value_xxx_entries(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map create /some_map type hash key 4 value 4 entries 64 ")
    def test_map_create_xxx_type_xxx_key_xxx_value_xxx_entries_xxx(self, completion):
        assert completion == "dev flags name".split()

    @pytest.mark.complete("bpftool map create /some_map type hash key 4 value 4 entries 64 name ")
    def test_map_create_xxx_type_xxx_key_xxx_value_xxx_entries_xxx_name(self, completion):
        """No completion for "name", we expect user to type a new name."""
        assert not completion

    @pytest.mark.complete("bpftool map create /some_map type hash key 4 value 4 entries 64 name some_name ")
    def test_map_create_xxx_type_xxx_key_xxx_value_xxx_entries_xxx_name_xxx(self, completion):
        assert completion == "dev flags".split()

    @pytest.mark.complete("bpftool map create /some_map type hash_of_maps key 4 value 4 entries 64 name some_name ")
    def test_map_create_xxx_type_mom_key_xxx_value_xxx_entries_xxx_name_xxx(self, completion):
        """Maps of maps get "inner_map" argument as well"""
        assert completion == "dev flags inner_map".split()

    @pytest.mark.complete("bpftool map create /some_map type hash key 4 value 4 entries 64 name some_name flags ")
    def test_map_create_xxx_type_xxx_key_xxx_value_xxx_entries_xxx_name_xxx_flags(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map create /some_map type hash key 4 value 4 entries 64 name some_name flags 0x0 ")
    def test_map_create_xxx_type_xxx_key_xxx_value_xxx_entries_xxx_name_xxx_flags_any(self, completion):
        assert completion == "dev"

    @pytest.mark.complete("bpftool map create /some_map type hash_of_maps key 4 value 4 entries 64 name some_name flags 0x0 ")
    def test_map_create_xxx_type_mom_key_xxx_value_xxx_entries_xxx_name_xxx_flags_xxx(self, completion):
        """Maps of maps get "inner_map" argument as well"""
        assert completion == "dev inner_map".split()

    @pytest.mark.complete("bpftool map create /some_map type hash_of_maps key 4 value 4 entries 64 name some_name inner_map ")
    def test_map_create_xxx_type_mom_key_xxx_value_xxx_entries_xxx_name_xxx_inner_map(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool map create /some_map type hash_of_maps key 4 value 4 entries 64 name some_name inner_map id ")
    def test_map_create_xxx_type_mom_key_xxx_value_xxx_entries_xxx_name_xxx_innermap_id(self, completion):
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool map create /some_map type hash_of_maps key 4 value 4 entries 64 name some_name inner_map id 1 ")
    def test_map_create_xxx_type_mom_key_xxx_value_xxx_entries_xxx_name_xxx_innermap_id_xxx(self, completion):
        assert completion == "dev flags".split()

    @pytest.mark.complete("bpftool map create /some_map type hash_of_maps key 4 value 4 entries 64 name some_name inner_map pinned ")
    def test_map_create_xxx_type_mom_key_xxx_value_xxx_entries_xxx_name_xxx_innermap_pinned(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool map create /some_map type hash_of_maps key 4 value 4 entries 64 name some_name inner_map pinned /some_map ")
    def test_map_create_xxx_type_mom_key_xxx_value_xxx_entries_xxx_name_xxx_innermap_pinned_xxx(self, completion):
        assert completion == "dev flags".split()

    @pytest.mark.complete("bpftool map create /some_map type hash_of_maps key 4 value 4 entries 64 name some_name inner_map name ")
    def test_map_create_xxx_type_mom_key_xxx_value_xxx_entries_xxx_name_xxx_innermap_name(self, completion):
        assert completion

    @pytest.mark.complete("bpftool map create /some_map type hash_of_maps key 4 value 4 entries 64 name some_name inner_map name some_name ")
    def test_map_create_xxx_type_mom_key_xxx_value_xxx_entries_xxx_name_xxx_innermap_name_xxx(self, completion):
        assert completion == "dev flags".split()

    @pytest.mark.complete("bpftool map create /some_map type hash_of_maps key 4 value 4 entries 64 name some_name inner_map name some_name flags ")
    def test_map_create_xxx_type_mom_key_xxx_value_xxx_entries_xxx_name_xxx_innermap_name_xxx_flags(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map create /some_map type hash_of_maps key 4 value 4 entries 64 name some_name inner_map name some_name flags 0x0 ")
    def test_map_create_xxx_type_mom_key_xxx_value_xxx_entries_xxx_name_xxx_innermap_name_xxx_flags_xxx(self, completion):
        assert completion == "dev"

    @pytest.mark.complete("bpftool map create /some_map type hash key 4 value 4 entries 64 name some_name dev ")
    def test_map_create_xxx_type_xxx_key_xxx_value_xxx_entries_xxx_name_xxx_dev(self, ifnames, completion):
        assert all(ifname in completion for ifname in ifnames)

    @pytest.mark.complete("bpftool map create /some_map type hash key 4 value 4 entries 64 name some_name dev some_ifname ")
    def test_map_create_xxx_type_xxx_key_xxx_value_xxx_entries_xxx_name_xxx_dev_some_ifname(self, completion):
        assert completion == "flags"

    @pytest.mark.complete("bpftool map create /some_map type hash_of_maps key 4 value 4 entries 64 name some_name dev some_ifname ")
    def test_map_create_xxx_type_mom_key_xxx_value_xxx_entries_xxx_name_xxx_dev_some_ifname(self, completion):
        """Maps of maps get "inner_map" argument as well"""
        assert completion == "flags inner_map".split()

    @pytest.mark.complete("bpftool map create /some_map type hash_of_maps key 4 value 4 entries 64 name some_name dev some_ifname inner_map name some_name flags 0x0 ")
    def test_map_create_xxx_type_mom_key_xxx_value_xxx_entries_xxx_name_xxx_dev_some_ifname_innermap_name_xxx_flags_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map dump ")
    def test_map_dump(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool map dump id ")
    def test_map_dump_id(self, completion):
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool map dump id 1 ")
    def test_map_dump_id_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map dump pinned ")
    def test_map_dump_pinned(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool map dump pinned /some_map ")
    def test_map_dump_pinned_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map dump name ")
    def test_map_dump_name(self, completion):
        assert completion

    @pytest.mark.complete("bpftool map dump name some_name ")
    def test_map_dump_name_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map update ")
    def test_map_update(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool map update id 1 ")
    def test_map_update_id_xxx(self, completion):
        assert completion == "key"

    @pytest.mark.complete("bpftool map update id 1 key ")
    def test_map_update_id_xxx_key(self, completion):
        assert completion == "hex"

    @pytest.mark.complete("bpftool map update id 1 key hex ")
    def test_map_update_id_xxx_key_hex(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map update id 1 key 0x00 0x00 0x00 0x00 ")
    def test_map_update_id_xxx_key_xxx(self, completion):
        assert completion == "value"

    @pytest.mark.complete("bpftool map update id 1 key 0x00 0x00 0x00 0x00 value ")
    def test_map_update_id_xxx_key_xxx_value(self, completion):
        assert completion == "hex"

    @pytest.mark.complete("bpftool map update id 1 key 0x00 0x00 0x00 0x00 value hex ")
    def test_map_update_id_xxx_key_xxx_value_hex(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map update id 1 key 0x00 0x00 0x00 0x00 value 0x00 0x00 0x00 0x00 ")
    def test_map_update_id_xxx_key_xxx_value_xxx(self, completion):
        assert completion == "any exist noexist".split()

    @pytest.mark.complete("bpftool map update id 1 key 0x00 0x00 0x00 0x00 value 0x00 0x00 0x00 0x00 any ")
    def test_map_update_id_xxx_key_xxx_value_xxx_any(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map lookup ")
    def test_map_lookup(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool map lookup id 1 ")
    def test_map_lookup_id_xxx(self, completion):
        assert completion == "key"

    @pytest.mark.complete("bpftool map lookup id 1 key ")
    def test_map_lookup_id_xxx_key(self, completion):
        assert completion == "hex"

    @pytest.mark.complete("bpftool map lookup id 1 key hex ")
    def test_map_lookup_id_xxx_key_hex(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map lookup id 1 key 0x00 0x00 0x00 0x00 ")
    def test_map_lookup_id_xxx_key_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map getnext ")
    def test_map_getnext(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool map getnext id 1 ")
    def test_map_getnext_id_xxx(self, completion):
        assert completion == "key"

    @pytest.mark.complete("bpftool map getnext id 1 key ")
    def test_map_getnext_id_xxx_key(self, completion):
        assert completion == "hex"

    @pytest.mark.complete("bpftool map getnext id 1 key hex ")
    def test_map_getnext_id_xxx_key_hex(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map getnext id 1 key 0x00 0x00 0x00 0x00 ")
    def test_map_getnext_id_xxx_key_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map delete ")
    def test_map_delete(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool map delete id 1 ")
    def test_map_delete_id_xxx(self, completion):
        assert completion == "key"

    @pytest.mark.complete("bpftool map delete id 1 key ")
    def test_map_delete_id_xxx_key(self, completion):
        assert completion == "hex"

    @pytest.mark.complete("bpftool map delete id 1 key hex ")
    def test_map_delete_id_xxx_key_hex(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map delete id 1 key 0x00 0x00 0x00 0x00 ")
    def test_map_delete_id_xxx_key_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map pin ")
    def test_map_pin(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool map pin id 1 ")
    def test_map_pin_id_xxx(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool map pin id 1 /some_path ")
    def test_map_pin_id_xxx_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map event_pipe ")
    def test_map_event_pipe(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool map event_pipe id 1 ")
    def test_map_event_pipe_id_xxx(self, completion):
        assert completion == "cpu index".split()

    @pytest.mark.complete("bpftool map event_pipe id 1 cpu ")
    def test_map_event_pipe_id_xxx_cpu(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map event_pipe id 1 cpu 1 ")
    def test_map_event_pipe_id_1_cpu_xxx(self, completion):
        assert completion == "index"

    @pytest.mark.complete("bpftool map event_pipe id 1 index ")
    def test_map_event_pipe_id_xxx_index(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map event_pipe id 1 index 1 ")
    def test_map_event_pipe_id_1_index_xxx(self, completion):
        assert completion == "cpu"

    @pytest.mark.complete("bpftool map event_pipe id 1 cpu 1 index ")
    def test_map_event_pipe_id_1_cpu_xxx_index(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map event_pipe id 1 cpu 1 index 1 ")
    def test_map_event_pipe_id_1_cpu_1_index_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map peek ")
    def test_map_peek(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool map peek id 1 ")
    def test_map_peek_id_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map push ")
    def test_map_push(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool map push id 1 ")
    def test_map_push_id_xxx(self, completion):
        assert completion == "value"

    @pytest.mark.complete("bpftool map push id 1 value ")
    def test_map_push_id_xxx_value(self, completion):
        assert completion == "hex"

    @pytest.mark.complete("bpftool map push id 1 value hex ")
    def test_map_push_id_xxx_value_hex(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map push id 1 value 0x00 0x00 0x00 0x00 ")
    def test_map_push_id_xxx_value_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map pop ")
    def test_map_pop(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool map pop id 1 ")
    def test_map_pop_id_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map enqueue ")
    def test_map_enqueue(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool map enqueue id 1 ")
    def test_map_enqueue_id_xxx(self, completion):
        assert completion == "value"

    @pytest.mark.complete("bpftool map enqueue id 1 value ")
    def test_map_enqueue_id_xxx_value(self, completion):
        assert completion == "hex"

    @pytest.mark.complete("bpftool map enqueue id 1 value hex ")
    def test_map_enqueue_id_xxx_value_hex(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map enqueue id 1 value 0x00 0x00 0x00 0x00 ")
    def test_map_enqueue_id_xxx_value_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map dequeue ")
    def test_map_dequeue(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool map dequeue id 1 ")
    def test_map_dequeue_id_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool map freeze ")
    def test_map_freeze(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool map freeze id 1 ")
    def test_map_freeze_id_xxx(self, completion):
        assert not completion

    # bpftool net

    @pytest.mark.complete("bpftool net ")
    def test_net(self, completion):
        assert completion == "attach detach help list show".split()

    @pytest.mark.complete("bpftool net help ")
    def test_net_help(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool net list ")
    def test_net_list(self, completion):
        assert completion == "dev"

    @pytest.mark.complete("bpftool net show ")
    def test_net_show(self, completion):
        assert completion == "dev"

    @pytest.mark.complete("bpftool net show dev ")
    def test_net_show_dev(self, ifnames, completion):
        assert all(ifname in completion for ifname in ifnames)

    @pytest.mark.complete("bpftool net show dev some_ifname ")
    def test_net_show_dev_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool net attach ")
    def test_net_attach(self, completion):
        assert completion == "xdp xdpdrv xdpgeneric xdpoffload".split()

    @pytest.mark.complete("bpftool net attach xdp ")
    def test_net_attach_xxx(self, completion):
        assert completion == "id name pinned tag".split()

    @pytest.mark.complete("bpftool net attach xdp id ")
    def test_net_attach_xxx_id(self, completion):
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool net attach xdp id 1 ")
    def test_net_attach_xxx_id_1(self, completion):
        assert completion == "dev"

    @pytest.mark.complete("bpftool net attach xdp pinned ")
    def test_net_attach_xxx_pinned(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool net attach xdp pinned /some_prog ")
    def test_net_attach_xxx_pinned_xxx(self, completion):
        assert completion == "dev"

    @pytest.mark.complete("bpftool net attach xdp name ")
    def test_net_attach_xxx_name(self, completion):
        assert completion

    @pytest.mark.complete("bpftool net attach xdp name some_name ")
    def test_net_attach_xxx_name_xxx(self, completion):
        assert completion == "dev"

    @pytest.mark.complete("bpftool net attach xdp tag ")
    def test_net_attach_xxx_tag(self, completion):
        assert self.all_tags(completion)

    @pytest.mark.complete("bpftool net attach xdp tag some_tag ")
    def test_net_attach_xxx_tag_xxx(self, completion):
        assert completion == "dev".split()

    @pytest.mark.complete("bpftool net attach xdp tag some_tag dev ")
    def test_net_attach_xxx_tag_xxx_dev(self, ifnames, completion):
        assert all(ifname in completion for ifname in ifnames)

    @pytest.mark.complete("bpftool net attach xdp tag some_tag dev some_ifname ")
    def test_net_attach_xxx_tag_xxx_dev_xxx(self, completion):
        assert completion == "overwrite"

    @pytest.mark.complete("bpftool net attach xdp tag some_tag dev some_ifname overwrite ")
    def test_net_attach_xxx_tag_xxx_dev_xxx_overwrite(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool net detach ")
    def test_net_detach(self, completion):
        assert completion == "xdp xdpdrv xdpgeneric xdpoffload".split()

    @pytest.mark.complete("bpftool net detach xdp ")
    def test_net_detach_xxx(self, completion):
        assert completion == "dev"

    @pytest.mark.complete("bpftool net detach xdp dev ")
    def test_net_detach_xxx_dev(self, ifnames, completion):
        assert all(ifname in completion for ifname in ifnames)

    @pytest.mark.complete("bpftool net detach xdp dev some_ifname ")
    def test_net_detach_xxx_dev_xxx(self, completion):
        assert not completion

    # bpftool perf

    @pytest.mark.complete("bpftool perf ")
    def test_perf(self, completion):
        assert completion == "help list show".split()

    @pytest.mark.complete("bpftool perf help ")
    def test_perf_help(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool perf list ")
    def test_perf_list(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool perf show ")
    def test_perf_show(self, completion):
        assert not completion

    # bpftool prog

    @pytest.mark.complete("bpftool prog ")
    def test_prog(self, completion):
        assert completion == [
                "attach",
                "detach",
                "dump",
                "help",
                "list",
                "load",
                "loadall",
                "pin",
                "profile",
                "run",
                "show",
                "tracelog",
        ]

    @pytest.mark.complete("bpftool prog help ")
    def test_prog_help(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog list ")
    def test_prog_list(self, completion):
        assert completion == "id name pinned tag".split()

    @pytest.mark.complete("bpftool prog show ")
    def test_prog_show(self, completion):
        assert completion == "id name pinned tag".split()

    @pytest.mark.complete("bpftool prog show id ")
    def test_prog_show_id(self, completion):
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool prog show id 1 ")
    def test_prog_show_id_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog show pinned ")
    def test_prog_show_pinned(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog show pinned /some_prog ")
    def test_prog_show_pinned_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog show tag ")
    def test_prog_show_tag(self, completion):
        assert self.all_tags(completion)

    @pytest.mark.complete("bpftool prog show some_tag ")
    def test_prog_show_sometag(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog show name ")
    def test_prog_show_name(self, completion):
        assert completion

    @pytest.mark.complete("bpftool prog show some_name ")
    def test_prog_show_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog dump ")
    def test_prog_dump(self, completion):
        assert completion == "jited xlated".split()

    @pytest.mark.complete("bpftool prog dump xlated ")
    def test_prog_dump_xlated(self, completion):
        assert completion == "id name pinned tag".split()

    @pytest.mark.complete("bpftool prog dump xlated id ")
    def test_prog_dump_xlated_id(self, completion):
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool prog dump xlated id 1 ")
    def test_prog_dump_xlated_id_xxx(self, completion):
        assert completion == "file linum opcodes visual".split()

    @pytest.mark.complete("bpftool prog dump xlated pinned ")
    def test_prog_dump_xlated_pinned(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog dump xlated pinned /some_prog ")
    def test_prog_dump_xlated_pinned_xxx(self, completion):
        assert completion == "file linum opcodes visual".split()

    @pytest.mark.complete("bpftool prog dump xlated tag ")
    def test_prog_dump_xlated_tag(self, completion):
        assert self.all_tags(completion)

    @pytest.mark.complete("bpftool prog dump xlated tag some_tag ")
    def test_prog_dump_xlated_tag_sometag(self, completion):
        assert completion == "file linum opcodes visual".split()

    @pytest.mark.complete("bpftool prog dump xlated name ")
    def test_prog_dump_xlated_name(self, completion):
        assert completion

    @pytest.mark.complete("bpftool prog dump xlated name some_name ")
    def test_prog_dump_xlated_name_xxx(self, completion):
        assert completion == "file linum opcodes visual".split()

    @pytest.mark.complete("bpftool prog dump xlated name some_name file ")
    def test_prog_dump_xlated_name_xxx_file(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog dump xlated name some_name file /some_file ")
    def test_prog_dump_xlated_name_xxx_file_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog dump xlated name some_name linum ")
    def test_prog_dump_xlated_name_xxx_linum(self, completion):
        assert completion == "opcodes visual".split()

    @pytest.mark.complete("bpftool prog dump xlated name some_name opcodes ")
    def test_prog_dump_xlated_name_xxx_opcodes(self, completion):
        assert completion == "linum visual".split()

    @pytest.mark.complete("bpftool prog dump xlated name some_name linum opcodes ")
    def test_prog_dump_xlated_name_xxx_linum_opcodes(self, completion):
        assert completion == "visual"

    @pytest.mark.complete("bpftool prog dump xlated name some_name -p ")
    def test_prog_dump_xlated_name_xxx_p(self, completion):
        """Options -j, --json, -p, --pretty prevent "visual" to appear."""
        assert completion == "file linum opcodes".split()

    @pytest.mark.complete("bpftool prog dump xlated name some_name -d ")
    def test_prog_dump_xlated_name_xxx_d(self, completion):
        assert completion == "file linum opcodes visual".split()

    @pytest.mark.complete("bpftool prog dump xlated name some_name linum --json ")
    def test_prog_dump_xlated_name_xxx_linum_json(self, completion):
        """Options -j, --json, -p, --pretty prevent "visual" to appear."""
        assert completion == "opcodes"

    @pytest.mark.complete("bpftool prog dump xlated name some_name opcodes --debug ")
    def test_prog_dump_xlated_name_xxx_opcodes_debug(self, completion):
        assert completion == "linum visual".split()

    @pytest.mark.complete("bpftool prog dump xlated name some_name visual ")
    def test_prog_dump_xlated_name_xxx_visual(self, completion):
        assert completion == "linum opcodes".split()

    @pytest.mark.complete("bpftool prog dump xlated name some_name visual linum ")
    def test_prog_dump_xlated_name_xxx_visual_linum(self, completion):
        assert completion == "opcodes"

    @pytest.mark.complete("bpftool prog dump xlated name some_name visual linum opcodes ")
    def test_prog_dump_xlated_name_xxx_visual_linum_opcodes(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog dump jited name some_name ")
    def test_prog_dump_jited_name_xxx(self, completion):
        assert completion == "file linum opcodes".split()

    @pytest.mark.complete("bpftool prog dump jited name some_name file ")
    def test_prog_dump_jited_name_xxx_file(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog dump jited name some_name file /some_file ")
    def test_prog_dump_jited_name_xxx_file_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog dump jited name some_name linum ")
    def test_prog_dump_jited_name_xxx_linum(self, completion):
        assert completion == "opcodes"

    @pytest.mark.complete("bpftool prog dump jited name some_name opcodes ")
    def test_prog_dump_jited_name_xxx_opcodes(self, completion):
        assert completion == "linum"

    @pytest.mark.complete("bpftool prog dump jited name some_name linum opcodes ")
    def test_prog_dump_jited_name_xxx_linum_opcodes(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog loadall ")
    def test_prog_loadall(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog load ")
    def test_prog_load(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog load some_objfile ")
    def test_prog_load_xxx(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog load some_objfile /some_path ")
    def test_prog_load_xxx_xxx(self, completion):
        assert completion == "autoattach dev map pinmaps type".split()

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type ")
    def test_prog_load_xxx_xxx_type(self, completion):
        assert completion == self.prog_types

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp ")
    def test_prog_load_xxx_xxx_type_xxx(self, completion):
        assert completion == "autoattach dev map pinmaps".split()

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map ")
    def test_prog_load_xxx_xxx_type_xxx_map(self, completion):
        assert completion == "idx name".split()

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map idx ")
    def test_prog_load_xxx_xxx_type_xxx_map_idx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map idx 1 ")
    def test_prog_load_xxx_xxx_type_xxx_map_idx_xxx(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool prog load /tmp/bash_comp_test.o /some_path type kprobe map name ")
    def test_prog_load_xxx_xxx_type_xxx_map_name(self, get_objfile, completion):
        """Test that the map name is correctly extracted from the object file."""
        assert completion == get_objfile["map_name"]

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map name some_name ")
    def test_prog_load_xxx_xxx_type_xxx_map_name_xxx(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map name some_name id ")
    def test_prog_load_xxx_xxx_type_xxx_map_name_xxx_id(self, completion):
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map name some_name id 1 ")
    def test_prog_load_xxx_xxx_type_xxx_map_name_xxx_id_xxx(self, completion):
        """Parameter "map" can be specified multiple times."""
        assert completion == "autoattach dev map pinmaps".split()

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map name some_name id 1 map ")
    def test_prog_load_xxx_xxx_type_xxx_map_name_xxx_id_xxx_map(self, completion):
        """Parameter "map" can be specified multiple times."""
        assert completion == "idx name".split()

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map name some_name id 1 map idx ")
    def test_prog_load_xxx_xxx_type_xxx_map_name_xxx_id_xxx_map_idx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map name some_name id 1 map idx 1 ")
    def test_prog_load_xxx_xxx_type_xxx_map_name_xxx_id_xxx_map_idx_xxx(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map name some_name id 1 map idx 1 name ")
    def test_prog_load_xxx_xxx_type_xxx_map_name_xxx_id_xxx_map_idx_xxx_name(self, completion):
        """Check that maps can be passed with different kind of references."""
        assert completion

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map name some_name id 1 map idx 1 id ")
    def test_prog_load_xxx_xxx_type_xxx_map_name_xxx_id_xxx_map_idx_xxx_id(self, completion):
        """Check that duplicate "id" is not an issue."""
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map name some_name id 1 map idx 1 id 1 ")
    def test_prog_load_xxx_xxx_type_xxx_map_name_xxx_id_xxx_map_idx_xxx_id_xxx(self, completion):
        """Parameter "map" can be specified multiple times."""
        assert completion == "autoattach dev map pinmaps".split()

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map name some_name pinned ")
    def test_prog_load_xxx_xxx_type_xxx_map_name_xxx_pinned(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map name some_name pinned /some_map ")
    def test_prog_load_xxx_xxx_type_xxx_map_name_xxx_pinned_xxx(self, completion):
        """Parameter "map" can be specified multiple times."""
        assert completion == "autoattach dev map pinmaps".split()

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp dev ")
    def test_prog_load_xxx_xxx_type_xxx_dev(self, ifnames, completion):
        assert all(ifname in completion for ifname in ifnames)

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp dev some_ifname ")
    def test_prog_load_xxx_xxx_type_xxx_dev_xxx(self, completion):
        assert completion == "autoattach map pinmaps".split()

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp pinmaps ")
    def test_prog_load_xxx_xxx_type_xxx_pinmaps(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp pinmaps /some_dir ")
    def test_prog_load_xxx_xxx_type_xxx_pinmaps_xxx(self, completion):
        assert completion == "autoattach dev map".split()

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp autoattach ")
    def test_prog_load_xxx_xxx_type_xxx_autoattach(self, completion):
        assert completion == "dev map pinmaps".split()

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map name some_name pinned /some_map dev ")
    def test_prog_load_xxx_xxx_type_xxx_map_name_xxx_pinned_xxx_dev(self, ifnames, completion):
        assert all(ifname in completion for ifname in ifnames)

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map name some_name pinned /some_map dev some_ifname ")
    def test_prog_load_xxx_xxx_type_xxx_map_name_xxx_pinned_xxx_dev_xxx(self, completion):
        """Parameter "map" can be specified multiple times."""
        assert completion == "autoattach map pinmaps".split()

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map name some_name pinned /some_map dev some_ifname pinmaps ")
    def test_prog_load_xxx_xxx_type_xxx_map_name_xxx_pinned_xxx_dev_xxx_pinmaps(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map name some_name pinned /some_map dev some_ifname pinmaps /some_dir ")
    def test_prog_load_xxx_xxx_type_xxx_map_name_xxx_pinned_xxx_dev_xxx_pinmaps_xxx(self, completion):
        """Parameter "map" can be specified multiple times."""
        assert completion == "autoattach map".split()

    @pytest.mark.complete("bpftool prog load some_objfile /some_path type xdp map name some_name pinned /some_map dev some_ifname pinmaps /some_dir autoattach ")
    def test_prog_load_xxx_xxx_type_xxx_map_name_xxx_pinned_xxx_dev_xxx_pinmaps_xxx_autoattach(self, completion):
        """Parameter "map" can be specified multiple times."""
        assert completion == "map"

    @pytest.mark.complete("bpftool prog attach ")
    def test_prog_attach(self, completion):
        assert completion == "id name pinned tag".split()

    @pytest.mark.complete("bpftool prog attach id 1 ")
    def test_prog_attach_id_xxx(self, completion):
        assert completion == self.prog_attach_types

    @pytest.mark.complete("bpftool prog attach id 1 sk_msg_verdict ")
    def test_prog_attach_id_xxx_xxx(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool prog attach id 1 sk_msg_verdict id ")
    def test_prog_attach_id_xxx_xxx_id(self, completion):
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool prog attach id 1 sk_msg_verdict id 1 ")
    def test_prog_attach_id_xxx_xxx_id_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog attach id 1 sk_msg_verdict pinned ")
    def test_prog_attach_id_xxx_xxx_pinned(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog attach id 1 sk_msg_verdict pinned /some_map ")
    def test_prog_attach_id_xxx_xxx_pinned_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog detach id 1 ")
    def test_prog_detach_id_xxx(self, completion):
        assert completion == self.prog_attach_types

    @pytest.mark.complete("bpftool prog detach id 1 sk_msg_verdict ")
    def test_prog_detach_id_xxx_xxx(self, completion):
        assert completion == "id name pinned".split()

    @pytest.mark.complete("bpftool prog detach id 1 sk_msg_verdict id ")
    def test_prog_detach_id_xxx_xxx_id(self, completion):
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool prog detach id 1 sk_msg_verdict id 1 ")
    def test_prog_detach_id_xxx_xxx_id_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog detach id 1 sk_msg_verdict pinned ")
    def test_prog_detach_id_xxx_xxx_pinned(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog detach id 1 sk_msg_verdict pinned /some_map ")
    def test_prog_detach_id_xxx_xxx_pinned_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog tracelog ")
    def test_prog_tracelog(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog run ")
    def test_prog_run(self, completion):
        assert completion == "id name pinned tag".split()

    @pytest.mark.complete("bpftool prog run id 1 ")
    def test_prog_run_id_xxx(self, completion):
        assert completion == "ctx_in ctx_out ctx_size_out data_in data_out " \
                "data_size_out repeat".split()

    @pytest.mark.complete("bpftool prog run id 1 data_in ")
    def test_prog_run_id_xxx_datain(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog run id 1 data_in /some_file ")
    def test_prog_run_id_xxx_datain_xxx(self, completion):
        assert completion == "ctx_in ctx_out ctx_size_out data_out " \
                "data_size_out repeat".split()

    @pytest.mark.complete("bpftool prog run id 1 data_in /some_file data_out ")
    def test_prog_run_id_xxx_datain_xxx_dataout(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog run id 1 data_in /some_file data_out /some_file ")
    def test_prog_run_id_xxx_datain_xxx_dataout_xxx(self, completion):
        assert completion == "ctx_in ctx_out ctx_size_out " \
                "data_size_out repeat".split()

    @pytest.mark.complete("bpftool prog run id 1 data_in /some_file data_out /some_file data_size_out ")
    def test_prog_run_id_xxx_datain_xxx_dataout_xxx_datasizeout(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog run id 1 data_in /some_file data_out /some_file data_size_out 64 ")
    def test_prog_run_id_xxx_datain_xxx_dataout_xxx_datasizeout_xxx(self, completion):
        assert completion == "ctx_in ctx_out ctx_size_out repeat".split()

    @pytest.mark.complete("bpftool prog run id 1 data_in /some_file ctx_in ")
    def test_prog_run_id_xxx_datain_xxx_ctxin(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog run id 1 data_in /some_file ctx_in /some_file ")
    def test_prog_run_id_xxx_datain_xxx_ctxin_xxx(self, completion):
        assert completion == "ctx_out ctx_size_out data_out " \
                "data_size_out repeat".split()

    @pytest.mark.complete("bpftool prog run id 1 data_in /some_file ctx_in /some_file ctx_out ")
    def test_prog_run_id_xxx_datain_xxx_ctxin_xxx_ctxout(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog run id 1 data_in /some_file ctx_in /some_file ctx_out /some_file ")
    def test_prog_run_id_xxx_datain_xxx_ctxin_xxx_ctxout_xxx(self, completion):
        assert completion == "ctx_size_out data_out " \
                "data_size_out repeat".split()

    @pytest.mark.complete("bpftool prog run id 1 data_in /some_file ctx_in /some_file ctx_out /some_file ctx_size_out ")
    def test_prog_run_id_xxx_datain_xxx_ctxin_xxx_ctxout_xxx_ctxsizeout(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog run id 1 data_in /some_file ctx_in /some_file ctx_out /some_file ctx_size_out 64 ")
    def test_prog_run_id_xxx_datain_xxx_ctxin_xxx_ctxout_xxx_ctxsizeout_xxx(self, completion):
        assert completion == "data_out data_size_out repeat".split()

    @pytest.mark.complete("bpftool prog run id 1 data_in /some_file repeat ")
    def test_prog_run_id_xxx_datain_xxx_repeat(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog run id 1 data_in /some_file repeat 100 ")
    def test_prog_run_id_xxx_datain_xxx_repeat_xxx(self, completion):
        assert completion == "ctx_in ctx_out ctx_size_out data_out " \
                "data_size_out".split()

    @pytest.mark.complete("bpftool prog run id 1 data_in /some_file data_out /some_file data_size_out 64 ctx_in ")
    def test_prog_run_id_xxx_datain_xxx_dataout_xxx_datasizeout_xxx_ctxin(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool prog run id 1 data_in /some_file data_out /some_file data_size_out 64 ctx_in /some_file ctx_out /some_file ")
    def test_prog_run_id_xxx_datain_xxx_dataout_xxx_datasizeout_xxx_ctxin_xxx_ctxout_xxx(self, completion):
        assert completion == "ctx_size_out repeat".split()

    @pytest.mark.complete("bpftool prog run id 1 data_in /some_file data_out /some_file data_size_out 64 ctx_in /some_file ctx_out /some_file ctx_size_out 64 repeat 100 ")
    def test_prog_run_id_xxx_datain_xxx_dataout_xxx_datasizeout_xxx_ctxin_xxx_ctxout_xxx_ctxsizeout_xxx_repeat_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog profile ")
    def test_prog_profile(self, completion):
        assert completion == "id name pinned tag".split()

    @pytest.mark.complete("bpftool prog profile id 1 ")
    def test_prog_profile_id_xxx(self, completion):
        assert completion == "cycles dtlb_misses duration instructions " \
                "itlb_misses l1d_loads llc_misses".split()

    @pytest.mark.complete("bpftool prog profile id 1 cycles ")
    def test_prog_profile_id_xxx_cycles(self, completion):
        assert completion == "dtlb_misses instructions " \
                "itlb_misses l1d_loads llc_misses".split()

    @pytest.mark.complete("bpftool prog profile id 1 duration ")
    def test_prog_profile_id_xxx_duration(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool prog profile id 1 duration 15 ")
    def test_prog_profile_id_xxx_duration_xxx(self, completion):
        assert completion == "cycles dtlb_misses instructions " \
                "itlb_misses l1d_loads llc_misses".split()

    @pytest.mark.complete("bpftool prog profile id 1 duration 15 cycles ")
    def test_prog_profile_id_xxx_duration_xxx_cycles(self, completion):
        assert completion == "dtlb_misses instructions " \
                "itlb_misses l1d_loads llc_misses".split()

    @pytest.mark.complete("bpftool prog profile id 1 duration 15 cycles instructions l1d_loads llc_misses itlb_misses dtlb_misses ")
    def test_prog_profile_id_xxx_duration_xxx_cycles_instructions_lgivendloads_llcmisses_itlbmisses_dtlbmisses(self, completion):
        assert not completion

    # bpftool struct_ops

    @pytest.mark.complete("bpftool struct_ops ")
    def test_structops(self, completion):
        assert completion == "dump help list register show unregister".split()

    @pytest.mark.complete("bpftool struct_ops help ")
    def test_structops_help(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool struct_ops list ")
    def test_structops_list(self, completion):
        assert completion == "id name".split()

    @pytest.mark.complete("bpftool struct_ops show ")
    def test_structops_show(self, completion):
        assert completion == "id name".split()

    @pytest.mark.complete("bpftool struct_ops show id ")
    def test_structops_show_id(self, completion):
        pytest.skip("Needs a loaded struct_ops map")
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool struct_ops show id 1 ")
    def test_structops_show_id_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool struct_ops show name ")
    def test_structops_name(self, completion):
        pytest.skip("Needs a loaded struct_ops map")
        assert completion

    @pytest.mark.complete("bpftool struct_ops show name some_name ")
    def test_structops_name_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool struct_ops dump ")
    def test_structops_dump(self, completion):
        assert completion == "id name".split()

    @pytest.mark.complete("bpftool struct_ops dump id ")
    def test_structops_dump_id(self, completion):
        pytest.skip("Needs a loaded struct_ops map")
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool struct_ops dump id 1 ")
    def test_structops_dump_id_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool struct_ops dump name ")
    def test_structops_dump_name(self, completion):
        pytest.skip("Needs a loaded struct_ops map")
        assert completion

    @pytest.mark.complete("bpftool struct_ops dump name some_name ")
    def test_structops_dump_name_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool struct_ops register ")
    def test_structops_register(self, completion):
        assert self.all_paths(completion)

    @pytest.mark.complete("bpftool struct_ops register some_objfile ")
    def test_structops_register_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool struct_ops unregister ")
    def test_structops_unregister(self, completion):
        assert completion == "id name".split()

    @pytest.mark.complete("bpftool struct_ops unregister id ")
    def test_structops_unregister_id(self, completion):
        pytest.skip("Needs a loaded struct_ops map")
        assert self.all_ints(completion)

    @pytest.mark.complete("bpftool struct_ops unregister id 1 ")
    def test_structops_unregister_id_xxx(self, completion):
        assert not completion

    @pytest.mark.complete("bpftool struct_ops unregister name ")
    def test_structops_unregister_name(self, completion):
        pytest.skip("Needs a loaded struct_ops map")
        assert completion

    @pytest.mark.complete("bpftool struct_ops unregister name some_name ")
    def test_structops_unregister_name_xxx(self, completion):
        assert not completion
