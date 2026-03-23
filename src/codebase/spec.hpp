#include <iostream>
#include <vector>
#include <map>
#include <string>


struct my_struct {
    std::string string_data = "";
    std::map <std::string, my_struct> dict_data = {};
    std::vector <my_struct> list_data = {};
};

typedef struct my_struct helper_functions_data;
typedef struct my_struct map_info_data;
typedef struct my_struct protocols_data;


class Specification {
    private:
		helper_functions_data helper_functions_1;
		helper_functions_data helper_functions_10;
		helper_functions_data helper_functions_11;
		helper_functions_data helper_functions_12;
		helper_functions_data helper_functions_13;
		helper_functions_data helper_functions_18;
		helper_functions_data helper_functions_19;
		helper_functions_data helper_functions_2;
		helper_functions_data helper_functions_31;
		helper_functions_data helper_functions_38;
		helper_functions_data helper_functions_39;
		helper_functions_data helper_functions_43;
		helper_functions_data helper_functions_44;
		helper_functions_data helper_functions_50;
		helper_functions_data helper_functions_51;
		helper_functions_data helper_functions_54;
		helper_functions_data helper_functions_63;
		helper_functions_data helper_functions_65;
		helper_functions_data helper_functions_9;
		map_info_data map_info_map1;
		map_info_data map_info_map2;
		protocols_data protocols_129;
		protocols_data protocols_1544;
		protocols_data protocols_17;
		protocols_data protocols_2048;
		protocols_data protocols_2054;
		protocols_data protocols_33024;
		protocols_data protocols_34525;
		protocols_data protocols_34984;
		protocols_data protocols_35006;
		protocols_data protocols_4;
		protocols_data protocols_41;
		protocols_data protocols_43144;
		protocols_data protocols_44;
		protocols_data protocols_47;
		protocols_data protocols_48776;
		protocols_data protocols_49431;
		protocols_data protocols_56710;
		protocols_data protocols_6;
		protocols_data protocols_6081;
		protocols_data protocols_8;
		protocols_data protocols__1;

		std::map<std::string, helper_functions_data> helper_functions;
		std::map<std::string, map_info_data> map_info;
		std::map<std::string, protocols_data> protocols;

    public:

        Specification() {
			helper_functions_1.dict_data["arguments"] = helper_functions_data();
			helper_functions_1.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_1.dict_data["arguments"].list_data[0].string_data = "struct bpf_map *map";
			helper_functions_1.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_1.dict_data["arguments"].list_data[1].string_data = "const void *key";
			helper_functions_1.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_1.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_1.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_1.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_1.dict_data["compatible_hookpoints"].list_data[1].string_data = "tc";
			helper_functions_1.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_1.dict_data["does_packet_manipulation"].string_data = "false";
			helper_functions_1.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_1.dict_data["helper_function_name"].string_data = "bpf_map_lookup_elem";
			helper_functions["1"] = helper_functions_1;

			helper_functions_10.dict_data["arguments"] = helper_functions_data();
			helper_functions_10.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_10.dict_data["arguments"].list_data[0].string_data = "struct sk_buff *skb";
			helper_functions_10.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_10.dict_data["arguments"].list_data[1].string_data = "u32 offset";
			helper_functions_10.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_10.dict_data["arguments"].list_data[2].string_data = "u64 from";
			helper_functions_10.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_10.dict_data["arguments"].list_data[3].string_data = "u64 to";
			helper_functions_10.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_10.dict_data["arguments"].list_data[4].string_data = "u64 size";
			helper_functions_10.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_10.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_10.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_10.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_10.dict_data["compatible_hookpoints"].list_data[1].string_data = "tc";
			helper_functions_10.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_10.dict_data["does_packet_manipulation"].string_data = "true";
			helper_functions_10.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_10.dict_data["helper_function_name"].string_data = "bpf_l3_csum_replace";
			helper_functions["10"] = helper_functions_10;

			helper_functions_11.dict_data["arguments"] = helper_functions_data();
			helper_functions_11.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_11.dict_data["arguments"].list_data[0].string_data = "struct sk_buff *skb";
			helper_functions_11.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_11.dict_data["arguments"].list_data[1].string_data = "u32 offset";
			helper_functions_11.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_11.dict_data["arguments"].list_data[2].string_data = "u64 from";
			helper_functions_11.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_11.dict_data["arguments"].list_data[3].string_data = "u64 to";
			helper_functions_11.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_11.dict_data["arguments"].list_data[4].string_data = "u64 flags";
			helper_functions_11.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_11.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_11.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_11.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_11.dict_data["compatible_hookpoints"].list_data[1].string_data = "tc";
			helper_functions_11.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_11.dict_data["does_packet_manipulation"].string_data = "true";
			helper_functions_11.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_11.dict_data["helper_function_name"].string_data = "bpf_l4_csum_replace";
			helper_functions["11"] = helper_functions_11;

			helper_functions_12.dict_data["arguments"] = helper_functions_data();
			helper_functions_12.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["arguments"].list_data[0].string_data = "void *ctx";
			helper_functions_12.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["arguments"].list_data[1].string_data = "struct bpf_map *prog_array_map";
			helper_functions_12.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["arguments"].list_data[2].string_data = "u32 index";
			helper_functions_12.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[0].string_data = "sk_lookup";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[1].string_data = "syscall";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[2].string_data = "sk_reuseport";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[3].string_data = "flow_dissector";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[4].string_data = "cgroup_sysctl";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[5].string_data = "raw_tracepoint_writable";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[6].string_data = "cgroup_sockopt";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[7].string_data = "socket_filter";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[8].string_data = "kprobe";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[9].string_data = "sched_cls";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[10].string_data = "sched_act";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[11].string_data = "tracepoint";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[12].string_data = "xdp";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[13].string_data = "perf_event";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[14].string_data = "cgroup_skb";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[15].string_data = "cgroup_sock";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[16].string_data = "lwt_in";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[17].string_data = "lwt_out";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[18].string_data = "lwt_xmit";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[19].string_data = "sock_ops";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[20].string_data = "sk_skb";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[21].string_data = "cgroup_device";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[22].string_data = "sk_msg";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[23].string_data = "raw_tracepoint";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[24].string_data = "cgroup_sock_addr";
			helper_functions_12.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_12.dict_data["compatible_hookpoints"].list_data[25].string_data = "lwt_seg6local";
			helper_functions_12.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_12.dict_data["does_packet_manipulation"].string_data = "false";
			helper_functions_12.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_12.dict_data["helper_function_name"].string_data = "bpf_tail_call";
			helper_functions["12"] = helper_functions_12;

			helper_functions_13.dict_data["arguments"] = helper_functions_data();
			helper_functions_13.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_13.dict_data["arguments"].list_data[0].string_data = "struct sk_buff *skb";
			helper_functions_13.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_13.dict_data["arguments"].list_data[1].string_data = "u32 ifindex";
			helper_functions_13.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_13.dict_data["arguments"].list_data[2].string_data = "u64 flags";
			helper_functions_13.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_13.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_13.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_13.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_13.dict_data["compatible_hookpoints"].list_data[1].string_data = "tc";
			helper_functions_13.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_13.dict_data["does_packet_manipulation"].string_data = "true";
			helper_functions_13.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_13.dict_data["helper_function_name"].string_data = "bpf_clone_redirect";
			helper_functions["13"] = helper_functions_13;

			helper_functions_18.dict_data["arguments"] = helper_functions_data();
			helper_functions_18.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_18.dict_data["arguments"].list_data[0].string_data = "struct sk_buff *skb";
			helper_functions_18.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_18.dict_data["arguments"].list_data[1].string_data = "__be16 vlan_proto";
			helper_functions_18.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_18.dict_data["arguments"].list_data[2].string_data = "u16 vlan_tci";
			helper_functions_18.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_18.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_18.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_18.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_18.dict_data["compatible_hookpoints"].list_data[1].string_data = "tc";
			helper_functions_18.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_18.dict_data["does_packet_manipulation"].string_data = "true";
			helper_functions_18.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_18.dict_data["helper_function_name"].string_data = "bpf_skb_vlan_push";
			helper_functions["18"] = helper_functions_18;

			helper_functions_19.dict_data["arguments"] = helper_functions_data();
			helper_functions_19.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_19.dict_data["arguments"].list_data[0].string_data = "struct sk_buff *skb";
			helper_functions_19.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_19.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_19.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_19.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_19.dict_data["compatible_hookpoints"].list_data[1].string_data = "tc";
			helper_functions_19.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_19.dict_data["does_packet_manipulation"].string_data = "true";
			helper_functions_19.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_19.dict_data["helper_function_name"].string_data = "bpf_skb_vlan_pop";
			helper_functions["19"] = helper_functions_19;

			helper_functions_2.dict_data["arguments"] = helper_functions_data();
			helper_functions_2.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_2.dict_data["arguments"].list_data[0].string_data = "struct bpf_map *map";
			helper_functions_2.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_2.dict_data["arguments"].list_data[1].string_data = "const void *key";
			helper_functions_2.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_2.dict_data["arguments"].list_data[2].string_data = "const void *value";
			helper_functions_2.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_2.dict_data["arguments"].list_data[3].string_data = "uint64_t flags";
			helper_functions_2.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_2.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_2.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_2.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_2.dict_data["compatible_hookpoints"].list_data[1].string_data = "tc";
			helper_functions_2.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_2.dict_data["does_packet_manipulation"].string_data = "false";
			helper_functions_2.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_2.dict_data["helper_function_name"].string_data = "bpf_map_update_elem";
			helper_functions["2"] = helper_functions_2;

			helper_functions_31.dict_data["arguments"] = helper_functions_data();
			helper_functions_31.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_31.dict_data["arguments"].list_data[0].string_data = "struct sk_buff *skb";
			helper_functions_31.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_31.dict_data["arguments"].list_data[1].string_data = "__be proto";
			helper_functions_31.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_31.dict_data["arguments"].list_data[2].string_data = "u64 flags";
			helper_functions_31.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_31.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_31.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_31.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_31.dict_data["compatible_hookpoints"].list_data[1].string_data = "tc";
			helper_functions_31.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_31.dict_data["does_packet_manipulation"].string_data = "true";
			helper_functions_31.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_31.dict_data["helper_function_name"].string_data = "bpf_skb_change_proto";
			helper_functions["31"] = helper_functions_31;

			helper_functions_38.dict_data["arguments"] = helper_functions_data();
			helper_functions_38.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_38.dict_data["arguments"].list_data[0].string_data = "struct sk_buff *skb";
			helper_functions_38.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_38.dict_data["arguments"].list_data[1].string_data = "u32 len";
			helper_functions_38.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_38.dict_data["arguments"].list_data[2].string_data = "u64 flags";
			helper_functions_38.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_38.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_38.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_38.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_38.dict_data["compatible_hookpoints"].list_data[1].string_data = "tc";
			helper_functions_38.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_38.dict_data["does_packet_manipulation"].string_data = "true";
			helper_functions_38.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_38.dict_data["helper_function_name"].string_data = "bpf_skb_change_tail";
			helper_functions["38"] = helper_functions_38;

			helper_functions_39.dict_data["arguments"] = helper_functions_data();
			helper_functions_39.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_39.dict_data["arguments"].list_data[0].string_data = "struct sk_buff *skb";
			helper_functions_39.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_39.dict_data["arguments"].list_data[1].string_data = "u32 len";
			helper_functions_39.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_39.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_39.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_39.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_39.dict_data["compatible_hookpoints"].list_data[1].string_data = "tc";
			helper_functions_39.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_39.dict_data["does_packet_manipulation"].string_data = "true";
			helper_functions_39.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_39.dict_data["helper_function_name"].string_data = "bpf_skb_pull_data";
			helper_functions["39"] = helper_functions_39;

			helper_functions_43.dict_data["arguments"] = helper_functions_data();
			helper_functions_43.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_43.dict_data["arguments"].list_data[0].string_data = "struct sk_buff *skb";
			helper_functions_43.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_43.dict_data["arguments"].list_data[1].string_data = "u32 len";
			helper_functions_43.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_43.dict_data["arguments"].list_data[2].string_data = "u64 flags";
			helper_functions_43.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_43.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_43.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_43.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_43.dict_data["compatible_hookpoints"].list_data[1].string_data = "tc";
			helper_functions_43.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_43.dict_data["does_packet_manipulation"].string_data = "true";
			helper_functions_43.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_43.dict_data["helper_function_name"].string_data = "bpf_skb_change_head";
			helper_functions["43"] = helper_functions_43;

			helper_functions_44.dict_data["arguments"] = helper_functions_data();
			helper_functions_44.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_44.dict_data["arguments"].list_data[0].string_data = "struct xdp_buff *xdp_md";
			helper_functions_44.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_44.dict_data["arguments"].list_data[1].string_data = "int delta";
			helper_functions_44.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_44.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_44.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_44.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_44.dict_data["does_packet_manipulation"].string_data = "true";
			helper_functions_44.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_44.dict_data["helper_function_name"].string_data = "bpf_xdp_adjust_head";
			helper_functions["44"] = helper_functions_44;

			helper_functions_50.dict_data["arguments"] = helper_functions_data();
			helper_functions_50.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_50.dict_data["arguments"].list_data[0].string_data = "struct sk_buff *skb";
			helper_functions_50.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_50.dict_data["arguments"].list_data[1].string_data = "s32 len_diff";
			helper_functions_50.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_50.dict_data["arguments"].list_data[2].string_data = "u32 mode";
			helper_functions_50.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_50.dict_data["arguments"].list_data[3].string_data = "u64 flags";
			helper_functions_50.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_50.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_50.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_50.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_50.dict_data["compatible_hookpoints"].list_data[1].string_data = "tc";
			helper_functions_50.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_50.dict_data["does_packet_manipulation"].string_data = "true";
			helper_functions_50.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_50.dict_data["helper_function_name"].string_data = "bpf_skb_adjust_room";
			helper_functions["50"] = helper_functions_50;

			helper_functions_51.dict_data["arguments"] = helper_functions_data();
			helper_functions_51.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_51.dict_data["arguments"].list_data[0].string_data = "struct bpf_map *map";
			helper_functions_51.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_51.dict_data["arguments"].list_data[1].string_data = "u32 key";
			helper_functions_51.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_51.dict_data["arguments"].list_data[2].string_data = "u64 flags";
			helper_functions_51.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_51.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_51.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_51.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_51.dict_data["does_packet_manipulation"].string_data = "false";
			helper_functions_51.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_51.dict_data["helper_function_name"].string_data = "bpf_redirect_map";
			helper_functions["51"] = helper_functions_51;

			helper_functions_54.dict_data["arguments"] = helper_functions_data();
			helper_functions_54.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_54.dict_data["arguments"].list_data[0].string_data = "struct xdp_md *xdp_md";
			helper_functions_54.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_54.dict_data["arguments"].list_data[1].string_data = "int delta";
			helper_functions_54.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_54.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_54.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_54.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_54.dict_data["does_packet_manipulation"].string_data = "true";
			helper_functions_54.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_54.dict_data["helper_function_name"].string_data = "bpf_xdp_adjust_meta";
			helper_functions["54"] = helper_functions_54;

			helper_functions_63.dict_data["arguments"] = helper_functions_data();
			helper_functions_63.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_63.dict_data["arguments"].list_data[0].string_data = "struct sk_msg_buff *msg";
			helper_functions_63.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_63.dict_data["arguments"].list_data[1].string_data = "u32 start";
			helper_functions_63.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_63.dict_data["arguments"].list_data[2].string_data = "u32 end";
			helper_functions_63.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_63.dict_data["arguments"].list_data[3].string_data = "u64 flags";
			helper_functions_63.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_63.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_63.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_63.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_63.dict_data["compatible_hookpoints"].list_data[1].string_data = "tc";
			helper_functions_63.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_63.dict_data["does_packet_manipulation"].string_data = "true";
			helper_functions_63.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_63.dict_data["helper_function_name"].string_data = "bpf_msg_pull_data";
			helper_functions["63"] = helper_functions_63;

			helper_functions_65.dict_data["arguments"] = helper_functions_data();
			helper_functions_65.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_65.dict_data["arguments"].list_data[0].string_data = "struct xdp_buff *xdp_md";
			helper_functions_65.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_65.dict_data["arguments"].list_data[1].string_data = "int delta";
			helper_functions_65.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_65.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_65.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_65.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_65.dict_data["does_packet_manipulation"].string_data = "true";
			helper_functions_65.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_65.dict_data["helper_function_name"].string_data = "bpf_xdp_adjust_tail";
			helper_functions["65"] = helper_functions_65;

			helper_functions_9.dict_data["arguments"] = helper_functions_data();
			helper_functions_9.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_9.dict_data["arguments"].list_data[0].string_data = "struct sk_buff *skb";
			helper_functions_9.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_9.dict_data["arguments"].list_data[1].string_data = "u32 offset";
			helper_functions_9.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_9.dict_data["arguments"].list_data[2].string_data = "const void *from";
			helper_functions_9.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_9.dict_data["arguments"].list_data[3].string_data = "u32 len";
			helper_functions_9.dict_data["arguments"].list_data.push_back(helper_functions_data());
			helper_functions_9.dict_data["arguments"].list_data[4].string_data = "u64 flags";
			helper_functions_9.dict_data["compatible_hookpoints"] = helper_functions_data();
			helper_functions_9.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_9.dict_data["compatible_hookpoints"].list_data[0].string_data = "xdp";
			helper_functions_9.dict_data["compatible_hookpoints"].list_data.push_back(helper_functions_data());
			helper_functions_9.dict_data["compatible_hookpoints"].list_data[1].string_data = "tc";
			helper_functions_9.dict_data["does_packet_manipulation"] = helper_functions_data();
			helper_functions_9.dict_data["does_packet_manipulation"].string_data = "true";
			helper_functions_9.dict_data["helper_function_name"] = helper_functions_data();
			helper_functions_9.dict_data["helper_function_name"].string_data = "bpf_skb_store_bytes";
			helper_functions["9"] = helper_functions_9;

			map_info_map1.dict_data["rules"] = map_info_data();
			map_info_map1.dict_data["rules"].dict_data["key1"] = map_info_data();
			map_info_map1.dict_data["rules"].dict_data["key1"].string_data = "value1";
			map_info_map1.dict_data["rules"].dict_data["key2"] = map_info_data();
			map_info_map1.dict_data["rules"].dict_data["key2"].string_data = "value2";
			map_info["map1"] = map_info_map1;

			map_info_map2.dict_data["rules"] = map_info_data();
			map_info_map2.dict_data["rules"].dict_data["key3"] = map_info_data();
			map_info_map2.dict_data["rules"].dict_data["key3"].string_data = "value3";
			map_info_map2.dict_data["rules"].dict_data["key4"] = map_info_data();
			map_info_map2.dict_data["rules"].dict_data["key4"].string_data = "value4";
			map_info["map2"] = map_info_map2;

			protocols_129.dict_data["field_offsets"] = protocols_data();
			protocols_129.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_129.dict_data["field_offsets"].dict_data["0"].string_data = "h_vlan_TCI";
			protocols_129.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_129.dict_data["field_offsets"].dict_data["2"].string_data = "h_vlan_encapsulated_proto";
			protocols_129.dict_data["header_size_bytes"] = protocols_data();
			protocols_129.dict_data["header_size_bytes"].string_data = "4";
			protocols_129.dict_data["next_protocols"] = protocols_data();
			protocols_129.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_129.dict_data["next_protocols"].list_data[0].string_data = "_1";
			protocols_129.dict_data["protocol_name"] = protocols_data();
			protocols_129.dict_data["protocol_name"].string_data = "VLAN";
			protocols_129.dict_data["tail_offset"] = protocols_data();
			protocols_129.dict_data["tail_offset"].string_data = "2";
			protocols["129"] = protocols_129;

			protocols_1544.dict_data["field_offsets"] = protocols_data();
			protocols_1544.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_1544.dict_data["field_offsets"].dict_data["0"].string_data = "ar_hrd";
			protocols_1544.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_1544.dict_data["field_offsets"].dict_data["2"].string_data = "ar_pro";
			protocols_1544.dict_data["field_offsets"].dict_data["4"] = protocols_data();
			protocols_1544.dict_data["field_offsets"].dict_data["4"].string_data = "ar_hln";
			protocols_1544.dict_data["field_offsets"].dict_data["5"] = protocols_data();
			protocols_1544.dict_data["field_offsets"].dict_data["5"].string_data = "ar_pln";
			protocols_1544.dict_data["field_offsets"].dict_data["6"] = protocols_data();
			protocols_1544.dict_data["field_offsets"].dict_data["6"].string_data = "ar_op";
			protocols_1544.dict_data["header_size_bytes"] = protocols_data();
			protocols_1544.dict_data["header_size_bytes"].string_data = "8";
			protocols_1544.dict_data["next_protocols"] = protocols_data();
			protocols_1544.dict_data["protocol_name"] = protocols_data();
			protocols_1544.dict_data["protocol_name"].string_data = "ARP";
			protocols_1544.dict_data["tail_offset"] = protocols_data();
			protocols_1544.dict_data["tail_offset"].string_data = "_1";
			protocols["1544"] = protocols_1544;

			protocols_17.dict_data["field_offsets"] = protocols_data();
			protocols_17.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_17.dict_data["field_offsets"].dict_data["0"].string_data = "source";
			protocols_17.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_17.dict_data["field_offsets"].dict_data["2"].string_data = "dest";
			protocols_17.dict_data["field_offsets"].dict_data["4"] = protocols_data();
			protocols_17.dict_data["field_offsets"].dict_data["4"].string_data = "len";
			protocols_17.dict_data["field_offsets"].dict_data["6"] = protocols_data();
			protocols_17.dict_data["field_offsets"].dict_data["6"].string_data = "check";
			protocols_17.dict_data["header_size_bytes"] = protocols_data();
			protocols_17.dict_data["header_size_bytes"].string_data = "8";
			protocols_17.dict_data["next_protocols"] = protocols_data();
			protocols_17.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_17.dict_data["next_protocols"].list_data[0].string_data = "47";
			protocols_17.dict_data["protocol_name"] = protocols_data();
			protocols_17.dict_data["protocol_name"].string_data = "UDP";
			protocols_17.dict_data["tail_offset"] = protocols_data();
			protocols_17.dict_data["tail_offset"].string_data = "_1";
			protocols["17"] = protocols_17;

			protocols_2048.dict_data["field_offsets"] = protocols_data();
			protocols_2048.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_2048.dict_data["field_offsets"].dict_data["0"].string_data = "ihl";
			protocols_2048.dict_data["field_offsets"].dict_data["1"] = protocols_data();
			protocols_2048.dict_data["field_offsets"].dict_data["1"].string_data = "tos";
			protocols_2048.dict_data["field_offsets"].dict_data["10"] = protocols_data();
			protocols_2048.dict_data["field_offsets"].dict_data["10"].string_data = "check";
			protocols_2048.dict_data["field_offsets"].dict_data["12"] = protocols_data();
			protocols_2048.dict_data["field_offsets"].dict_data["12"].string_data = "saddr";
			protocols_2048.dict_data["field_offsets"].dict_data["16"] = protocols_data();
			protocols_2048.dict_data["field_offsets"].dict_data["16"].string_data = "daddr";
			protocols_2048.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_2048.dict_data["field_offsets"].dict_data["2"].string_data = "tot_len";
			protocols_2048.dict_data["field_offsets"].dict_data["4"] = protocols_data();
			protocols_2048.dict_data["field_offsets"].dict_data["4"].string_data = "id";
			protocols_2048.dict_data["field_offsets"].dict_data["6"] = protocols_data();
			protocols_2048.dict_data["field_offsets"].dict_data["6"].string_data = "frag_off";
			protocols_2048.dict_data["field_offsets"].dict_data["8"] = protocols_data();
			protocols_2048.dict_data["field_offsets"].dict_data["8"].string_data = "ttl";
			protocols_2048.dict_data["field_offsets"].dict_data["9"] = protocols_data();
			protocols_2048.dict_data["field_offsets"].dict_data["9"].string_data = "protocol";
			protocols_2048.dict_data["header_size_bytes"] = protocols_data();
			protocols_2048.dict_data["header_size_bytes"].string_data = "20";
			protocols_2048.dict_data["next_protocols"] = protocols_data();
			protocols_2048.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_2048.dict_data["next_protocols"].list_data[0].string_data = "6";
			protocols_2048.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_2048.dict_data["next_protocols"].list_data[1].string_data = "17";
			protocols_2048.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_2048.dict_data["next_protocols"].list_data[2].string_data = "47";
			protocols_2048.dict_data["protocol_name"] = protocols_data();
			protocols_2048.dict_data["protocol_name"].string_data = "IPv4";
			protocols_2048.dict_data["tail_offset"] = protocols_data();
			protocols_2048.dict_data["tail_offset"].string_data = "9";
			protocols["2048"] = protocols_2048;

			protocols_2054.dict_data["field_offsets"] = protocols_data();
			protocols_2054.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_2054.dict_data["field_offsets"].dict_data["0"].string_data = "ar_hrd";
			protocols_2054.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_2054.dict_data["field_offsets"].dict_data["2"].string_data = "ar_pro";
			protocols_2054.dict_data["field_offsets"].dict_data["4"] = protocols_data();
			protocols_2054.dict_data["field_offsets"].dict_data["4"].string_data = "ar_hln";
			protocols_2054.dict_data["field_offsets"].dict_data["5"] = protocols_data();
			protocols_2054.dict_data["field_offsets"].dict_data["5"].string_data = "ar_pln";
			protocols_2054.dict_data["field_offsets"].dict_data["6"] = protocols_data();
			protocols_2054.dict_data["field_offsets"].dict_data["6"].string_data = "ar_op";
			protocols_2054.dict_data["header_size_bytes"] = protocols_data();
			protocols_2054.dict_data["header_size_bytes"].string_data = "8";
			protocols_2054.dict_data["next_protocols"] = protocols_data();
			protocols_2054.dict_data["protocol_name"] = protocols_data();
			protocols_2054.dict_data["protocol_name"].string_data = "ARP";
			protocols_2054.dict_data["tail_offset"] = protocols_data();
			protocols_2054.dict_data["tail_offset"].string_data = "_1";
			protocols["2054"] = protocols_2054;

			protocols_33024.dict_data["field_offsets"] = protocols_data();
			protocols_33024.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_33024.dict_data["field_offsets"].dict_data["0"].string_data = "h_vlan_TCI";
			protocols_33024.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_33024.dict_data["field_offsets"].dict_data["2"].string_data = "h_vlan_encapsulated_proto";
			protocols_33024.dict_data["header_size_bytes"] = protocols_data();
			protocols_33024.dict_data["header_size_bytes"].string_data = "4";
			protocols_33024.dict_data["next_protocols"] = protocols_data();
			protocols_33024.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_33024.dict_data["next_protocols"].list_data[0].string_data = "_1";
			protocols_33024.dict_data["protocol_name"] = protocols_data();
			protocols_33024.dict_data["protocol_name"].string_data = "VLAN";
			protocols_33024.dict_data["tail_offset"] = protocols_data();
			protocols_33024.dict_data["tail_offset"].string_data = "2";
			protocols["33024"] = protocols_33024;

			protocols_34525.dict_data["field_offsets"] = protocols_data();
			protocols_34525.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_34525.dict_data["field_offsets"].dict_data["0"].string_data = "priority";
			protocols_34525.dict_data["field_offsets"].dict_data["1"] = protocols_data();
			protocols_34525.dict_data["field_offsets"].dict_data["1"].string_data = "flow_lbl";
			protocols_34525.dict_data["field_offsets"].dict_data["24"] = protocols_data();
			protocols_34525.dict_data["field_offsets"].dict_data["24"].string_data = "daddr";
			protocols_34525.dict_data["field_offsets"].dict_data["4"] = protocols_data();
			protocols_34525.dict_data["field_offsets"].dict_data["4"].string_data = "payload_len";
			protocols_34525.dict_data["field_offsets"].dict_data["6"] = protocols_data();
			protocols_34525.dict_data["field_offsets"].dict_data["6"].string_data = "nexthdr";
			protocols_34525.dict_data["field_offsets"].dict_data["7"] = protocols_data();
			protocols_34525.dict_data["field_offsets"].dict_data["7"].string_data = "hop_limit";
			protocols_34525.dict_data["field_offsets"].dict_data["8"] = protocols_data();
			protocols_34525.dict_data["field_offsets"].dict_data["8"].string_data = "saddr";
			protocols_34525.dict_data["header_size_bytes"] = protocols_data();
			protocols_34525.dict_data["header_size_bytes"].string_data = "40";
			protocols_34525.dict_data["next_protocols"] = protocols_data();
			protocols_34525.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_34525.dict_data["next_protocols"].list_data[0].string_data = "6";
			protocols_34525.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_34525.dict_data["next_protocols"].list_data[1].string_data = "17";
			protocols_34525.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_34525.dict_data["next_protocols"].list_data[2].string_data = "47";
			protocols_34525.dict_data["protocol_name"] = protocols_data();
			protocols_34525.dict_data["protocol_name"].string_data = "IPv6";
			protocols_34525.dict_data["tail_offset"] = protocols_data();
			protocols_34525.dict_data["tail_offset"].string_data = "6";
			protocols["34525"] = protocols_34525;

			protocols_34984.dict_data["field_offsets"] = protocols_data();
			protocols_34984.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_34984.dict_data["field_offsets"].dict_data["0"].string_data = "h_vlan_TCI";
			protocols_34984.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_34984.dict_data["field_offsets"].dict_data["2"].string_data = "h_vlan_encapsulated_proto";
			protocols_34984.dict_data["header_size_bytes"] = protocols_data();
			protocols_34984.dict_data["header_size_bytes"].string_data = "4";
			protocols_34984.dict_data["next_protocols"] = protocols_data();
			protocols_34984.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_34984.dict_data["next_protocols"].list_data[0].string_data = "_1";
			protocols_34984.dict_data["protocol_name"] = protocols_data();
			protocols_34984.dict_data["protocol_name"].string_data = "VLAN";
			protocols_34984.dict_data["tail_offset"] = protocols_data();
			protocols_34984.dict_data["tail_offset"].string_data = "2";
			protocols["34984"] = protocols_34984;

			protocols_35006.dict_data["field_offsets"] = protocols_data();
			protocols_35006.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_35006.dict_data["field_offsets"].dict_data["0"].string_data = "vlan_upper";
			protocols_35006.dict_data["field_offsets"].dict_data["1"] = protocols_data();
			protocols_35006.dict_data["field_offsets"].dict_data["1"].string_data = "vlan";
			protocols_35006.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_35006.dict_data["field_offsets"].dict_data["2"].string_data = "session_id_upper";
			protocols_35006.dict_data["field_offsets"].dict_data["3"] = protocols_data();
			protocols_35006.dict_data["field_offsets"].dict_data["3"].string_data = "session_id";
			protocols_35006.dict_data["header_size_bytes"] = protocols_data();
			protocols_35006.dict_data["header_size_bytes"].string_data = "4";
			protocols_35006.dict_data["next_protocols"] = protocols_data();
			protocols_35006.dict_data["protocol_name"] = protocols_data();
			protocols_35006.dict_data["protocol_name"].string_data = "ETH_P_ERSPAN";
			protocols_35006.dict_data["tail_offset"] = protocols_data();
			protocols_35006.dict_data["tail_offset"].string_data = "_1";
			protocols["35006"] = protocols_35006;

			protocols_4.dict_data["field_offsets"] = protocols_data();
			protocols_4.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_4.dict_data["field_offsets"].dict_data["0"].string_data = "ihl";
			protocols_4.dict_data["field_offsets"].dict_data["1"] = protocols_data();
			protocols_4.dict_data["field_offsets"].dict_data["1"].string_data = "tos";
			protocols_4.dict_data["field_offsets"].dict_data["10"] = protocols_data();
			protocols_4.dict_data["field_offsets"].dict_data["10"].string_data = "check";
			protocols_4.dict_data["field_offsets"].dict_data["12"] = protocols_data();
			protocols_4.dict_data["field_offsets"].dict_data["12"].string_data = "saddr";
			protocols_4.dict_data["field_offsets"].dict_data["16"] = protocols_data();
			protocols_4.dict_data["field_offsets"].dict_data["16"].string_data = "daddr";
			protocols_4.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_4.dict_data["field_offsets"].dict_data["2"].string_data = "tot_len";
			protocols_4.dict_data["field_offsets"].dict_data["4"] = protocols_data();
			protocols_4.dict_data["field_offsets"].dict_data["4"].string_data = "id";
			protocols_4.dict_data["field_offsets"].dict_data["6"] = protocols_data();
			protocols_4.dict_data["field_offsets"].dict_data["6"].string_data = "flags";
			protocols_4.dict_data["field_offsets"].dict_data["8"] = protocols_data();
			protocols_4.dict_data["field_offsets"].dict_data["8"].string_data = "ttl";
			protocols_4.dict_data["field_offsets"].dict_data["9"] = protocols_data();
			protocols_4.dict_data["field_offsets"].dict_data["9"].string_data = "protocol";
			protocols_4.dict_data["header_size_bytes"] = protocols_data();
			protocols_4.dict_data["header_size_bytes"].string_data = "20";
			protocols_4.dict_data["next_protocols"] = protocols_data();
			protocols_4.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_4.dict_data["next_protocols"].list_data[0].string_data = "8";
			protocols_4.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_4.dict_data["next_protocols"].list_data[1].string_data = "2048";
			protocols_4.dict_data["protocol_name"] = protocols_data();
			protocols_4.dict_data["protocol_name"].string_data = "IPPROTO_IPIP";
			protocols_4.dict_data["tail_offset"] = protocols_data();
			protocols_4.dict_data["tail_offset"].string_data = "9";
			protocols["4"] = protocols_4;

			protocols_41.dict_data["field_offsets"] = protocols_data();
			protocols_41.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_41.dict_data["field_offsets"].dict_data["0"].string_data = "priority";
			protocols_41.dict_data["field_offsets"].dict_data["1"] = protocols_data();
			protocols_41.dict_data["field_offsets"].dict_data["1"].string_data = "flow_lbl";
			protocols_41.dict_data["field_offsets"].dict_data["24"] = protocols_data();
			protocols_41.dict_data["field_offsets"].dict_data["24"].string_data = "daddr";
			protocols_41.dict_data["field_offsets"].dict_data["4"] = protocols_data();
			protocols_41.dict_data["field_offsets"].dict_data["4"].string_data = "payload_len";
			protocols_41.dict_data["field_offsets"].dict_data["6"] = protocols_data();
			protocols_41.dict_data["field_offsets"].dict_data["6"].string_data = "nexthdr";
			protocols_41.dict_data["field_offsets"].dict_data["7"] = protocols_data();
			protocols_41.dict_data["field_offsets"].dict_data["7"].string_data = "hop_limit";
			protocols_41.dict_data["field_offsets"].dict_data["8"] = protocols_data();
			protocols_41.dict_data["field_offsets"].dict_data["8"].string_data = "saddr";
			protocols_41.dict_data["header_size_bytes"] = protocols_data();
			protocols_41.dict_data["header_size_bytes"].string_data = "40";
			protocols_41.dict_data["next_protocols"] = protocols_data();
			protocols_41.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_41.dict_data["next_protocols"].list_data[0].string_data = "8";
			protocols_41.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_41.dict_data["next_protocols"].list_data[1].string_data = "2048";
			protocols_41.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_41.dict_data["next_protocols"].list_data[2].string_data = "34525";
			protocols_41.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_41.dict_data["next_protocols"].list_data[3].string_data = "56710";
			protocols_41.dict_data["protocol_name"] = protocols_data();
			protocols_41.dict_data["protocol_name"].string_data = "IPPROTO_IPV6";
			protocols_41.dict_data["tail_offset"] = protocols_data();
			protocols_41.dict_data["tail_offset"].string_data = "6";
			protocols["41"] = protocols_41;

			protocols_43144.dict_data["field_offsets"] = protocols_data();
			protocols_43144.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_43144.dict_data["field_offsets"].dict_data["0"].string_data = "h_vlan_TCI";
			protocols_43144.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_43144.dict_data["field_offsets"].dict_data["2"].string_data = "h_vlan_encapsulated_proto";
			protocols_43144.dict_data["header_size_bytes"] = protocols_data();
			protocols_43144.dict_data["header_size_bytes"].string_data = "4";
			protocols_43144.dict_data["next_protocols"] = protocols_data();
			protocols_43144.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_43144.dict_data["next_protocols"].list_data[0].string_data = "_1";
			protocols_43144.dict_data["protocol_name"] = protocols_data();
			protocols_43144.dict_data["protocol_name"].string_data = "VLAN";
			protocols_43144.dict_data["tail_offset"] = protocols_data();
			protocols_43144.dict_data["tail_offset"].string_data = "2";
			protocols["43144"] = protocols_43144;

			protocols_44.dict_data["field_offsets"] = protocols_data();
			protocols_44.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_44.dict_data["field_offsets"].dict_data["0"].string_data = "nexthdr";
			protocols_44.dict_data["field_offsets"].dict_data["1"] = protocols_data();
			protocols_44.dict_data["field_offsets"].dict_data["1"].string_data = "reserved";
			protocols_44.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_44.dict_data["field_offsets"].dict_data["2"].string_data = "frag_off";
			protocols_44.dict_data["field_offsets"].dict_data["4"] = protocols_data();
			protocols_44.dict_data["field_offsets"].dict_data["4"].string_data = "id";
			protocols_44.dict_data["header_size_bytes"] = protocols_data();
			protocols_44.dict_data["header_size_bytes"].string_data = "8";
			protocols_44.dict_data["next_protocols"] = protocols_data();
			protocols_44.dict_data["protocol_name"] = protocols_data();
			protocols_44.dict_data["protocol_name"].string_data = "IPPROTO_FRAGMENT";
			protocols_44.dict_data["tail_offset"] = protocols_data();
			protocols_44.dict_data["tail_offset"].string_data = "0";
			protocols["44"] = protocols_44;

			protocols_47.dict_data["field_offsets"] = protocols_data();
			protocols_47.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_47.dict_data["field_offsets"].dict_data["0"].string_data = "flags";
			protocols_47.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_47.dict_data["field_offsets"].dict_data["2"].string_data = "protocol";
			protocols_47.dict_data["header_size_bytes"] = protocols_data();
			protocols_47.dict_data["header_size_bytes"].string_data = "4";
			protocols_47.dict_data["next_protocols"] = protocols_data();
			protocols_47.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_47.dict_data["next_protocols"].list_data[0].string_data = "_1";
			protocols_47.dict_data["protocol_name"] = protocols_data();
			protocols_47.dict_data["protocol_name"].string_data = "GRE";
			protocols_47.dict_data["tail_offset"] = protocols_data();
			protocols_47.dict_data["tail_offset"].string_data = "2";
			protocols["47"] = protocols_47;

			protocols_48776.dict_data["field_offsets"] = protocols_data();
			protocols_48776.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_48776.dict_data["field_offsets"].dict_data["0"].string_data = "vlan_upper";
			protocols_48776.dict_data["field_offsets"].dict_data["1"] = protocols_data();
			protocols_48776.dict_data["field_offsets"].dict_data["1"].string_data = "vlan";
			protocols_48776.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_48776.dict_data["field_offsets"].dict_data["2"].string_data = "session_id_upper";
			protocols_48776.dict_data["field_offsets"].dict_data["3"] = protocols_data();
			protocols_48776.dict_data["field_offsets"].dict_data["3"].string_data = "session_id";
			protocols_48776.dict_data["header_size_bytes"] = protocols_data();
			protocols_48776.dict_data["header_size_bytes"].string_data = "4";
			protocols_48776.dict_data["next_protocols"] = protocols_data();
			protocols_48776.dict_data["protocol_name"] = protocols_data();
			protocols_48776.dict_data["protocol_name"].string_data = "ETH_P_ERSPAN";
			protocols_48776.dict_data["tail_offset"] = protocols_data();
			protocols_48776.dict_data["tail_offset"].string_data = "_1";
			protocols["48776"] = protocols_48776;

			protocols_49431.dict_data["field_offsets"] = protocols_data();
			protocols_49431.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_49431.dict_data["field_offsets"].dict_data["0"].string_data = "opt_len";
			protocols_49431.dict_data["field_offsets"].dict_data["1"] = protocols_data();
			protocols_49431.dict_data["field_offsets"].dict_data["1"].string_data = "ver";
			protocols_49431.dict_data["field_offsets"].dict_data["10"] = protocols_data();
			protocols_49431.dict_data["field_offsets"].dict_data["10"].string_data = "rsvd2";
			protocols_49431.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_49431.dict_data["field_offsets"].dict_data["2"].string_data = "rsvd1";
			protocols_49431.dict_data["field_offsets"].dict_data["3"] = protocols_data();
			protocols_49431.dict_data["field_offsets"].dict_data["3"].string_data = "critical";
			protocols_49431.dict_data["field_offsets"].dict_data["4"] = protocols_data();
			protocols_49431.dict_data["field_offsets"].dict_data["4"].string_data = "oam";
			protocols_49431.dict_data["field_offsets"].dict_data["5"] = protocols_data();
			protocols_49431.dict_data["field_offsets"].dict_data["5"].string_data = "proto_type";
			protocols_49431.dict_data["field_offsets"].dict_data["7"] = protocols_data();
			protocols_49431.dict_data["field_offsets"].dict_data["7"].string_data = "vni";
			protocols_49431.dict_data["header_size_bytes"] = protocols_data();
			protocols_49431.dict_data["header_size_bytes"].string_data = "11";
			protocols_49431.dict_data["next_protocols"] = protocols_data();
			protocols_49431.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_49431.dict_data["next_protocols"].list_data[0].string_data = "_1";
			protocols_49431.dict_data["protocol_name"] = protocols_data();
			protocols_49431.dict_data["protocol_name"].string_data = "GENEVE";
			protocols_49431.dict_data["tail_offset"] = protocols_data();
			protocols_49431.dict_data["tail_offset"].string_data = "5";
			protocols["49431"] = protocols_49431;

			protocols_56710.dict_data["field_offsets"] = protocols_data();
			protocols_56710.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_56710.dict_data["field_offsets"].dict_data["0"].string_data = "priority";
			protocols_56710.dict_data["field_offsets"].dict_data["1"] = protocols_data();
			protocols_56710.dict_data["field_offsets"].dict_data["1"].string_data = "flow_lbl";
			protocols_56710.dict_data["field_offsets"].dict_data["24"] = protocols_data();
			protocols_56710.dict_data["field_offsets"].dict_data["24"].string_data = "daddr";
			protocols_56710.dict_data["field_offsets"].dict_data["4"] = protocols_data();
			protocols_56710.dict_data["field_offsets"].dict_data["4"].string_data = "payload_len";
			protocols_56710.dict_data["field_offsets"].dict_data["6"] = protocols_data();
			protocols_56710.dict_data["field_offsets"].dict_data["6"].string_data = "nexthdr";
			protocols_56710.dict_data["field_offsets"].dict_data["7"] = protocols_data();
			protocols_56710.dict_data["field_offsets"].dict_data["7"].string_data = "hop_limit";
			protocols_56710.dict_data["field_offsets"].dict_data["8"] = protocols_data();
			protocols_56710.dict_data["field_offsets"].dict_data["8"].string_data = "saddr";
			protocols_56710.dict_data["header_size_bytes"] = protocols_data();
			protocols_56710.dict_data["header_size_bytes"].string_data = "40";
			protocols_56710.dict_data["next_protocols"] = protocols_data();
			protocols_56710.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_56710.dict_data["next_protocols"].list_data[0].string_data = "6";
			protocols_56710.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_56710.dict_data["next_protocols"].list_data[1].string_data = "17";
			protocols_56710.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_56710.dict_data["next_protocols"].list_data[2].string_data = "47";
			protocols_56710.dict_data["protocol_name"] = protocols_data();
			protocols_56710.dict_data["protocol_name"].string_data = "IPv6";
			protocols_56710.dict_data["tail_offset"] = protocols_data();
			protocols_56710.dict_data["tail_offset"].string_data = "6";
			protocols["56710"] = protocols_56710;

			protocols_6.dict_data["field_offsets"] = protocols_data();
			protocols_6.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_6.dict_data["field_offsets"].dict_data["0"].string_data = "source";
			protocols_6.dict_data["field_offsets"].dict_data["12"] = protocols_data();
			protocols_6.dict_data["field_offsets"].dict_data["12"].string_data = "flags";
			protocols_6.dict_data["field_offsets"].dict_data["14"] = protocols_data();
			protocols_6.dict_data["field_offsets"].dict_data["14"].string_data = "window";
			protocols_6.dict_data["field_offsets"].dict_data["16"] = protocols_data();
			protocols_6.dict_data["field_offsets"].dict_data["16"].string_data = "check";
			protocols_6.dict_data["field_offsets"].dict_data["18"] = protocols_data();
			protocols_6.dict_data["field_offsets"].dict_data["18"].string_data = "urg_ptr";
			protocols_6.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_6.dict_data["field_offsets"].dict_data["2"].string_data = "dest";
			protocols_6.dict_data["field_offsets"].dict_data["4"] = protocols_data();
			protocols_6.dict_data["field_offsets"].dict_data["4"].string_data = "seq";
			protocols_6.dict_data["field_offsets"].dict_data["8"] = protocols_data();
			protocols_6.dict_data["field_offsets"].dict_data["8"].string_data = "ack_seq";
			protocols_6.dict_data["header_size_bytes"] = protocols_data();
			protocols_6.dict_data["header_size_bytes"].string_data = "20";
			protocols_6.dict_data["next_protocols"] = protocols_data();
			protocols_6.dict_data["protocol_name"] = protocols_data();
			protocols_6.dict_data["protocol_name"].string_data = "TCP";
			protocols_6.dict_data["tail_offset"] = protocols_data();
			protocols_6.dict_data["tail_offset"].string_data = "_1";
			protocols["6"] = protocols_6;

			protocols_6081.dict_data["field_offsets"] = protocols_data();
			protocols_6081.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_6081.dict_data["field_offsets"].dict_data["0"].string_data = "opt_len";
			protocols_6081.dict_data["field_offsets"].dict_data["1"] = protocols_data();
			protocols_6081.dict_data["field_offsets"].dict_data["1"].string_data = "ver";
			protocols_6081.dict_data["field_offsets"].dict_data["10"] = protocols_data();
			protocols_6081.dict_data["field_offsets"].dict_data["10"].string_data = "rsvd2";
			protocols_6081.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_6081.dict_data["field_offsets"].dict_data["2"].string_data = "rsvd1";
			protocols_6081.dict_data["field_offsets"].dict_data["3"] = protocols_data();
			protocols_6081.dict_data["field_offsets"].dict_data["3"].string_data = "critical";
			protocols_6081.dict_data["field_offsets"].dict_data["4"] = protocols_data();
			protocols_6081.dict_data["field_offsets"].dict_data["4"].string_data = "oam";
			protocols_6081.dict_data["field_offsets"].dict_data["5"] = protocols_data();
			protocols_6081.dict_data["field_offsets"].dict_data["5"].string_data = "proto_type";
			protocols_6081.dict_data["field_offsets"].dict_data["7"] = protocols_data();
			protocols_6081.dict_data["field_offsets"].dict_data["7"].string_data = "vni";
			protocols_6081.dict_data["header_size_bytes"] = protocols_data();
			protocols_6081.dict_data["header_size_bytes"].string_data = "11";
			protocols_6081.dict_data["next_protocols"] = protocols_data();
			protocols_6081.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_6081.dict_data["next_protocols"].list_data[0].string_data = "_1";
			protocols_6081.dict_data["protocol_name"] = protocols_data();
			protocols_6081.dict_data["protocol_name"].string_data = "GENEVE";
			protocols_6081.dict_data["tail_offset"] = protocols_data();
			protocols_6081.dict_data["tail_offset"].string_data = "5";
			protocols["6081"] = protocols_6081;

			protocols_8.dict_data["field_offsets"] = protocols_data();
			protocols_8.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols_8.dict_data["field_offsets"].dict_data["0"].string_data = "ihl";
			protocols_8.dict_data["field_offsets"].dict_data["1"] = protocols_data();
			protocols_8.dict_data["field_offsets"].dict_data["1"].string_data = "tos";
			protocols_8.dict_data["field_offsets"].dict_data["10"] = protocols_data();
			protocols_8.dict_data["field_offsets"].dict_data["10"].string_data = "check";
			protocols_8.dict_data["field_offsets"].dict_data["12"] = protocols_data();
			protocols_8.dict_data["field_offsets"].dict_data["12"].string_data = "saddr";
			protocols_8.dict_data["field_offsets"].dict_data["16"] = protocols_data();
			protocols_8.dict_data["field_offsets"].dict_data["16"].string_data = "daddr";
			protocols_8.dict_data["field_offsets"].dict_data["2"] = protocols_data();
			protocols_8.dict_data["field_offsets"].dict_data["2"].string_data = "tot_len";
			protocols_8.dict_data["field_offsets"].dict_data["4"] = protocols_data();
			protocols_8.dict_data["field_offsets"].dict_data["4"].string_data = "id";
			protocols_8.dict_data["field_offsets"].dict_data["6"] = protocols_data();
			protocols_8.dict_data["field_offsets"].dict_data["6"].string_data = "frag_off";
			protocols_8.dict_data["field_offsets"].dict_data["8"] = protocols_data();
			protocols_8.dict_data["field_offsets"].dict_data["8"].string_data = "ttl";
			protocols_8.dict_data["field_offsets"].dict_data["9"] = protocols_data();
			protocols_8.dict_data["field_offsets"].dict_data["9"].string_data = "protocol";
			protocols_8.dict_data["header_size_bytes"] = protocols_data();
			protocols_8.dict_data["header_size_bytes"].string_data = "20";
			protocols_8.dict_data["next_protocols"] = protocols_data();
			protocols_8.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_8.dict_data["next_protocols"].list_data[0].string_data = "6";
			protocols_8.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_8.dict_data["next_protocols"].list_data[1].string_data = "17";
			protocols_8.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols_8.dict_data["next_protocols"].list_data[2].string_data = "47";
			protocols_8.dict_data["protocol_name"] = protocols_data();
			protocols_8.dict_data["protocol_name"].string_data = "IPv4";
			protocols_8.dict_data["tail_offset"] = protocols_data();
			protocols_8.dict_data["tail_offset"].string_data = "9";
			protocols["8"] = protocols_8;

			protocols__1.dict_data["field_offsets"] = protocols_data();
			protocols__1.dict_data["field_offsets"].dict_data["0"] = protocols_data();
			protocols__1.dict_data["field_offsets"].dict_data["0"].string_data = "h_dest";
			protocols__1.dict_data["field_offsets"].dict_data["12"] = protocols_data();
			protocols__1.dict_data["field_offsets"].dict_data["12"].string_data = "h_proto";
			protocols__1.dict_data["field_offsets"].dict_data["6"] = protocols_data();
			protocols__1.dict_data["field_offsets"].dict_data["6"].string_data = "h_source";
			protocols__1.dict_data["header_size_bytes"] = protocols_data();
			protocols__1.dict_data["header_size_bytes"].string_data = "14";
			protocols__1.dict_data["next_protocols"] = protocols_data();
			protocols__1.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols__1.dict_data["next_protocols"].list_data[0].string_data = "8";
			protocols__1.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols__1.dict_data["next_protocols"].list_data[1].string_data = "2048";
			protocols__1.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols__1.dict_data["next_protocols"].list_data[2].string_data = "56710";
			protocols__1.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols__1.dict_data["next_protocols"].list_data[3].string_data = "34525";
			protocols__1.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols__1.dict_data["next_protocols"].list_data[4].string_data = "1544";
			protocols__1.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols__1.dict_data["next_protocols"].list_data[5].string_data = "2054";
			protocols__1.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols__1.dict_data["next_protocols"].list_data[6].string_data = "129";
			protocols__1.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols__1.dict_data["next_protocols"].list_data[7].string_data = "34984";
			protocols__1.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols__1.dict_data["next_protocols"].list_data[8].string_data = "33024";
			protocols__1.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols__1.dict_data["next_protocols"].list_data[9].string_data = "43144";
			protocols__1.dict_data["next_protocols"].list_data.push_back(protocols_data());
			protocols__1.dict_data["next_protocols"].list_data[10].string_data = "47";
			protocols__1.dict_data["protocol_name"] = protocols_data();
			protocols__1.dict_data["protocol_name"].string_data = "Ethernet";
			protocols__1.dict_data["tail_offset"] = protocols_data();
			protocols__1.dict_data["tail_offset"].string_data = "12";
			protocols["-1"] = protocols__1;


        }
    
		std::vector<helper_functions_data> get_arguments(std::string helper_functions_id) {
			if (helper_functions[helper_functions_id].dict_data.find("arguments") == helper_functions[helper_functions_id].dict_data.end()) {
				return {};
			}
			return helper_functions[helper_functions_id].dict_data["arguments"].list_data;
		}


		std::vector<helper_functions_data> get_compatible_hookpoints(std::string helper_functions_id) {
			if (helper_functions[helper_functions_id].dict_data.find("compatible_hookpoints") == helper_functions[helper_functions_id].dict_data.end()) {
				return {};
			}
			return helper_functions[helper_functions_id].dict_data["compatible_hookpoints"].list_data;
		}


		std::string get_does_packet_manipulation(std::string helper_functions_id) {
			if (helper_functions[helper_functions_id].dict_data.find("does_packet_manipulation") == helper_functions[helper_functions_id].dict_data.end()) {
				return "";
			}
			return helper_functions[helper_functions_id].dict_data["does_packet_manipulation"].string_data;
		}


		std::string get_helper_function_name(std::string helper_functions_id) {
			if (helper_functions[helper_functions_id].dict_data.find("helper_function_name") == helper_functions[helper_functions_id].dict_data.end()) {
				return "";
			}
			return helper_functions[helper_functions_id].dict_data["helper_function_name"].string_data;
		}


		std::map<std::string, map_info_data> get_rules(std::string map_info_id) {
			if (map_info[map_info_id].dict_data.find("rules") == map_info[map_info_id].dict_data.end()) {
				return {};
			}
			return map_info[map_info_id].dict_data["rules"].dict_data;
		}


		std::map<std::string, protocols_data> get_field_offsets(std::string protocols_id) {
			if (protocols[protocols_id].dict_data.find("field_offsets") == protocols[protocols_id].dict_data.end()) {
				return {};
			}
			return protocols[protocols_id].dict_data["field_offsets"].dict_data;
		}


		std::string get_header_size_bytes(std::string protocols_id) {
			if (protocols[protocols_id].dict_data.find("header_size_bytes") == protocols[protocols_id].dict_data.end()) {
				return "";
			}
			return protocols[protocols_id].dict_data["header_size_bytes"].string_data;
		}


		std::vector<protocols_data> get_next_protocols(std::string protocols_id) {
			if (protocols[protocols_id].dict_data.find("next_protocols") == protocols[protocols_id].dict_data.end()) {
				return {};
			}
			return protocols[protocols_id].dict_data["next_protocols"].list_data;
		}


		std::string get_protocol_name(std::string protocols_id) {
			if (protocols[protocols_id].dict_data.find("protocol_name") == protocols[protocols_id].dict_data.end()) {
				return "";
			}
			return protocols[protocols_id].dict_data["protocol_name"].string_data;
		}


		std::string get_tail_offset(std::string protocols_id) {
			if (protocols[protocols_id].dict_data.find("tail_offset") == protocols[protocols_id].dict_data.end()) {
				return "";
			}
			return protocols[protocols_id].dict_data["tail_offset"].string_data;
		}


};
