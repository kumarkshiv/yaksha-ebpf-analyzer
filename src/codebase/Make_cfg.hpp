#include <iostream>
#include <bpf/libbpf.h>
#include <bpf/libbpf_common.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <boost/graph/graphviz.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/algorithm/string/join.hpp>
#include "netcxt_structs.hpp"

using namespace std;

/*
	Refer: https://www.boost.org/doc/libs/1_55_0/libs/graph/doc/adjacency_list.html
	This adjacency_list holds the network context for every Node/Vertex
*/
typedef boost::adjacency_list<boost::vecS, boost::vecS, boost::directedS, VertexProps, EdgeProps> Graph;

class Make_cfg
{
private:
	struct block
	{
		int bb_first;
		int bb_last;
		set<int> next_bb;
	};
	struct edge
	{
		int src_bb; // the leader inst of the source bb
		int dst_bb; // leader inst of the dest bb
	};

	string prog_name;

	map<int, block> make_basic_blocks(vector<bpf_insn> inst_list);
	Graph make_cfg_from_basic_blocks(map<int, block> bb_map);
	Graph add_network_context(vector<network_context> network_context, Graph cfg);

public:
	Graph make_cfg(vector<bpf_insn> inst_list, vector<network_context> network_context, string prog)
	{
		prog_name = prog;
		map<int, block>
			bb_map = make_basic_blocks(inst_list);
		Graph cfg = make_cfg_from_basic_blocks(bb_map);
		Graph final_cfg = add_network_context(network_context, cfg);
		return final_cfg;
	}
};

/*
TO RUN MAIN FILE eBPF_parser.cpp THAT INCLUDES THIS FILE:

g++ eBPF_parser.cpp -o eBPF_parser -lbpf -lelf -lz -I/home/netx9/libbpf_old/include/uapi -L/usr/local/lib
./eBPF_parser ./test_files/object_files/ether_ip_ipv6_tcp_udp.o xdp_parser_func
dot -Tpdf graph.dot > test_final.pdf

*/