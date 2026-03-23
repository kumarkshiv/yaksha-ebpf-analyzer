#include "Make_cfg.hpp"

map<int, Make_cfg::block> Make_cfg::make_basic_blocks(vector<bpf_insn> inst_list)
{
    // set for leader instructions
    set<int> leader_inst;
    leader_inst.insert(0);

    for (int i = 0; i < inst_list.size(); i++)
    {
        char opcode[3];
        char code[4];
        sprintf(opcode, "%x", (BPF_CLASS(inst_list[i].code)));
        sprintf(code, "%x", (BPF_OP(inst_list[i].code)));

        // need JMP and JMP32 instructions, but have to handle the case of BPF_JA and BPF_CALL and BPF_EXIT differently.
        if ((strcmp(opcode, "5") == 0 || strcmp(opcode, "6") == 0) && (strcmp(code, "0") != 0 || strcmp(code, "8") != 0 || strcmp(code, "90") != 0))
        {
            // Case of conditional jump
            if (i + 1 < inst_list.size())
            {
                leader_inst.insert(i + 1);
            }
            if (i + inst_list[i].off + 1 < inst_list.size())
            {
                leader_inst.insert(i + inst_list[i].off + 1);
            }
        }
        else if ((strcmp(opcode, "5") == 0 || strcmp(opcode, "6") == 0) && (strcmp(code, "0") == 0))
        {
            // case of BPF_JA
            if (i + inst_list[i].off + 1 < inst_list.size())
            {
                leader_inst.insert(i + inst_list[i].off + 1);
            }
        }
        else if ((strcmp(opcode, "5") == 0 || strcmp(opcode, "6") == 0) && (strcmp(code, "0") == 90))
        {
            // case of BPF_EXIT
            if (i + 1 < inst_list.size())
            {
                leader_inst.insert(i + 1);
            }
        }
    }

    // mapping leader instructions to serial numbers

    map<int, int> leader_inst_serial;
    int serial_no = 0;
    set<int>::iterator leader_iter;
    for (leader_iter = leader_inst.begin(); leader_iter != leader_inst.end(); ++leader_iter)
    {
        leader_inst_serial.insert({*leader_iter, serial_no});
        serial_no++;
    }

    // making the basic blocks
    vector<block> basic_blocks;
    for (leader_iter = leader_inst.begin(); leader_iter != leader_inst.end(); ++leader_iter)
    {
        block new_block;
        new_block.bb_first = *leader_iter;

        // for the last basic block only
        if (std::distance(leader_iter, --leader_inst.end()) == 0)
        {
            new_block.bb_last = inst_list.size() - 1;
        }
        else
        {
            new_block.bb_last = *++leader_iter - 1; // because the set automatically orders the elements in increasing order
            --leader_iter;
        }
        char opcode[3];
        char code[4];
        sprintf(opcode, "%x", (BPF_CLASS(inst_list[new_block.bb_last].code)));
        sprintf(code, "%x", (BPF_OP(inst_list[new_block.bb_last].code)));
        // unconditional jump
        if ((strcmp(opcode, "5") == 0 || strcmp(opcode, "6") == 0) && ((strcmp(code, "0") == 0) || (strcmp(code, "90") == 0)))
        {
            if (strcmp(code, "0") == 0){
                new_block.next_bb.insert(leader_inst_serial[new_block.bb_last + inst_list[new_block.bb_last].off + 1]);
            }
            // If code is 90, then Program exits. So, no successor.
        }
        // conditional jump
        else if ((strcmp(opcode, "5") == 0 || strcmp(opcode, "6") == 0))
        {
            new_block.next_bb.insert(leader_inst_serial[new_block.bb_last + 1]);
            new_block.next_bb.insert(leader_inst_serial[new_block.bb_last + inst_list[new_block.bb_last].off + 1]);
        }
        else
        {
            new_block.next_bb.insert(leader_inst_serial[new_block.bb_last + 1]);
        }
        
        basic_blocks.push_back(new_block);
    }

    // printing the leader_inst_serial map
    map<int, int>::iterator map_iter;
    for (map_iter = leader_inst_serial.begin(); map_iter != leader_inst_serial.end(); ++map_iter)
    {
        // cout << map_iter->first << " " << map_iter->second << endl;
    }

    // printing the basic blocks
    for (block &e : basic_blocks)
    {
        // cout << e.bb_first << " to " << e.bb_last;
        // cout << " and successors are: ";
        for (const int &i : e.next_bb)
        {
            // cout << i << " ";
        }
        // cout << endl;
    }

    // making a map where keys are serial numbers and values are basic blocks
    map<int, block> bb_map;
    for (block &e : basic_blocks)
    {
        bb_map.insert({leader_inst_serial[e.bb_first], e});
    }

    // returning the map
    return bb_map;
}

Graph Make_cfg::make_cfg_from_basic_blocks(map<int, Make_cfg::block> bb_map)
{
    vector<edge> edge_list;
    map<int, block>::iterator bb_iter;

    // adding edges to edge list
    for (bb_iter = bb_map.begin(); bb_iter != bb_map.end(); ++bb_iter)
    {
        for (const int &i : bb_iter->second.next_bb)
        {
            edge ed;
            ed.src_bb = bb_iter->first;
            ed.dst_bb = i;
            edge_list.push_back(ed);
        }
    }

    Graph g(bb_map.size());
    int node_index = 0;
    // cout << bb_map.size() << endl;

    // adding vertices to graph
    for (bb_iter = bb_map.begin(); bb_iter != bb_map.end(); ++bb_iter)
    {
        g[node_index].bb_first = bb_iter->second.bb_first;
        g[node_index].bb_last = bb_iter->second.bb_last;
        g[node_index].name = to_string(bb_iter->second.bb_first) + "-" + to_string(bb_iter->second.bb_last);
        g[node_index].s_no = node_index;
        node_index++;
    }

    // adding edges to graph
    // cout << "\nEdges(Basic Blocks):\n";
    for (int i = 0; i < edge_list.size(); i++)
    {
        boost::add_edge(edge_list.at(i).src_bb, edge_list.at(i).dst_bb, {"e" + to_string(i)}, g); // EDGETAG : change the name here based on action info.
        // cout << edge_list.at(i).src_bb << "->" << edge_list.at(i).dst_bb << endl;
    }
    return g;
}

Graph Make_cfg::add_network_context(vector<network_context> network_context, Graph cfg)
{
    // iterating through cfg and adding network context
    for (int i = 0; i < boost::num_vertices(cfg); i++)
    {
        int inst_start = cfg[i].bb_first;
        int inst_end = cfg[i].bb_last;

        /* set-union of information from each instruction in a basic block */

        for (int j = inst_start; j <= inst_end; j++)
        {
            string proto;
            if (network_context[j].protocol.protocol_name != "" and network_context[j].protocol.protocol_name != " ")
            {
                // One cfg node can have multiple protocols. So concatenating the protocol names to header field info in that node.
                // As of now, action criteria and action not needed, so not concatenating to that.
                proto = network_context[j].protocol.protocol_name;
                cfg[i].context_info.protocol.protocol_names.insert(proto);
            }
            for (const string &k : network_context[j].protocol.header_fields_accessed)
            {
                if (k != "" and k != " ")
                    cfg[i].context_info.protocol.header_fields_accessed.insert(proto + "." + k);
            }

            if (!(network_context[j].protocol.action_criteria_and_action == make_pair(string(""), string(""))) and
                !(network_context[j].protocol.action_criteria_and_action == make_pair(string(" "), string(" "))))
            {
                cfg[i].context_info.protocol.action_criteria_and_action.insert(network_context[j].protocol.action_criteria_and_action);
            }

            for (auto &k : network_context[j].protocol.header_fields_updated)
            {
                if (k.first != "" and k.first != " ")
                {

                    cfg[i].context_info.protocol.header_fields_updated.insert(make_pair(proto + "." + k.first, k.second));
                }
            }

            // helper functions
            if (network_context[j].helper.name_of_helper_function != "" and network_context[j].helper.name_of_helper_function != " ")
            {
                cfg[i].context_info.helper.helper_function_info.insert(make_tuple(network_context[j].helper.name_of_helper_function, network_context[j].helper.helper_id, network_context[j].helper.does_packet_manipulation));
            }

            // maps

            if (network_context[j].map_information.name_of_map != "" and network_context[j].map_information.name_of_map != " ")
            {
                cfg[i].context_info.map_information.map_info.insert(make_tuple(network_context[j].map_information.name_of_map, network_context[j].map_information.size_of_key, network_context[j].map_information.tag_of_the_key, network_context[j].map_information.size_of_value, network_context[j].map_information.tag_of_the_value));
            }
        }
    }

    // Export the graph to a DOT file with custom attributes

    // Function to print the set of tuples header_fields_updated, with commas in between
    auto print_header_fields_updated = [](set<pair<string, string>> v)
    {
        vector<string> s;
        for (auto &k : v)
        {
            s.push_back("(" + k.first + ", updated with value: " + k.second + ")");
        }
        return boost::algorithm::join(s, ", ");
    };

    // function to print the set of tuples helper_name_packet_manipulation, with commas in between
    auto print_helper_name_packet_manipulation = [](set<tuple<string, int, string>> v)
    {
        vector<string> s;
        for (auto &k : v)
        {
            s.push_back("(" + get<0>(k) + ", Packet_Man: " + get<2>(k) + ")");
        }
        return boost::algorithm::join(s, ", ");
    };

    // function to print the set of tuples map_info, with commas in between
    auto print_map_info = [](set<tuple<string, int, string, int, string>> v)
    {
        vector<string> s;
        for (auto &k : v)
        {
            s.push_back(get<0>(k));
        }
        return boost::algorithm::join(s, ", ");
    };

    // function to print the set of tuples action_criteria_and_action, with commas in between
    auto print_action_criteria_and_action = [](set<pair<string, string>> v)
    {
        vector<string> s;
        for (auto &k : v)
        {
            s.push_back("(" + k.first + ", " + k.second + ")");
        }
        return boost::algorithm::join(s, ", ");
    };

    std::ofstream dotFile(prog_name + ".dot");
    dotFile << "digraph G {\n";
    BGL_FORALL_VERTICES(v, cfg, Graph)
    {
        dotFile << "  " << v << " [shape=\"box\", style=\"rounded\", label=\"I : " << cfg[v].bb_first << " - " << cfg[v].bb_last << ", BB: " << cfg[v].s_no
                << (cfg[v].context_info.protocol.protocol_names.size() > 0 ? "\\nProtocols: " : "") << boost::algorithm::join(cfg[v].context_info.protocol.protocol_names, ", ")
                << (cfg[v].context_info.protocol.header_fields_accessed.size() > 0 ? "\\nHeader Fields Accessed: " : "") << boost::algorithm::join(cfg[v].context_info.protocol.header_fields_accessed, ", ")
                // << (cfg[v].context_info.protocol.action_criteria_and_action.size() > 0 ? "\\nAction Criteria and Action: " : "") << print_action_criteria_and_action(cfg[v].context_info.protocol.action_criteria_and_action)
                << (cfg[v].context_info.protocol.header_fields_updated.size() > 0 ? "\\nHeader Fields Updated: " : "") << print_header_fields_updated(cfg[v].context_info.protocol.header_fields_updated)
                << (cfg[v].context_info.helper.helper_function_info.size() > 0 ? "\\nHelper Functions: " : "") << print_helper_name_packet_manipulation(cfg[v].context_info.helper.helper_function_info)
                << (cfg[v].context_info.map_information.map_info.size() > 0 ? "\\nMaps: " : "") << print_map_info(cfg[v].context_info.map_information.map_info)
                << "\"];\n";
    }
    BGL_FORALL_EDGES(e, cfg, Graph)
    {
        dotFile << "  " << source(e, cfg) << " -> " << target(e, cfg) << ";\n";
    }
    dotFile << "}\n";

    return cfg;
}
