// Define all the functions required to extract the info from network context
// Define the Query Engine class too.

#include <iostream>
#include <boost/graph/graphviz.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/graph/depth_first_search.hpp>
#include "netcxt_structs.hpp"
#include "tabulate.hpp"

typedef boost::adjacency_list<boost::vecS, boost::vecS, boost::directedS, VertexProps, EdgeProps> Graph;

class dfs_visitor_protocol : public boost::default_dfs_visitor
{
    private:
        protocol_network_context_cfg *all_protocol_info_ptr;
    public:
        dfs_visitor_protocol(protocol_network_context_cfg *all_protocol_info_ptr) {
            this->all_protocol_info_ptr = all_protocol_info_ptr;
        }
        void discover_vertex(boost::graph_traits<Graph>::vertex_descriptor v, const Graph &g);
};

class dfs_visitor_header_fields : public boost::default_dfs_visitor
{
    private:
        protocol_network_context_cfg *all_header_fields_info_ptr;
    public:
        dfs_visitor_header_fields(protocol_network_context_cfg *all_header_fields_info_ptr) {
            this->all_header_fields_info_ptr = all_header_fields_info_ptr;
        }
        void discover_vertex(boost::graph_traits<Graph>::vertex_descriptor v, const Graph &g);
};

class dfs_visitor_helper_functions : public boost::default_dfs_visitor
{
    private:
        helper_network_context_cfg *all_helper_functions_info_ptr;
    public:
        dfs_visitor_helper_functions(helper_network_context_cfg *all_helper_functions_info_ptr) {
            this->all_helper_functions_info_ptr = all_helper_functions_info_ptr;
        }
        void discover_vertex(boost::graph_traits<Graph>::vertex_descriptor v, const Graph &g);
};

class dfs_visitor_maps : public boost::default_dfs_visitor
{
    private:
        map_network_context_cfg *all_map_info_ptr;
    public:
        dfs_visitor_maps(map_network_context_cfg *all_map_info_ptr) {
            this->all_map_info_ptr = all_map_info_ptr;
        }
        void discover_vertex(boost::graph_traits<Graph>::vertex_descriptor v, const Graph &g);
};


class QueryEngine
{
    private:
        std::string intro = "Welcome to Query Engine v1.0";
        std::string help = R"(

            Help Page

                h       :       Print this page
                p       :       List all the protocols used
                o       :       List all header fields accessed and updated
                f       :       List all the helper functions used
                m       :       List all the maps used
            )";
        std::string outro = "Thanks for using Query Engine v1.0";

        vector<int> get_out_edges(Graph cfg, int vertex);

        protocol_network_context_cfg all_protocol_info;
        protocol_network_context_cfg all_header_fields_info;
        helper_network_context_cfg all_helper_functions_info;
        map_network_context_cfg all_map_info;

        void list_protocol_information(Graph cfg);
        void list_header_fields(Graph cfg);
        void list_helper_functions(Graph cfg);
        void list_map_information(Graph cfg);

        void print_table(tabulate::Table table);

    public:
        QueryEngine();
        void run(Graph cfg);
};
