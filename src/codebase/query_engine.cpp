#include "query_engine.hpp"

using namespace std;
using namespace tabulate;

/* Function to get the vertices connected to a given vertex*/
vector<int> QueryEngine::get_out_edges(Graph cfg, int vertex)
{
    typedef boost::graph_traits<Graph>::adjacency_iterator adjacency_iterator;
    adjacency_iterator ai_start, ai_end;
    boost::tie(ai_start, ai_end) = adjacent_vertices(vertex, cfg);
    vector<int> out_edges;
    for (adjacency_iterator iter = ai_start; iter != ai_end; ++iter)
    {
        out_edges.push_back(*iter);
    }
    return out_edges;
}

void QueryEngine::print_table(Table table)
{
    table[0].format()
    .font_style({FontStyle::bold})
    .font_align(FontAlign::center);

    for(int i=1 ; i < table.size() ; i++){
        table[i].format()
        .font_align(FontAlign::center);
    }
    
    table.format()
    .padding_top(1)
    .padding_bottom(1)
    .font_align(FontAlign::center)
    .border_top(" ")
    .border_bottom(" ")
    .border_left(" ")
    .border_right(" ")
    .corner(" ");

    std::cout << table << endl << endl;
}

void dfs_visitor_protocol::discover_vertex(boost::graph_traits<Graph>::vertex_descriptor v, const Graph &g)
{
    // copy protocol name from v to protocol_network_context_info_ptr
    all_protocol_info_ptr->protocol_names.insert(g[v].context_info.protocol.protocol_names.begin(), g[v].context_info.protocol.protocol_names.end());
}

void dfs_visitor_header_fields::discover_vertex(boost::graph_traits<Graph>::vertex_descriptor v, const Graph &g)
{
    all_header_fields_info_ptr->header_fields_accessed.insert(g[v].context_info.protocol.header_fields_accessed.begin(), g[v].context_info.protocol.header_fields_accessed.end());
    all_header_fields_info_ptr->header_fields_updated.insert(g[v].context_info.protocol.header_fields_updated.begin(), g[v].context_info.protocol.header_fields_updated.end());
}

void dfs_visitor_helper_functions::discover_vertex(boost::graph_traits<Graph>::vertex_descriptor v, const Graph &g)
{
    all_helper_functions_info_ptr->helper_function_info.insert(g[v].context_info.helper.helper_function_info.begin(), g[v].context_info.helper.helper_function_info.end());
}

void dfs_visitor_maps::discover_vertex(boost::graph_traits<Graph>::vertex_descriptor v, const Graph &g)
{
    all_map_info_ptr->map_info.insert(g[v].context_info.map_information.map_info.begin(), g[v].context_info.map_information.map_info.end());
}   

void QueryEngine::list_protocol_information(Graph cfg)
{
    dfs_visitor_protocol vis(&all_protocol_info);
    boost::depth_first_search(cfg, boost::visitor(vis));

    Table QEoutput;
    QEoutput.add_row({"Protocol Names"});
    
    for (const string &s : all_protocol_info.protocol_names){
        QEoutput.add_row({s});
    }
    
    print_table(QEoutput);
}

void QueryEngine::list_header_fields(Graph cfg) 
{
    dfs_visitor_header_fields vis(&all_header_fields_info);
    boost::depth_first_search(cfg, boost::visitor(vis));

    Table QEoutput_1;
    QEoutput_1.add_row({"Header Fields accessed"});

    for (const string &s : all_header_fields_info.header_fields_accessed){
        QEoutput_1.add_row({s});
    }

    Table QEoutput_2;
    QEoutput_2.add_row({"Header Fields Updated", "Value Updated With"});

    for (const auto &s : all_header_fields_info.header_fields_updated){
        QEoutput_2.add_row({s.first, s.second});
    }
    
    print_table(QEoutput_1);
    print_table(QEoutput_2);
}

void QueryEngine::list_helper_functions(Graph cfg) 
{
    dfs_visitor_helper_functions vis(&all_helper_functions_info);
    boost::depth_first_search(cfg, boost::visitor(vis));

    Table QEoutput;
    QEoutput.add_row({"Helper Function Name", "Helper Function Type", "Helper Function Arguments"});

    for (const auto &s : all_helper_functions_info.helper_function_info){
        QEoutput.add_row({get<0>(s), to_string(get<1>(s)), get<2>(s)});
    }
    
    print_table(QEoutput);
}

void QueryEngine::list_map_information(Graph cfg)
{
    dfs_visitor_maps vis(&all_map_info);
    boost::depth_first_search(cfg, boost::visitor(vis));

    Table QEoutput;
    QEoutput.add_row({"Map Name", "Key Size", "Key Tag", "Value Size", "Value Tag"});

    for (const auto &s : all_map_info.map_info){
        QEoutput.add_row({get<0>(s), to_string(get<1>(s)), get<2>(s), to_string(get<3>(s)), get<4>(s)});
    }
    
    print_table(QEoutput);
}


QueryEngine::QueryEngine()
{
    // Constructor class for Query Engine
    cout << "Query Engine Instantiated" << endl;
}

void QueryEngine::run(Graph cfg)
{
    cout << intro << endl;
    char condition;

    while (true)
    {
        cout << ">>> Enter an option (protocols/maps/helpers): ";
        cin >> condition;
        switch (condition)
        {
            case 'q':
            {
                cout << outro << endl;
                return;
            };
            case 'h':
            {
                cout << help << endl;
                break;
            };
            case 'p':
            {
                list_protocol_information(cfg);
                break;
            };
            case 'o':
            {
                list_header_fields(cfg);
                break;
            };	
            case 'f':
            {
                list_helper_functions(cfg);
                break;
            };
            case 'm':
            {
                list_map_information(cfg);
                break;
            };
            default:
            {
                cout << "Invalid argument. Please refer the help page for information" << endl;
            }
            
        };
    
    }
}
