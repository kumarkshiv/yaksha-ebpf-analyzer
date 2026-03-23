#include "ebpf_parser.cpp"
#include "Make_cfg.cpp"
#include "query_engine.cpp"

int main(int argc, char *argv[])
{
    vector<string> prog_names;
    vector<string> prog_func_names;
    int selected_prog;
    string selected_prog_name;
    string selected_prog_func_name;

    /*
    ###################### Commands to compile: ######################
    $ g++ -std=c++17 main.cpp -o main_output -lbpf -lelf -lz -I/home/netx9/libbpf/include/uapi -L/usr/local/lib -I/home/netx9/libbpf0_0.8.1/libbpf-0.8.1/src/ -I./ELFIO/
    $ ./main_output ../../ebpf_repo_internal/test_files/object_files/mptm.o
    */

    const char *filename = argv[1];
    if (argc > 1)
    {
        cout << "\n File Name -> " << filename << endl;
    }
    else
    {
        cout << "Please add <object_file.o> as CLI arguments." << endl;
        return (0);
    }

    struct bpf_object *obj, *loaded_obj;
    struct bpf_program *prog, *loaded_prog, *bpf_prog;
    const struct bpf_insn *orig_insns;
    int inst_count;

    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj))
    {
        cout << stderr, "\nERROR: opening BPF object file failed\n";
        exit;
    }

    bpf_object__for_each_program(prog, obj)
    {
        const char *program_name = bpf_program__name(prog);
        const char *section_name = bpf_program__section_name(prog);
        prog_names.push_back(section_name);
        prog_func_names.push_back(program_name);
        cout << "section_name: " << section_name << ", program_name: " << program_name << " : " << bpf_program__insn_cnt(prog) << endl;
    }

    cout << "Select the program section to analyze: " << endl;
    for (int i = 0; i < prog_names.size(); i++)
    {
        cout << i + 1 << ") " << prog_names.at(i) << "( " << prog_func_names.at(i) << ")" << endl;
    }
    cout << "Choice: ";
    cin >> selected_prog;
    cout << "Selected program is: " << selected_prog << ") " << prog_names.at(selected_prog - 1) << "(" << prog_func_names.at(selected_prog - 1) << ")" << endl;
    selected_prog_name = prog_names.at(selected_prog - 1);
    selected_prog_func_name = prog_func_names.at(selected_prog - 1);

    vector<bpf_insn> inst_list;
    vector<network_context> network_context;
    parse_main(filename, selected_prog_name, selected_prog_func_name, &inst_list, &network_context);

    Make_cfg cfg_obj;
    Graph final_cfg = cfg_obj.make_cfg(inst_list, network_context, selected_prog_func_name);

    QueryEngine qe = QueryEngine();
    qe.run(final_cfg);

    return(0);
}