#include <iostream>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
#include <vector>
#include <map>
#include <unistd.h>
#include <algorithm>

#define     HEADERS         {"iostream", "vector", "map", "string"}

struct my_struct {
    /*
    The integers ad strings are stored in the string_data field of the struct.
    The maps are stored in the dict_data field of the struct. Each value of the key in this map with be a protocol_data struct.
    The lists are stored in the list_data field of the struct. Each value of the list will be a protocol_data struct.
    Only one field will take a non-NULL value at a time. The other two will be empty. This will NOT hold if any of the values in the JSON are NULL.
    */
    std::string string_data;
    std::map <std::string, my_struct> dict_data;
    std::vector <my_struct> list_data;
    std::map <std::string, std::string> type_map;
};

my_struct parse_data(const boost::property_tree::ptree& root) {

    my_struct data;

    if (root.empty()) {
        // This is a leaf node.
        if (!root.data().empty()) {
            // This is a string.
            std::string key = root.data();
            std::replace(key.begin(), key.end(), '-', '_');
            data.string_data = key;
        }
        return data;
    }

    // Root is either a map or list
    BOOST_FOREACH(boost::property_tree::ptree::value_type node, root) {

        // data.type_map[node.first] = typeid(node.second).name();
        if (node.second.empty()) {
            // This is a leaf node.
            if (!node.second.data().empty()) {
                // This is a string.
                std::string key = node.first;
                std::replace(key.begin(), key.end(), '-', '_');
                data.type_map[key] = "string";
                data.dict_data[key] = parse_data(node.second);
            } else {
                std::string key = node.first;
                std::replace(key.begin(), key.end(), '-', '_');
                data.type_map[key] = "vector";
                data.dict_data[key] = parse_data(node.second);
            }
        } else if (node.second.count("") == 0) {
            // This is a dictionary or a map
            std::string key = node.first;
            std::replace(key.begin(), key.end(), '-', '_');
            data.type_map[key] = "map";
            data.dict_data[key] = parse_data(node.second);
        } else {
            // This is a list or vector
            data.type_map[node.first] = "vector";
            std::string key = node.first;
            std::replace(key.begin(), key.end(), '-', '_');
            BOOST_FOREACH(boost::property_tree::ptree::value_type tmp, node.second) {
                data.dict_data[key].list_data.push_back(parse_data(tmp.second));
            }
        }
    }
    return data;
}


// Function to dump the header file constructs in the spec file
void dump_headers(std::ofstream *file, std::vector<std::string> headers) {
    for (auto header : headers) {
        *file << "#include <" << header << ">" << std::endl;
    }

    *file << std::endl;
}

// Function to dump the struct and typedef definitions in the spec file
void dump_structure_defs(std::ofstream *file, std::vector<std::string> typedefs={}) {
    std::string structure = R"(
struct my_struct {
    std::string string_data = "";
    std::map <std::string, my_struct> dict_data = {};
    std::vector <my_struct> list_data = {};
};
)";

    *file << structure << std::endl;

    for (auto typedef_name : typedefs) {
        *file << "typedef struct my_struct " << typedef_name << ";" << std::endl;
    }
    *file << std::endl;

}

// Function to dump the struct variables in the spec file. This is a recursive function. Variables are private to the class
void dump_struct_variables(std::ofstream *file, my_struct data, std::string parent_key, std::string structure) {

    // Set string data to the struct variable
    if (data.string_data != "") {
        *file << parent_key << ".string_data = \"" << data.string_data << "\";" << std::endl;
    }

    // Set map data to the struct variable
    if (data.dict_data.size() > 0) {
        for (auto key : data.dict_data) {
            *file << parent_key << ".dict_data[\"" << key.first << "\"] = " << structure << "();" << std::endl;
            dump_struct_variables(file, key.second, parent_key + ".dict_data[\"" + key.first + "\"]", structure);
        }
    }

    // Set list data to the struct variable
    if (data.list_data.size() > 0) {
        for (int i = 0; i < data.list_data.size(); i++) {
            *file << parent_key << ".list_data.push_back(" << structure << "());" << std::endl;
            dump_struct_variables(file, data.list_data[i], parent_key + ".list_data[" + std::to_string(i) + "]", structure);
        }
    }
}

// Helper function for the dump_getter_funcs function to get the field names and their datatypes
std::map<std::string, std::string> get_struct_types(my_struct data) {
    std::map<std::string, std::string> struct_types;
    
    for (auto key : data.dict_data) {
        for (auto key2 : key.second.dict_data) {
            if (struct_types.find(key2.first) == struct_types.end()) {
                struct_types[key2.first] = key.second.type_map[key2.first];
            }
        }
    }
    return struct_types;
}

// Helper function for the dump_getter_funcs function to generate the getter functions strings for each field. The strings are used to dump the function constructs in the header file.
std::string generate_function(std::string function_name, std::string spec_name, std::string field_name, std::string return_type, std::string default_return_type, std::string argument_name, std::string argument_data_type) {
    
    std::string structure;
    
    structure = "\t\t" + return_type + " " + function_name + "(" + argument_data_type + " " + argument_name + ") {\n";
    structure = structure + "\t\t\t" + "if (" + spec_name + "["+ argument_name + "]" + ".dict_data.find(\"" + field_name + "\") == " + spec_name + "[" + argument_name +"]" ".dict_data.end()) {\n";
    structure = structure + "\t\t\t\t" + "return "+ default_return_type + ";\n";
    structure = structure + "\t\t\t" + "}\n";

    if (return_type == "std::string") {
        structure = structure + "\t\t\t" + "return " + spec_name + "["+ argument_name + "]" + ".dict_data[\"" + field_name + "\"].string_data;\n";
    } else if (return_type == "std::map<std::string, " + spec_name + "_data>") {
        structure = structure + "\t\t\t" + "return " + spec_name + "["+ argument_name + "]" + ".dict_data[\"" + field_name + "\"].dict_data;\n";
    } else if (return_type == "std::vector<" + spec_name + "_data>") {
        structure = structure + "\t\t\t" + "return " + spec_name + "["+ argument_name + "]" + ".dict_data[\"" + field_name + "\"].list_data;\n";
    }

    structure = structure + "\t\t" + "}\n\n";

    return structure;
}

// Function to dump the getter functions in the public section of the class in spec file
void dump_getter_funcs(std::ofstream *file, my_struct data) {

    for (auto key : data.dict_data) {
        std::map<std::string, std::string> struct_types = get_struct_types(key.second);
        for (auto key2 : struct_types) {
            std::string return_type = key2.second;
            std::string field_name = key2.first;
            std::string argument_data_type = "std::string";
            std::string function_name = "get_" + field_name;
            std::string spec_name = key.first;
            std::string argument_name = spec_name + "_id";
            std::string default_return_value;

            if (return_type == "string") {
                return_type = "std::string";
                default_return_value = "\"\"";
            } else if (return_type == "map") {
                return_type = "std::map<std::string, " + spec_name + "_data>";
                default_return_value = "{}";
            } else if (return_type == "vector") {
                return_type = "std::vector<" + spec_name + "_data>";
                default_return_value = "{}";
            }

            *file << generate_function(function_name, spec_name, field_name, return_type, default_return_value, argument_name, argument_data_type) << std::endl;
        }
    }
}

// Function to dump the constructor of the class in spec file
void dump_constructor(std::ofstream *file, my_struct data) {
    std::string structure = R"(
        Specification() {)"; 

    *file << structure << std::endl;

    for (auto par_key : data.dict_data) {
        for (auto key : par_key.second.dict_data) {
            dump_struct_variables(file, key.second, "\t\t\t" + par_key.first + "_" + key.first, par_key.first + "_data");
            std::string key_ = key.first;
            std::replace(key_.begin(), key_.end(), '_', '-');
            *file << "\t\t\t" << par_key.first << "[\"" << key_ << "\"] = " + par_key.first +"_" << key.first << ";" << std::endl;
            *file << std::endl;
        }
    }

    structure = R"(
        }
    )";

    *file << structure << std::endl;
}

// Function to dump the private member variables of the class in spec file
void dump_private_entities(std::ofstream *file, my_struct data) {
    for (auto par_key : data.dict_data) {
        for (auto key : par_key.second.dict_data) {
            *file << "\t\t" << par_key.first << "_data " + par_key.first +"_" << key.first << ";" << std::endl;
        }
    }
    *file << std::endl;

    for (auto par_key: data.dict_data) {
        *file << "\t\t" << "std::map<std::string, " << par_key.first <<  "_data> " << par_key.first << ";" << std::endl;
    }
}

// Function to dump the public member variables of the class in spec file
void dump_public_entities(std::ofstream *file, my_struct data) {
    dump_constructor(file, data);
    dump_getter_funcs(file, data);
}

// Function to dump the entire spec file. Uses the above functions sequentially.
void dump_text(my_struct data, std::string filename) {
    std::ofstream file;
    file.open(filename);

    // Dump each of the header from HEADERS as include directives in the spec file
    dump_headers(&file, HEADERS);

    // Creating the required typedefs: protocols_data, helper_functions_data, map_info_data
    std::vector<std::string> typedefs;

    for (auto key : data.dict_data) {
        typedefs.push_back(key.first + "_data");
    }

    // Dump the struct and typedef definitions in the spec file
    dump_structure_defs(&file, typedefs);

    // Dump the class definition in the spec file
    std::string structure = R"(
class Specification {
    private:)";

    file << structure << std::endl;

    // Dump the variable definition statements in the spec file
    dump_private_entities(&file, data);

    // Dump the public section of the class in the spec file
    structure = R"(
    public:)";

    file << structure << std::endl;

    // Dump the variable assignment and value manipulation statements in the spec file
    dump_public_entities(&file, data);

    // Dump the closing brace of the class in the spec file
    structure = R"(};)";

    file << structure << std::endl;
    file.close();
}

// Main Function
int main(int argc, char** argv) {

    int opt;
    std::string json_filename, output_filename;

    while ((opt = getopt(argc, argv, "i:o:h")) != -1) {
        switch (opt) {
            case 'i': {
                json_filename = optarg;
                std::cout << "Input JSON specification file : " << json_filename << std::endl;
                break;
            }
            case 'o': {
                output_filename = optarg;
                std::cout << "Output spec file : " << output_filename << std::endl;
                break;
            }
            case 'h': {
                std::cout << "Usage: ./convert_spec -i <JSON filename> -o <output filename>" << std::endl;
                return EXIT_SUCCESS;
            }
            case '?': {
                std::cout << "Unknown option " << opt << " identified" << std::endl;
                std::cout << "Usage: ./convert_spec -i <JSON filename> -o <output filename>" << std::endl;
                return EXIT_FAILURE;
            }
            default:
                std::cout << "Usage: ./convert_spec -i <JSON filename> -o <output filename>" << std::endl;
                return EXIT_FAILURE;
        }
    }

    // Check if the JSON filename and output filename are provided
    if (json_filename == "" || output_filename == "") {
        std::cout << "Usage: ./convert_spec -i <JSON filename> -o <output filename>" << std::endl;
        return EXIT_FAILURE;
    }

    namespace pt = boost::property_tree;

    // Definition of ptree variable to read JSON
    pt::ptree root;

    // Read the JSON into root
    pt::read_json(json_filename, root);

    // Parse through the JSON to store the data in memory
    my_struct final_data = parse_data(root);
    
    // Dump the formatted data into spec file
    dump_text(final_data, output_filename);

    std::cout << "Successfully dumped the spec file" << std::endl;
    return EXIT_SUCCESS;
}