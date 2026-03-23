## Steps to compile and run the code to convert JSON file to C++ header

- To compile, pass the name of the executable as CLI argument

  `g++ convert_spec.cpp -o convert_spec`
  
- To run the executable, pass the JSON specification file and the name of output C++ header file as CLI arguments.

  `./convert_spec protocols.json spec.hpp`

## Steps to compile and run the ebpf_parser

- To compile :
  
  `g++ ebpf_parser.cpp -o parser -lbpf -lelf -lz -I/home/netx9/libbpf/include/uapi -L/usr/local/lib`

- To run the executable, we need to pass the path to the object file and the program name as command line arguments :

  `./parser ./test_files/object_files/ether_ip_ipv6_tcp_udp.o xdp_parser_func` 

## Steps to compile and run Make_cfg.cpp

- To compile :

  `g++ Make_cfg.cpp -o Make_cfg -lbpf -lelf -lz -I/home/netx9/libbpf_old/include/uapi -L/usr/local/lib`

- To run the executable, we need to pass the path to the object file and the program name as command line arguments :

  `./Make_cfg ./test_files/object_files/ether_ip_ipv6_tcp_udp.o xdp_parser_func`

- To view the cfg in pdf format :
  
  `dot -Tpdf graph.dot > test_cfg.pdf`
