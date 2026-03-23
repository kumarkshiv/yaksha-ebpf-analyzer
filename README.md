# Yaksha-Prashna — eBPF Bytecode Network Function Analyzer
> Published on Arxiv 2025

## The Problem
Cloud operators increasingly deploy third-party eBPF-based 
network functions (Cilium, F5, Palo Alto) in bytecode format 
— with little visibility into their behavior, bugs, or 
privacy implications. Questions like:
- Does it bypass other eBPF programs at the same hookpoint?
- Does it make unintended modifications to header fields?
- Does it copy sensitive data violating privacy policies?

...are impossible to answer without deep bytecode analysis.

## What Yaksha Does
Yaksha allows network operators to write queries on 
individual or chained eBPF bytecodes. It analyzes bytecode 
behavior for specific queries — helping prevent high-profile 
outages like Datadog's $5M eBPF incident.

## My Contributions
- Studied eBPF internals and bytecode structure deeply
- Designed transfer function rules for data flow analysis
- Implemented data flow analysis engine in C++
- Designed query language implemented in Prolog
- Implemented Prolog rules and predicates for query resolution
- Conducted 2-3 months of extensive evaluation

## Tech Stack
- Language: C++ · Prolog · XDP/eBPF · TC/eBPF
- Compiler: LLVM-Clang
- Tools: Libbpf · bpfman · bpftool · Docker · tcpdump

## Paper
[Yaksha-Prashna: Understanding eBPF Bytecode NF Behavior](https://arxiv.org/pdf/2602.11232)
