import argparse
import subprocess
import os

def main():
    parser = argparse.ArgumentParser(
        description="XDP/eBPF utility with parser, object, section, priority, and query options"
    )

    parser.add_argument("--parser", type=str, required=True, help="Parser type or name")
    parser.add_argument("--obj", type=str, required=True, help="Path to eBPF object file (.o)")
    parser.add_argument("--sec", type=str, default="xdp", help="ELF section name (default: xdp)")
    parser.add_argument("--query", type=str, help="Path of text file containing queries")
    parser.add_argument("--priority", type=str, help="Query string to run on parsed data")

    args = parser.parse_args()

    # --------------------------------------------------
    # Run parser executable
    # --------------------------------------------------
    command = [args.parser, "--path", args.obj, "--sec", args.sec]
    print("\ncommand: ", command, "✅")

    cwd = os.path.dirname(args.parser) or "."

    result = subprocess.run(command, capture_output=True, cwd=cwd, text=True)
    print("STDOUT:\n", result.stdout)
    print("STDERR:\n", result.stderr)

    if result.returncode != 0:
        print(f"❌ Parser failed with exit code: {result.returncode}\n")
    else:
        print("✅ Parser ran successfully!\n")

    # --------------------------------------------------
    # Run queries if --query is provided
    # --------------------------------------------------
    if args.query:
        if not os.path.isfile(args.query):
            print(f"❌ Query file not found: {args.query}")
            return

        with open(args.query, 'r') as file:
            for line in file:
                main_query = line.strip()
                # query = f"({main_query} -> writeln(Fld) ; writeln(false)), halt."
                # query = f"{main_query}."
                if "Fld" in main_query:
                    # Query for extracting values
                    query = f"forall({main_query}, writeln(Fld)), halt."
                else:
                    # Query for boolean check
                    query = f"({main_query} -> writeln(true) ; writeln(false)), halt."

                prolog_command = ["swipl", "-q",
                                  "-s", "rules.pl",
                                  "-s", "prolog.pl",
                                  "-s", "nf_chain.pl",
                                  "-g", query]
                print("Running command:", " ".join(prolog_command))
                try:
                    result = subprocess.run(prolog_command, capture_output=True, cwd=cwd, text=True, check=True)
                    
                    raw_output = result.stdout.strip().split('\n')

                    output_values = list(set(val for val in raw_output if val.strip()))
                    
                    if output_values == ['']: # Handle case where nothing was found
                        print(f"Query: {main_query} - No results found.")
                    else:
                        print(f"Query: {main_query} ✅")
                        for value in output_values:
                            print(f"  Found Field: {value}")

                except subprocess.CalledProcessError as e:
                    print("\nQuery: ", main_query, "❌")
                    print("Exit Code:", e.returncode)
                    print("Standard Error:", e.stderr) # This will tell you the exact Prolog syntax error
                    print("Standard Output:", e.stdout)

if __name__ == "__main__":
    main()
