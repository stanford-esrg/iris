#!/usr/bin/env python3

import argparse
import subprocess
import os
import sys
import difflib
import json

def main():
    parser = argparse.ArgumentParser(
        description="Run a debug build of the iris test app with expected output and pcap files."
    )
    parser.add_argument("--app", help="Name of the test application binary (e.g., basic_test)")
    parser.add_argument("--expected-outfile", help="Path to the expected output binary file")
    parser.add_argument("--outfile", help="Path to file to write results to")
    parser.add_argument("--cmpfile", help="Path to file to compare against")

    args = parser.parse_args()

    app_directory = os.path.join("target", "debug", args.app)
    command_args = [app_directory]

    try:
        result = subprocess.run(
            command_args,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        # print("Output:\n", result.stdout)

        # Skip the first 3 lines of output and save stdout (JSON from Rust app) to output file
        lines = result.stdout.splitlines()
        cleaned_output = "\n".join(lines[3:])

        if args.outfile:
            with open(args.outfile, "w") as f:
                f.write(cleaned_output)
            print(f"Output written to {args.outfile}")

    except subprocess.CalledProcessError as e:
        print("Error:\n", e.stderr)
    except FileNotFoundError:
        print(f"Executable not found: {app_directory}")
        sys.exit(1)

    # Run diff on output file and expected_output file
    cmp_outfile = args.cmpfile if args.cmpfile else args.outfile
    if "json" in args.expected_outfile:
        diff_files_json(cmp_outfile, args.expected_outfile)
    else:
        diff_files(cmp_outfile, args.expected_outfile)

# Helper function
def diff_files_json(file1, file2):
    with open(file1, 'r') as f:
        data1 = json.load(f)
    with open(file2, 'r') as f:
        data2 = json.load(f)
    if data1 == data2:
        print("Output files are identical. Test passed!")
        return

    diffs = {}

    if isinstance(data1, list) and isinstance(data2, list):
        s1 = {json.dumps(it, sort_keys=True) for it in data1}
        s2 = {json.dumps(it, sort_keys=True) for it in data2}
        for it in s1 - s2:
            idx = data1.index(json.loads(it))
            diffs[idx] = f"Only in {file1}: {it} (original idx: {idx})"
        for it in s2 - s1:
            idx = data2.index(json.loads(it))
            diffs[idx] = f"Only in {file2}: {it} (original idx: {idx})"
    else:
        print("Unsupported format for JSON comparison; defaulting to text diff.")
        diff_files(file1, file2)
        return

    if not diffs:
        print("Output files are identical. Test passed!")
    else:

        for (idx, diff) in sorted(diffs.items()):
            print(diff)


# Helper function
def diff_files(file1, file2):
    with open(file1) as f1, open(file2) as f2:
        lines1 = f1.readlines()
        lines2 = f2.readlines()

    diff = difflib.unified_diff(
        lines1,
        lines2,
        fromfile=file1,
        tofile=file2,
        lineterm=""
    )

    diff_output = list(diff)
    if diff_output:
        print("Differences found:")
        for line in diff_output:
            print(line)
    else:
        print("Output files are identical. Test passed!")

if __name__ == "__main__":
    main()
