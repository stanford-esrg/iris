import math
import argparse
import os
import toml

root_dir = os.getenv("IRIS_HOME")
if not root_dir:
    raise RuntimeError("Set $IRIS_HOME")
gen_script = f"{root_dir}/examples/benchmark/generate.py"
prog = "benchmark"
run_bin = f"{root_dir}/target/release/{prog}"
get_zlt = f"{root_dir}/examples/benchmark/get_zeroloss.py"
config = f"{root_dir}/configs/online.toml"
duration = 60
start_buckets = 512
mult = 8

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='Subscription Runner',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--start',
        type=int,
        default=2,
        help='Min. number of subscriptions to generate')
    parser.add_argument('--end',
        type=int,
        default=256,
        help='Max. number of subscriptions to generate')
    args = parser.parse_args()

    start_exp = math.ceil(math.log2(args.start))
    end_exp = math.floor(math.log2(args.end))
    for exp in range(start_exp, end_exp + 1):
        val = 2 ** exp

        # Build
        os.system(f"python3 {gen_script} -n {val}")
        os.system(f"rm -f ./target/release/deps/benchmark*") # force rebuild
        os.system(f"cargo build --bin {prog} --release")

        # Run
        cmd = f'python3 {get_zlt} -b {prog} -d {duration} -s {start_buckets} -c {config} -m {mult} -l {val}_subs'
        print(cmd)
        os.system(cmd)