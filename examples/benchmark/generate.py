import os
import math
import ipaddress
import argparse

root_dir = os.getenv("IRIS_HOME")
if not root_dir:
    raise RuntimeError("Set $IRIS_HOME")
filter_fp = f"{root_dir}/examples/benchmark/filter_strs.txt"

def build_ipv4_filters(n):
    if not (n > 0 and (n & (n - 1)) == 0):
        raise ValueError(f"{n} is not a power of 2")
    new_prefix = int(math.log2(n))
    net = ipaddress.IPv4Network("0.0.0.0/0")
    subnets = list(net.subnets(new_prefix=new_prefix))
    s = ""
    for subnet in subnets:
        s += f"ipv4.addr = {subnet} and (http or tls or dns or quic)\n"
    s = s[:-1] # remove last newline
    return s

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        prog='Filter String Generator',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-n',
        type=int,
        default=2,
        help='Number of filter strings to generate')

    args = parser.parse_args()
    print(f"Generating {args.n} filters")

    filters_str = build_ipv4_filters(args.n)

    with open(filter_fp, 'w') as file:
        file.write(filters_str)
