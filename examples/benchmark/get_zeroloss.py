import subprocess, re, os
import toml
import argparse


# allowed % packet drop
EPSILON=1
GRACE_PD = 5
def execute(cmd, executable):
    print(f'starting {executable}')
    stop = 0
    throughput = -1
    popen = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, universal_newlines=True)
    grace_pd = 0
    for stdout_line in iter(popen.stdout.readline, ''):
        print(stdout_line, end='')
        if 'AVERAGE' in stdout_line and 'Process' in stdout_line:
            num = re.findall('\d*\.\d+ bps', stdout_line)
            if not num:
                continue
            throughput = float(num[0].split('bps')[0])

        if 'SW Dropped' in stdout_line:
            num = re.findall('\d*\.*\d+\%', stdout_line)
            if not num: continue
            value = float(num[0].split('%')[0])
            if value > EPSILON :
                grace_pd += 1
                if grace_pd < GRACE_PD:
                    continue

                print(f'TERMINATING, current SW drops {value} greater than {EPSILON}, exceeded {GRACE_PD}s grace period...')
                stream = os.popen(f'pidof {executable}')
                pid = stream.read()
                os.system(f'sudo kill -INT {pid}')
                stop = 0      # continue decreasing buckets
        elif 'DROPPED' in stdout_line:
            num = re.findall('\d*\.*\d+\%', stdout_line)
            if not num: continue
            value = float(num[0].split('%')[0])
            if value == 0:
                # 0 drops
                print('Zero drops...')
                stop = 1
            elif value <= EPSILON :
                print(f'Epsilon {value}% dropped...')
                stop = 2
            elif value > EPSILON:
                if grace_pd < GRACE_PD:
                    print(f'Epsilon {value}% dropped, but likely due to spike at end.')
                    stop = 2
                else:
                    stop = 0

    popen.stdout.close()
    popen.wait()
    return stop, throughput

def main(args):
    binary = args.binary

    duration = int(args.duration)
    start = int(args.start)

    config_file = args.config

    executable = f'/home/tcr6/iris/target/release/{binary}'
    cmd = f'sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error {executable} -c {config_file}'
    if args.args:
        cmd += ' ' + args.args
    print(cmd)
    config=toml.load(config_file)
    n_cores = len(config['online']['ports'][0]['cores'])
    print(config)
    for b in range(start, 0, -n_cores * int(args.multiplier)):
        print(f'Running {binary} with {b} buckets')

        config['online']['monitor']['log'] = None
        config['online']['duration'] = duration
        config['online']['ports'][0]['sink']["nb_buckets"] = b
        if len(config['online']['ports']) > 1 and 'sink' in config['online']['ports'][1]:
            config['online']['ports'][1]['sink']['nb_buckets'] = b

        f = open(config_file, 'w')
        toml.dump(config, f)
        f.close()

        stop_code, throughput = execute(cmd, executable)
        if stop_code > 0:
            print(f'Stop code {stop_code}: done')
            print(f'<{EPSILON}% Loss Throughput RESULT: {throughput}')
            with open(args.outfile, "a") as file:
                file.write(f'{args.label}: <{EPSILON}% Loss Throughput RESULT: {throughput}\n')
            break

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--binary')
    parser.add_argument('-d', '--duration')
    parser.add_argument('-s', '--start')
    parser.add_argument('-c', '--config')
    parser.add_argument('-m', '--multiplier')
    parser.add_argument('-l', '--label')
    parser.add_argument('-o', '--outfile', default='zlt_results.txt')
    parser.add_argument('-a', '--args', default='')
    return parser.parse_args()

if __name__ == '__main__':
    print("start ZLT")
    main(parse_args())