#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    run_id = f'a-identity-{uuid.uuid4().hex[:12]}'
    root = Path(tempfile.mkdtemp(prefix=f'{run_id}-'))
    source = root / 'cmain.c'
    source.write_text('#include <stdio.h>\nint main(int argc, char **argv) { printf("%s:%d\\n", argv[0], argc); return 0; }\n')
    data = root / 'sample.db'
    data.write_bytes(bytes(range(64)))
    binary = root / 'cmain'
    facts = []

    def run(name, command, cwd=None, checkpoints=None):
        started = time.time_ns()
        process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        fact = {
            'name': name,
            'pid': process.pid,
            'ppid': os.getpid(),
            'command': command,
            'exit_code': process.returncode,
            'started_at_unix_ns': started,
            'waited_at_unix_ns': time.time_ns(),
            'stdout': stdout[-2048:],
            'stderr': stderr[-2048:],
            'exec_checkpoints': checkpoints or [],
        }
        facts.append(fact)

    run('short_true', ['/bin/true'])
    run('short_false', ['/bin/false'])
    run('xxd', ['xxd', str(data)])
    run('head', ['head', '-c', '16', str(data)])
    run('git_log', ['git', 'log', '--oneline', '-1'], cwd='/home/zhongyule/code/Observer')
    compile_command = [
        'bash', '-c',
        f'gcc -O0 -o {binary} {source} && gcc -O1 -o {binary} {source} && '
        f'{binary} 0 && {binary} 50 && {binary} 93',
    ]
    run('compile_chain', compile_command)
    consecutive = f'exec bash -c \'exec /bin/echo {run_id}-consecutive\''
    run(
        'consecutive_exec',
        ['bash', '-c', consecutive],
        checkpoints=[
            {'sequence': 1, 'image': 'bash', 'pid_source': 'fork_wait_pid'},
            {'sequence': 2, 'image': 'bash', 'pid_source': 'same_pid_exec_checkpoint'},
            {'sequence': 3, 'image': '/bin/echo', 'pid_source': 'same_pid_exec_checkpoint'},
        ],
    )
    result = {
        'schema': 'a3s.process-identity-live-truth.v1',
        'run_id': run_id,
        'root': str(root),
        'runner_pid': os.getpid(),
        'note': 'fork/wait proves birth and final exit; listed checkpoints describe expected same-PID exec transitions, not an independent kernel trace',
        'facts': facts,
    }
    output = Path(args.output)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'run_id': run_id, 'root': str(root), 'output': str(output), 'facts': len(facts)}))


if __name__ == '__main__':
    main()
