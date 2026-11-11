#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import time
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--count', type=int, default=500)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--record-tree', action='store_true')
    args = parser.parse_args()
    run_id = f'exit-tree-{uuid.uuid4().hex[:12]}'
    started = time.time_ns()

    def execute(index):
        script = 'git diff --stat HEAD~1 HEAD && git diff --name-status HEAD~1 HEAD'
        if args.record_tree:
            script = (
                'git diff --stat HEAD~1 HEAD >/dev/null & first=$!; '
                'git diff --name-status HEAD~1 HEAD >/dev/null & second=$!; '
                'wait "$first"; first_code=$?; wait "$second"; second_code=$?; '
                'printf \'__A3S_TREE__{"first_pid":%s,"second_pid":%s,'
                '"first_exit_code":%s,"second_exit_code":%s}\\n\' '
                '"$first" "$second" "$first_code" "$second_code"; '
                'exit "$(( first_code != 0 || second_code != 0 ))"'
            )
        command = ['bash', '-c', script]
        process = subprocess.Popen(
            command,
            cwd='/home/zhongyule/code/Observer',
            stdout=subprocess.PIPE if args.record_tree else subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        fact = {'index': index, 'pid': process.pid, 'command': command, 'exit_code': process.returncode, 'stderr': stderr.decode(errors='replace')[-500:]}
        if args.record_tree:
            prefix = b'__A3S_TREE__'
            records = [json.loads(line[len(prefix):]) for line in stdout.splitlines() if line.startswith(prefix)]
            if len(records) != 1:
                raise RuntimeError(f'expected one process-tree receipt for {process.pid}, got {len(records)}')
            fact['children'] = [
                {'pid': records[0]['first_pid'], 'command': ['git', 'diff', '--stat', 'HEAD~1', 'HEAD'], 'exit_code': records[0]['first_exit_code']},
                {'pid': records[0]['second_pid'], 'command': ['git', 'diff', '--name-status', 'HEAD~1', 'HEAD'], 'exit_code': records[0]['second_exit_code']},
            ]
        return fact

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        facts = list(pool.map(execute, range(args.count)))
    result = {
        'schema': 'a3s.short-lived-git-tree-truth.v2' if args.record_tree else 'a3s.short-lived-git-tree-truth.v1',
        'run_id': run_id,
        'runner_pid': os.getpid(),
        'started_at_unix_ns': started,
        'finished_at_unix_ns': time.time_ns(),
        'workers': args.workers,
        'facts': facts,
    }
    Path(args.output).write_text(json.dumps(result, indent=2) + '\n')
    failures = [fact for fact in facts if fact['exit_code'] != 0]
    print(json.dumps({'run_id': run_id, 'count': len(facts), 'failures': failures[:5], 'output': args.output}))


if __name__ == '__main__':
    main()
