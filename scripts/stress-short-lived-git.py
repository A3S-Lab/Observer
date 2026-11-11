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
    args = parser.parse_args()
    run_id = f'exit-stress-{uuid.uuid4().hex[:12]}'
    started = time.time_ns()

    def execute(index):
        command = ['git', 'diff', '--stat', 'HEAD~1', 'HEAD']
        process = subprocess.Popen(command, cwd='/home/zhongyule/code/Observer', stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        _, stderr = process.communicate()
        return {
            'index': index,
            'pid': process.pid,
            'command': command,
            'exit_code': process.returncode,
            'stderr': stderr.decode(errors='replace')[-500:],
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        facts = list(pool.map(execute, range(args.count)))
    result = {
        'schema': 'a3s.short-lived-git-truth.v1',
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
