#!/usr/bin/env python3
import argparse
import collections
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--truth', required=True)
    parser.add_argument('--events', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    truth = json.loads(Path(args.truth).read_text())
    pids = {fact['pid'] for fact in truth['facts']}
    rows = []
    for line in Path(args.events).read_text().splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        event = row.get('event', {})
        if event.get('ToolExec', {}).get('exec_confirmed') is True or 'ProcessExit' in event:
            rows.append(row)
    changed = True
    while changed:
        changed = False
        for row in rows:
            process = row.get('process', {})
            pid = process.get('pid')
            if pid not in pids and (process.get('creation_ppid') in pids or process.get('ppid') in pids):
                pids.add(pid)
                changed = True
    scoped = [row for row in rows if row.get('process', {}).get('pid') in pids]
    by_pid = collections.defaultdict(list)
    for row in scoped:
        by_pid[row['process']['pid']].append(row)

    missing_exit = []
    missing_ns = []
    bad_parent_generation = []
    bad_ticks = []
    for pid, events in by_pid.items():
        execs = [row for row in events if 'ToolExec' in row['event']]
        exits = [row for row in events if 'ProcessExit' in row['event']]
        if execs and not exits:
            missing_exit.append(pid)
        for row in events:
            process = row['process']
            if not process.get('start_boottime_ns'):
                missing_ns.append(pid)
            parent = process.get('creation_ppid')
            if parent in by_pid:
                expected = by_pid[parent][0]['process'].get('start_boottime_ns')
                if process.get('creation_parent_start_boottime_ns') != expected:
                    bad_parent_generation.append({'pid': pid, 'parent': parent})
            ticks = process.get('start_time_ticks')
            hz = process.get('user_hz')
            if ticks is not None and hz:
                divisor = 1_000_000_000 // hz
                if divisor == 0 or process['start_boottime_ns'] // divisor != ticks:
                    bad_ticks.append(pid)

    exit_mismatches = []
    for fact in truth['facts']:
        exits = [row for row in by_pid.get(fact['pid'], []) if 'ProcessExit' in row['event']]
        if len(exits) != 1 or exits[0]['event']['ProcessExit']['exit_code'] != fact['exit_code']:
            exit_mismatches.append(fact['pid'])

    consecutive_pid = next(fact['pid'] for fact in truth['facts'] if fact['name'] == 'consecutive_exec')
    consecutive = [row for row in by_pid[consecutive_pid] if 'ToolExec' in row['event']]
    comm_sequence = [row['process']['comm'] for row in consecutive]
    consecutive_generations = {row['process']['start_boottime_ns'] for row in by_pid[consecutive_pid]}
    compile_chain = collections.Counter(
        row['process']['comm']
        for row in scoped
        if 'ToolExec' in row['event'] and row['process']['comm'] in {'gcc', 'cc1', 'as', 'collect2', 'ld'}
    )
    checks = {
        'all_observed_exec_pids_have_final_exit': not missing_exit,
        'all_scoped_events_have_start_boottime_ns': not missing_ns,
        'creation_parent_generations_match': not bad_parent_generation,
        'proc_ticks_match_target_user_hz_conversion': not bad_ticks,
        'fork_wait_exit_codes_match': not exit_mismatches,
        'consecutive_exec_comm_sequence': comm_sequence == ['bash', 'bash', 'echo'],
        'consecutive_exec_generation_stable': len(consecutive_generations) == 1,
        'two_complete_compile_chains': all(compile_chain[name] == 2 for name in ['gcc', 'cc1', 'as', 'collect2', 'ld']),
    }
    summary = {
        'schema': 'a3s.process-identity-live-result.v1',
        'run_id': truth['run_id'],
        'scope_pids': len(pids),
        'confirmed_exec': sum('ToolExec' in row['event'] for row in scoped),
        'process_exit': sum('ProcessExit' in row['event'] for row in scoped),
        'compile_chain': dict(compile_chain),
        'consecutive_exec_comm': comm_sequence,
        'missing_exit': missing_exit,
        'missing_ns': sorted(set(missing_ns)),
        'bad_parent_generation': bad_parent_generation,
        'bad_ticks': sorted(set(bad_ticks)),
        'exit_mismatches': exit_mismatches,
        'checks': checks,
        'passed': all(checks.values()),
        'evidence_boundary': 'fork/wait plus explicit exec checkpoints; PID reuse is not exercised by this live run',
    }
    Path(args.output).write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    if not summary['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
