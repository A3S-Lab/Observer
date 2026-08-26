use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcessNamespaceFacts {
    pub(crate) pid_namespace: String,
    pub(crate) namespace_pid: u32,
    pub(crate) namespace_ppid: Option<u32>,
}

pub(crate) fn parse_pid_namespace_link(value: &str) -> Option<String> {
    let value = value.trim();
    let inode = value.strip_prefix("pid:[")?.strip_suffix(']')?;
    (!inode.is_empty() && inode.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| inode.to_string())
}

pub(crate) fn innermost_namespace_pid(status: &str) -> Option<u32> {
    let values = status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))?;
    values
        .split_whitespace()
        .last()?
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 0)
}

fn namespace_inode_at(proc_root: &Path, pid: u32) -> Option<String> {
    let link = std::fs::read_link(proc_root.join(pid.to_string()).join("ns/pid")).ok()?;
    parse_pid_namespace_link(link.to_str()?)
}

fn namespace_pid_at(proc_root: &Path, pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(proc_root.join(pid.to_string()).join("status")).ok()?;
    innermost_namespace_pid(&status)
}

pub(crate) fn read_process_namespace_at(
    proc_root: &Path,
    pid: u32,
    host_ppid: u32,
) -> Option<ProcessNamespaceFacts> {
    let pid_namespace = namespace_inode_at(proc_root, pid)?;
    let namespace_pid = namespace_pid_at(proc_root, pid)?;
    let namespace_ppid = (host_ppid > 0)
        .then(|| {
            let parent_namespace = namespace_inode_at(proc_root, host_ppid)?;
            (parent_namespace == pid_namespace).then(|| namespace_pid_at(proc_root, host_ppid))?
        })
        .flatten();
    Some(ProcessNamespaceFacts {
        pid_namespace,
        namespace_pid,
        namespace_ppid,
    })
}

pub(crate) fn read_process_namespace(pid: u32, host_ppid: u32) -> Option<ProcessNamespaceFacts> {
    read_process_namespace_at(Path::new("/proc"), pid, host_ppid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pid_namespace_inode_without_numeric_coercion() {
        assert_eq!(
            parse_pid_namespace_link("pid:[4026532441]"),
            Some("4026532441".to_string())
        );
        assert_eq!(parse_pid_namespace_link("mnt:[4026532441]"), None);
        assert_eq!(parse_pid_namespace_link("pid:[not-a-number]"), None);
    }

    #[test]
    fn uses_the_innermost_nspid() {
        assert_eq!(
            innermost_namespace_pid("Name:\tnode\nNSpid:\t52000\t17\t1\n"),
            Some(1)
        );
        assert_eq!(innermost_namespace_pid("Name:\tnode\n"), None);
        assert_eq!(innermost_namespace_pid("NSpid:\t0\n"), None);
    }
}
