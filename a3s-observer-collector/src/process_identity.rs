use anyhow::{bail, Context, Result};

pub const PROCESS_IDENTITY_CONFIG_ENABLED: usize = 0;
pub const PROCESS_IDENTITY_GROUP_LEADER_OFFSET: usize = 1;
pub const PROCESS_IDENTITY_REAL_PARENT_OFFSET: usize = 2;
pub const PROCESS_IDENTITY_START_BOOTTIME_OFFSET: usize = 3;
pub const PROCESS_IDENTITY_PID_OFFSET: usize = 4;
pub const PROCESS_IDENTITY_CONFIG_LEN: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskOffsets {
    pub group_leader: u64,
    pub real_parent: u64,
    pub start_boottime: u64,
    pub pid: u64,
}

#[derive(Clone, Copy)]
struct TypeHeader {
    kind: u32,
    size_or_type: u32,
}

pub fn config_from_sys_fs() -> Result<[u64; PROCESS_IDENTITY_CONFIG_LEN]> {
    let bytes = std::fs::read("/sys/kernel/btf/vmlinux")
        .context("read /sys/kernel/btf/vmlinux for start_boottime")?;
    let offsets = task_offsets_from_btf(&bytes)?;
    let mut config = [0; PROCESS_IDENTITY_CONFIG_LEN];
    config[PROCESS_IDENTITY_CONFIG_ENABLED] = 1;
    config[PROCESS_IDENTITY_GROUP_LEADER_OFFSET] = offsets.group_leader;
    config[PROCESS_IDENTITY_REAL_PARENT_OFFSET] = offsets.real_parent;
    config[PROCESS_IDENTITY_START_BOOTTIME_OFFSET] = offsets.start_boottime;
    config[PROCESS_IDENTITY_PID_OFFSET] = offsets.pid;
    Ok(config)
}

pub fn start_boottime_ns_to_ticks(ns: u64, user_hz: u32) -> Option<u64> {
    if user_hz == 0 {
        return None;
    }
    let divisor = 1_000_000_000u64 / u64::from(user_hz);
    if divisor == 0 {
        return None;
    }
    Some(ns / divisor)
}

pub fn task_offsets_from_btf(bytes: &[u8]) -> Result<TaskOffsets> {
    if bytes.len() < 24 {
        bail!("BTF header is truncated");
    }
    let little = match &bytes[..2] {
        [0x9f, 0xeb] => true,
        [0xeb, 0x9f] => false,
        _ => bail!("unsupported BTF magic"),
    };
    let u16_at = |offset: usize| -> Result<u16> {
        let raw: [u8; 2] = bytes
            .get(offset..offset + 2)
            .context("truncated BTF u16")?
            .try_into()
            .unwrap();
        Ok(if little {
            u16::from_le_bytes(raw)
        } else {
            u16::from_be_bytes(raw)
        })
    };
    let u32_at = |offset: usize| -> Result<u32> {
        let raw: [u8; 4] = bytes
            .get(offset..offset + 4)
            .context("truncated BTF u32")?
            .try_into()
            .unwrap();
        Ok(if little {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        })
    };
    if u16_at(2)? != 1 {
        bail!("unsupported BTF version");
    }
    let header_len = u32_at(4)? as usize;
    let type_offset = header_len + u32_at(8)? as usize;
    let type_len = u32_at(12)? as usize;
    let string_offset = header_len + u32_at(16)? as usize;
    let string_len = u32_at(20)? as usize;
    let type_end = type_offset
        .checked_add(type_len)
        .context("BTF type overflow")?;
    let string_end = string_offset
        .checked_add(string_len)
        .context("BTF string overflow")?;
    if type_end > bytes.len() || string_end > bytes.len() {
        bail!("BTF sections are truncated");
    }
    let string_at = |offset: u32| -> Result<&str> {
        let start = string_offset + offset as usize;
        if start >= string_end {
            bail!("invalid BTF string offset");
        }
        let tail = &bytes[start..string_end];
        let len = tail
            .iter()
            .position(|byte| *byte == 0)
            .context("unterminated BTF string")?;
        std::str::from_utf8(&tail[..len]).context("non-UTF8 BTF name")
    };

    let mut headers = Vec::new();
    let mut cursor = type_offset;
    let mut task: Option<(u32, Vec<(u32, u32, u32)>)> = None;
    while cursor < type_end {
        if cursor + 12 > type_end {
            bail!("truncated BTF type header");
        }
        let name_offset = u32_at(cursor)?;
        let info = u32_at(cursor + 4)?;
        let size_or_type = u32_at(cursor + 8)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        let kflag = info >> 31 != 0;
        headers.push(TypeHeader { kind, size_or_type });
        let payload = cursor + 12;
        let extra = match kind {
            0 | 2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18 => 0,
            1 | 14 | 17 => 4,
            3 => 12,
            4 | 5 => vlen * 12,
            6 => vlen * 8,
            13 => vlen * 8,
            15 => vlen * 12,
            19 => vlen * 12,
            _ => bail!("unsupported BTF kind {kind}"),
        };
        if payload + extra > type_end {
            bail!("truncated BTF type payload");
        }
        if kind == 4 && string_at(name_offset)? == "task_struct" {
            let mut members = Vec::with_capacity(vlen);
            for index in 0..vlen {
                let at = payload + index * 12;
                let raw_offset = u32_at(at + 8)?;
                let bit_offset = if kflag {
                    raw_offset & 0x00ff_ffff
                } else {
                    raw_offset
                };
                let bitfield_size = if kflag { raw_offset >> 24 } else { 0 };
                if bitfield_size != 0 || bit_offset % 8 != 0 {
                    continue;
                }
                members.push((u32_at(at)?, u32_at(at + 4)?, bit_offset / 8));
            }
            task = Some((size_or_type, members));
        }
        cursor = payload + extra;
    }
    let (_, members) = task.context("target BTF has no task_struct")?;
    let resolve = |mut type_id: u32| -> Result<TypeHeader> {
        for _ in 0..16 {
            let header = headers
                .get(type_id.checked_sub(1).context("invalid BTF type id")? as usize)
                .copied()
                .context("BTF type id is out of range")?;
            if matches!(header.kind, 8 | 9 | 10 | 11 | 18) {
                type_id = header.size_or_type;
            } else {
                return Ok(header);
            }
        }
        bail!("BTF type alias depth exceeded");
    };
    let member = |name: &str| -> Result<(u32, u64)> {
        let (name_offset, type_id, offset) = members
            .iter()
            .find(|(member_name, _, _)| string_at(*member_name).is_ok_and(|value| value == name))
            .copied()
            .with_context(|| format!("task_struct has no {name}"))?;
        let _ = name_offset;
        Ok((type_id, u64::from(offset)))
    };
    let (group_type, group_leader) = member("group_leader")?;
    let (parent_type, real_parent) = member("real_parent")?;
    let (start_type, start_boottime) = member("start_boottime")?;
    let (pid_type, pid) = member("pid")?;
    if resolve(group_type)?.kind != 2 || resolve(parent_type)?.kind != 2 {
        bail!("task_struct parent fields are not pointers");
    }
    if resolve(start_type)?.kind != 1 || resolve(start_type)?.size_or_type != 8 {
        bail!("task_struct start_boottime is not u64");
    }
    if resolve(pid_type)?.kind != 1 || resolve(pid_type)?.size_or_type != 4 {
        bail!("task_struct pid is not u32");
    }
    Ok(TaskOffsets {
        group_leader,
        real_parent,
        start_boottime,
        pid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut types = Vec::new();
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&((1 << 24) as u32).to_le_bytes());
        types.extend_from_slice(&8u32.to_le_bytes());
        types.extend_from_slice(&0x8000_0001u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&((1 << 24) as u32).to_le_bytes());
        types.extend_from_slice(&4u32.to_le_bytes());
        types.extend_from_slice(&0x8000_0001u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&((2 << 24) as u32).to_le_bytes());
        types.extend_from_slice(&4u32.to_le_bytes());
        types.extend_from_slice(&50u32.to_le_bytes());
        types.extend_from_slice(&((4u32 << 24) | 4).to_le_bytes());
        types.extend_from_slice(&40u32.to_le_bytes());
        for (name, kind, offset) in [
            (6u32, 3u32, 64u32),
            (19, 3, 128),
            (31, 1, 192),
            (46, 2, 256),
        ] {
            types.extend_from_slice(&name.to_le_bytes());
            types.extend_from_slice(&kind.to_le_bytes());
            types.extend_from_slice(&offset.to_le_bytes());
        }
        let strings = b"\0u64\0\0group_leader\0real_parent\0start_boottime\0pid\0task_struct\0";
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x9f, 0xeb, 1, 0]);
        bytes.extend_from_slice(&24u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(types.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(types.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&types);
        bytes.extend_from_slice(strings);
        bytes
    }

    #[test]
    fn reads_target_task_offsets() {
        let offsets = task_offsets_from_btf(&fixture()).unwrap();
        assert_eq!(
            offsets,
            TaskOffsets {
                group_leader: 8,
                real_parent: 16,
                start_boottime: 24,
                pid: 32,
            }
        );
    }

    #[test]
    fn missing_start_boottime_is_explicit() {
        let mut bytes = fixture();
        let name = b"start_boottime";
        let at = bytes
            .windows(name.len())
            .position(|window| window == name)
            .unwrap();
        bytes[at] = b'X';
        assert!(task_offsets_from_btf(&bytes)
            .unwrap_err()
            .to_string()
            .contains("start_boottime"));
    }

    #[test]
    fn ticks_follow_integer_kernel_conversion() {
        assert_eq!(start_boottime_ns_to_ticks(123_456_789, 100), Some(12));
        assert_eq!(start_boottime_ns_to_ticks(9_999_999, 100), Some(0));
        assert_eq!(start_boottime_ns_to_ticks(10_000_000, 100), Some(1));
        assert_eq!(start_boottime_ns_to_ticks(1, 0), None);
    }
}
