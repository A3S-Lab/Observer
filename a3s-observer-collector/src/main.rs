//! a3s-observer collector — loads the eBPF probes, pumps the ring buffer, and emits
//! enriched events through the [`Exporter`] contract. This is the exec-probe vertical
//! slice: it proves the Aya toolchain + loader + ring buffer end to end.

use a3s_observer::{AgentEvent, EnrichedEvent, Exporter, Identity, LogExporter};
use a3s_observer_common::ExecEvent;
use anyhow::Context as _;
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // The eBPF object is built by build.rs (aya-build) into OUT_DIR.
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/probes"
    )))
    .context("load eBPF object")?;

    let prog: &mut TracePoint = ebpf
        .program_mut("exec")
        .context("`exec` program not found in object")?
        .try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_execve")
        .context("attach sys_enter_execve")?;

    // ponytail: LogExporter + default identity for the slice; OtelExporter +
    // pid-tree/k8s IdentityResolver land in task #6.
    let exporter = LogExporter;
    let mut ring =
        RingBuf::try_from(ebpf.take_map("EVENTS").context("`EVENTS` map not found")?)?;

    tracing::info!("a3s-observer-collector: exec probe attached; streaming (Ctrl-C to stop)");

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            // ponytail: poll loop; a production collector uses AsyncFd on the ring fd.
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                while let Some(item) = ring.next() {
                    let bytes: &[u8] = &item;
                    if bytes.len() >= core::mem::size_of::<ExecEvent>() {
                        let ev: ExecEvent =
                            unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const ExecEvent) };
                        exporter.export(&EnrichedEvent {
                            identity: Identity::default(),
                            provider: None,
                            event: AgentEvent::ToolExec {
                                pid: ev.pid,
                                ppid: ev.ppid,
                                argv: argv_of(&ev.filename),
                                cwd: String::new(),
                            },
                        });
                    }
                }
            }
        }
    }

    tracing::info!("a3s-observer-collector: stopped");
    Ok(())
}

fn argv_of(filename: &[u8; 128]) -> Vec<String> {
    let end = filename.iter().position(|&b| b == 0).unwrap_or(filename.len());
    vec![String::from_utf8_lossy(&filename[..end]).into_owned()]
}
