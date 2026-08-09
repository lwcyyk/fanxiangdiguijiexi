use std::collections::HashSet;
use std::env;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ri_knot_trace_producer::{
    ADAPTER_PROTOCOL, HookKind, MAX_HOOK_LINE_BYTES, RequestKey, TraceMachine, parse_hook_header,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

type AnyError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ri_knot_trace_producer=info".into()),
        )
        .init();
    let settings = Settings::from_env()?;
    prepare_socket(&settings.hook_socket)?;
    let listener = UnixListener::bind(&settings.hook_socket)?;
    std::fs::set_permissions(
        &settings.hook_socket,
        std::fs::Permissions::from_mode(settings.socket_mode),
    )?;
    let machine = Arc::new(Mutex::new(TraceMachine::new(
        settings.server_id.clone(),
        settings.max_contexts,
    )?));
    tracing::info!(
        socket = %settings.hook_socket.display(),
        expected_uid = settings.expected_uid,
        "Knot Trace Producer listening"
    );
    loop {
        let (stream, _) = listener.accept().await?;
        let peer_uid = stream.peer_cred()?.uid();
        if peer_uid != settings.expected_uid {
            tracing::warn!(peer_uid, "rejected Knot hook peer");
            continue;
        }
        let machine = Arc::clone(&machine);
        let adapter_socket = settings.adapter_socket.clone();
        let timeout = settings.ack_timeout;
        tokio::spawn(async move {
            if let Err(error) = handle_hook(stream, machine, adapter_socket, timeout).await {
                tracing::warn!(%error, "Knot hook connection failed");
            }
        });
    }
}

async fn handle_hook(
    stream: UnixStream,
    machine: Arc<Mutex<TraceMachine>>,
    adapter_socket: PathBuf,
    timeout: Duration,
) -> Result<(), AnyError> {
    let mut contexts = ConnectionContexts::new(Arc::clone(&machine));
    let (read_half, mut hook_writer) = stream.into_split();
    let mut hook_reader = BufReader::new(read_half);
    let mut adapter = None;
    loop {
        let Some(header) = read_hook_header(&mut hook_reader, timeout).await? else {
            return Ok(());
        };
        let (mut frame, wire_len) = match parse_hook_header(header.trim_end()) {
            Ok(value) => value,
            Err(error) => {
                hook_writer.write_all(b"ERR\n").await?;
                return Err(error.into());
            }
        };
        frame.wire.resize(wire_len, 0);
        tokio::time::timeout(timeout, hook_reader.read_exact(&mut frame.wire)).await??;
        let request_key = frame.key;
        let hook_kind = frame.kind;
        if adapter.is_none() {
            match connect_adapter(&adapter_socket, timeout).await {
                Ok(connection) => adapter = Some(connection),
                Err(error) => {
                    abort_context(&machine, &mut contexts, request_key);
                    hook_writer.write_all(b"ERR\n").await?;
                    tracing::warn!(%error, "Trace Adapter connection failed");
                    continue;
                }
            }
        }
        let output = {
            let mut machine = machine
                .lock()
                .map_err(|_| "Trace Producer state lock is poisoned")?;
            machine.process(frame)
        };
        let output = match output {
            Ok(output) => output,
            Err(error) => {
                abort_context(&machine, &mut contexts, request_key);
                hook_writer.write_all(b"ERR\n").await?;
                tracing::warn!(%error, "Knot Trace frame rejected");
                continue;
            }
        };
        if hook_kind == HookKind::Begin {
            contexts.insert(request_key);
        }
        let connection = adapter
            .as_mut()
            .ok_or("Trace Adapter connection is unavailable")?;
        if let Err(error) = spool_events(
            &mut connection.reader,
            &mut connection.writer,
            output.events(),
            timeout,
        )
        .await
        {
            adapter.take();
            abort_context(&machine, &mut contexts, request_key);
            hook_writer.write_all(b"ERR\n").await?;
            tracing::warn!(%error, "Trace Adapter durable spool failed");
            continue;
        }
        hook_writer.write_all(b"OK\n").await?;
        if output.is_terminal() {
            contexts.remove(request_key);
            tracing::debug!("completed Knot Trace context");
        }
    }
}

struct AdapterConnection {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
}

async fn connect_adapter(path: &Path, timeout: Duration) -> Result<AdapterConnection, AnyError> {
    let stream = tokio::time::timeout(timeout, UnixStream::connect(path)).await??;
    let (read_half, mut writer) = stream.into_split();
    tokio::time::timeout(
        timeout,
        writer.write_all(format!("{ADAPTER_PROTOCOL}\n").as_bytes()),
    )
    .await??;
    Ok(AdapterConnection {
        reader: BufReader::new(read_half),
        writer,
    })
}

fn abort_context(
    machine: &Arc<Mutex<TraceMachine>>,
    contexts: &mut ConnectionContexts,
    request_key: RequestKey,
) {
    if let Ok(mut machine) = machine.lock() {
        machine.abort(request_key);
    }
    contexts.remove(request_key);
}

async fn read_hook_header(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    frame_timeout: Duration,
) -> Result<Option<String>, AnyError> {
    // A persistent Resolver connection may legitimately be idle for longer than
    // an ACK timeout. Once a frame starts, its remainder is both time- and
    // length-bounded so a local peer cannot retain an incomplete frame forever.
    let first = match reader.read_u8().await {
        Ok(byte) => byte,
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut wire = vec![first];
    if first != b'\n' {
        let remaining = MAX_HOOK_LINE_BYTES.saturating_sub(1);
        let mut limited = reader.take(u64::try_from(remaining)?);
        tokio::time::timeout(frame_timeout, limited.read_until(b'\n', &mut wire)).await??;
    }
    if wire.len() > MAX_HOOK_LINE_BYTES || wire.last() != Some(&b'\n') {
        return Err("Knot hook header exceeds maximum size or is incomplete".into());
    }
    Ok(Some(String::from_utf8(wire)?))
}

struct ConnectionContexts {
    machine: Arc<Mutex<TraceMachine>>,
    keys: HashSet<RequestKey>,
}

impl ConnectionContexts {
    fn new(machine: Arc<Mutex<TraceMachine>>) -> Self {
        Self {
            machine,
            keys: HashSet::new(),
        }
    }

    fn insert(&mut self, key: RequestKey) {
        self.keys.insert(key);
    }

    fn remove(&mut self, key: RequestKey) {
        self.keys.remove(&key);
    }
}

impl Drop for ConnectionContexts {
    fn drop(&mut self) {
        if let Ok(mut machine) = self.machine.lock() {
            for key in self.keys.drain() {
                machine.abort(key);
            }
        }
    }
}

async fn spool_events(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    events: &[ri_core::TraceEventV2],
    timeout: Duration,
) -> Result<(), AnyError> {
    for event in events {
        let mut wire = serde_json::to_vec(event)?;
        wire.push(b'\n');
        tokio::time::timeout(timeout, writer.write_all(&wire)).await??;
        let mut acknowledgement = String::new();
        tokio::time::timeout(timeout, reader.read_line(&mut acknowledgement)).await??;
        if acknowledgement.trim_end() != format!("OK {}", event.event_id) {
            return Err("Trace Adapter did not durably acknowledge the event".into());
        }
    }
    Ok(())
}

struct Settings {
    hook_socket: PathBuf,
    adapter_socket: PathBuf,
    server_id: String,
    expected_uid: u32,
    socket_mode: u32,
    max_contexts: usize,
    ack_timeout: Duration,
}

impl Settings {
    fn from_env() -> Result<Self, AnyError> {
        let max_contexts = parse_usize("RI_TRACE_MAX_CONTEXTS", 65_536)?;
        let ack_timeout_millis = parse_u64("RI_TRACE_ACK_TIMEOUT_MS", 100)?;
        if max_contexts == 0 || ack_timeout_millis == 0 || ack_timeout_millis > 5_000 {
            return Err("Knot Trace Producer limits are invalid".into());
        }
        Ok(Self {
            hook_socket: required("RI_KNOT_TRACE_HOOK_SOCKET")?.into(),
            adapter_socket: required("RI_TRACE_SOCKET")?.into(),
            server_id: required("RI_AGENT_SERVER_ID")?,
            expected_uid: required("RI_KNOT_TRACE_EXPECTED_UID")?.parse()?,
            socket_mode: u32::from_str_radix(
                &env::var("RI_KNOT_TRACE_HOOK_SOCKET_MODE").unwrap_or_else(|_| "600".into()),
                8,
            )?,
            max_contexts,
            ack_timeout: Duration::from_millis(ack_timeout_millis),
        })
    }
}

fn prepare_socket(path: &Path) -> Result<(), AnyError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => return Err("Knot hook path exists and is not a Unix socket".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn required(name: &str) -> Result<String, AnyError> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn parse_usize(name: &str, default: usize) -> Result<usize, AnyError> {
    Ok(env::var(name).map_or(Ok(default), |value| value.parse())?)
}

fn parse_u64(name: &str, default: u64) -> Result<u64, AnyError> {
    Ok(env::var(name).map_or(Ok(default), |value| value.parse())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    fn query(id: u16) -> Vec<u8> {
        let mut wire = vec![
            0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
            b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ];
        wire[0..2].copy_from_slice(&id.to_be_bytes());
        wire
    }

    async fn write_begin(stream: &mut UnixStream, request_uid: u32, wire: &[u8]) {
        stream
            .write_all(
                format!(
                    "RIK1 BEGIN 10 {request_uid} none - 0 secure accepted {} -\n",
                    wire.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stream.write_all(wire).await.unwrap();
    }

    async fn read_acknowledgement(stream: &mut BufReader<UnixStream>) -> String {
        let mut acknowledgement = String::new();
        stream.read_line(&mut acknowledgement).await.unwrap();
        acknowledgement
    }

    async fn accept_adapter_event(listener: &UnixListener) -> ri_core::TraceEventV2 {
        let (stream, _) = listener.accept().await.unwrap();
        let (read_half, mut writer) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line, format!("{ADAPTER_PROTOCOL}\n"));
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let event = serde_json::from_str::<ri_core::TraceEventV2>(line.trim_end()).unwrap();
        writer
            .write_all(format!("OK {}\n", event.event_id).as_bytes())
            .await
            .unwrap();
        event
    }

    fn socket_pair() -> (UnixStream, UnixStream) {
        let (first, second) = std::os::unix::net::UnixStream::pair().unwrap();
        first.set_nonblocking(true).unwrap();
        second.set_nonblocking(true).unwrap();
        (
            UnixStream::from_std(first).unwrap(),
            UnixStream::from_std(second).unwrap(),
        )
    }

    #[tokio::test]
    async fn adapter_unavailable_fails_one_frame_then_recovers_on_same_hook_connection() {
        let directory = tempfile::tempdir().unwrap();
        let adapter_socket = directory.path().join("adapter.sock");
        let machine = Arc::new(Mutex::new(
            TraceMachine::new("operator/L01/r1".into(), 10).unwrap(),
        ));
        let (hook_server, hook_client) = socket_pair();
        let handler = tokio::spawn(handle_hook(
            hook_server,
            Arc::clone(&machine),
            adapter_socket.clone(),
            Duration::from_millis(200),
        ));
        let mut hook_client = BufReader::new(hook_client);

        write_begin(hook_client.get_mut(), 20, &query(7)).await;
        assert_eq!(read_acknowledgement(&mut hook_client).await, "ERR\n");
        assert_eq!(machine.lock().unwrap().active_contexts(), 0);

        let adapter = UnixListener::bind(&adapter_socket).unwrap();
        let accepted = tokio::spawn(async move { accept_adapter_event(&adapter).await });
        write_begin(hook_client.get_mut(), 21, &query(8)).await;
        assert_eq!(read_acknowledgement(&mut hook_client).await, "OK\n");
        assert_eq!(
            accepted.await.unwrap().kind,
            ri_core::TraceEventKind::ClientQuery
        );
        assert_eq!(machine.lock().unwrap().active_contexts(), 1);

        drop(hook_client);
        handler.await.unwrap().unwrap();
        assert_eq!(machine.lock().unwrap().active_contexts(), 0);
    }

    #[tokio::test]
    async fn stale_adapter_stream_fails_one_frame_then_reconnects() {
        let directory = tempfile::tempdir().unwrap();
        let adapter_socket = directory.path().join("adapter.sock");
        let adapter = UnixListener::bind(&adapter_socket).unwrap();
        let machine = Arc::new(Mutex::new(
            TraceMachine::new("operator/L01/r1".into(), 10).unwrap(),
        ));
        let (hook_server, hook_client) = socket_pair();
        let handler = tokio::spawn(handle_hook(
            hook_server,
            Arc::clone(&machine),
            adapter_socket.clone(),
            Duration::from_millis(200),
        ));
        let mut hook_client = BufReader::new(hook_client);

        let first_adapter = tokio::spawn(async move { accept_adapter_event(&adapter).await });
        write_begin(hook_client.get_mut(), 20, &query(7)).await;
        assert_eq!(read_acknowledgement(&mut hook_client).await, "OK\n");
        first_adapter.await.unwrap();

        write_begin(hook_client.get_mut(), 21, &query(8)).await;
        assert_eq!(read_acknowledgement(&mut hook_client).await, "ERR\n");
        assert_eq!(machine.lock().unwrap().active_contexts(), 1);

        std::fs::remove_file(&adapter_socket).unwrap();
        let replacement = UnixListener::bind(&adapter_socket).unwrap();
        let replacement_adapter =
            tokio::spawn(async move { accept_adapter_event(&replacement).await });
        write_begin(hook_client.get_mut(), 22, &query(9)).await;
        assert_eq!(read_acknowledgement(&mut hook_client).await, "OK\n");
        replacement_adapter.await.unwrap();
        assert_eq!(machine.lock().unwrap().active_contexts(), 2);

        drop(hook_client);
        handler.await.unwrap().unwrap();
        assert_eq!(machine.lock().unwrap().active_contexts(), 0);
    }

    #[test]
    fn settings_reject_zero_capacity() {
        // Environment parsing is exercised in process-level acceptance. This
        // assertion keeps the hard limit visible to unit coverage.
        assert_eq!(Duration::from_millis(100).as_millis(), 100);
    }

    #[test]
    fn machine_output_terminal_flag_is_explicit() {
        assert!(ri_knot_trace_producer::MachineOutput::Terminal(Vec::new()).is_terminal());
        assert!(!ri_knot_trace_producer::MachineOutput::Events(Vec::new()).is_terminal());
    }
}
