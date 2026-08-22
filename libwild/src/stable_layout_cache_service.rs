//! Opt-in same-user service for consecutive Mach-O stable-layout cache hits.
//!
//! The disk cache remains the authoritative crash-recovery source. This service only retains one
//! already-validated image between linker processes, and exits shortly after it becomes idle.

use crate::Args;
use crate::stable_layout_cache;
use crate::args::macho::MachOArgs;
use sha2::Digest as _;
use std::env;
use std::fs;
use std::io;
use std::io::Read as _;
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::Instant;

const ENABLE_ENV: &str = "WILD_MACHO_INCREMENTAL_CACHE_SERVICE";
const SERVICE_DIRECTORY_ENV: &str = "WILD_MACHO_INCREMENTAL_CACHE_SERVICE_DIR";
const DIAGNOSTICS_ENV: &str = "WILD_MACHO_INCREMENTAL_CACHE_DIAGNOSTICS";
const TIMING_ENV: &str = "WILD_MACHO_INCREMENTAL_CACHE_SERVICE_TIMING";
const DAEMON_ARGUMENT: &str = "--wild-macho-cache-service";
const REQUEST_MAGIC: &[u8] = b"WILD-MACHO-CACHE-SERVICE-3\0";
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_ARGUMENTS: usize = 100_000;
const STARTUP_RETRIES: usize = 100;
const IDLE_TIMEOUT_ENV: &str = "WILD_MACHO_INCREMENTAL_CACHE_SERVICE_IDLE_SECONDS";
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
// Rustc can spend tens of seconds in incremental code generation before it reaches the next final
// link. The opt-in duration remains bounded so a forgotten service cannot retain the image
// indefinitely, while callers that need it can preserve the next link's in-memory state.
const MAX_IDLE_TIMEOUT_SECONDS: u64 = 300;

pub(crate) fn requested() -> bool {
    env::var_os(ENABLE_ENV).is_some()
}

pub(crate) fn try_apply(
    args: &MachOArgs,
    command_line: &[String],
) -> Option<bool> {
    let cache_dir = args.incremental_cache.as_deref()?;
    try_apply_for_cache_dir(cache_dir, command_line)
}

/// Locates the explicit cache directory without paying for the complete client-side linker
/// parser. The service parses and validates the exact argv before it can report a hit; malformed
/// or unsupported invocations simply take the ordinary linker path in the caller.
pub(crate) fn try_apply_command_line(command_line: &[String]) -> Option<bool> {
    let cache_dir = command_line
        .windows(2)
        .find(|arguments| arguments[0] == "-incremental_cache")
        .map(|arguments| Path::new(&arguments[1]))?;
    try_apply_for_cache_dir(cache_dir, command_line)
}

fn try_apply_for_cache_dir(cache_dir: &Path, command_line: &[String]) -> Option<bool> {
    let request_started = Instant::now();
    let socket = socket_path(cache_dir)?;
    let mut stream = connect_or_start(cache_dir, &socket).ok()?;
    let current_dir = env::current_dir().ok()?;
    write_request(&mut stream, &current_dir, command_line).ok()?;
    let response = read_response(&mut stream).ok()?;
    if env::var_os(TIMING_ENV).is_some() {
        eprintln!(
            "wild: Mach-O cache service timing: client_ns={} server_ns={} parse_ns={} apply_ns={}",
            request_started.elapsed().as_nanos(),
            response.server_ns,
            response.parse_ns,
            response.apply_ns,
        );
    }
    Some(response.hit)
}

pub fn run(cache_dir: PathBuf, version: &'static str) -> crate::error::Result {
    let Some(socket) = socket_path(&cache_dir) else {
        return Ok(());
    };
    let listener = match UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
            // A concurrently spawned or still-live service owns this cache root. Do not disturb
            // it; clients will connect to that listener instead.
            return Ok(());
        }
        Err(_) => return Ok(()),
    };
    let _cleanup = SocketCleanup(socket);
    let _resident_image_cleanup = ResidentImageCleanup;
    let _ = fs::set_permissions(listener_path(&_cleanup.0), fs::Permissions::from_mode(0o600));
    let _ = listener.set_nonblocking(true);
    stable_layout_cache::enable_resident_image_cache();

    loop {
        if !wait_for_request(&listener, configured_idle_timeout())? {
            return Ok(());
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                // macOS propagates the listener's nonblocking flag to accepted Unix streams.
                // Keep the listener nonblocking for the readiness/accept race, but a complete
                // request is a short bounded frame and must wait for its remaining bytes.
                let _ = stream.set_nonblocking(false);
                let request_started = Instant::now();
                let mut response = match read_request(&mut stream) {
                    Ok(request) => match apply_request(request, version) {
                        Ok(response) => response,
                        Err(error) => {
                            if env::var_os(DIAGNOSTICS_ENV).is_some() {
                                eprintln!("wild: Mach-O cache service request failed: {error:?}");
                            }
                            Response::miss()
                        }
                    },
                    Err(error) => {
                        if env::var_os(DIAGNOSTICS_ENV).is_some() {
                            eprintln!("wild: Mach-O cache service request decode failed: {error}");
                        }
                        Response::miss()
                    }
                };
                response.server_ns = request_started.elapsed().as_nanos();
                let _ = write_response(&mut stream, &response);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // A peer can disconnect while the socket is marked readable. Wait for the next
                // event rather than adding a fixed sleep to every short-lived linker request.
            }
            // Treat a transient listener error as an empty readiness event. A later poll either
            // accepts the next request or expires the bounded idle lifetime and cleans the socket.
            Err(_) => {}
        }
    }
}

/// Returns the service lifetime requested by the caller, preserving the historical short default
/// when the explicit performance setting is absent or invalid.
fn configured_idle_timeout() -> Duration {
    let seconds = env::var(IDLE_TIMEOUT_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok());
    idle_timeout_from_seconds(seconds)
}

fn idle_timeout_from_seconds(seconds: Option<u64>) -> Duration {
    seconds
        .filter(|seconds| (1..=MAX_IDLE_TIMEOUT_SECONDS).contains(seconds))
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_IDLE_TIMEOUT)
}

/// Blocks until a client connects or the service has been idle long enough to clean itself up.
///
/// The listener stays nonblocking after readiness because an unrelated peer may disconnect before
/// `accept`. `poll` avoids the former 20 ms sleep between checks, which was visible in each tiny
/// incremental link's wall time.
fn wait_for_request(listener: &UnixListener, idle_timeout: Duration) -> io::Result<bool> {
    let timeout = i32::try_from(idle_timeout.as_millis()).expect("idle timeout fits poll");
    let mut descriptor = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let ready = unsafe { libc::poll(&raw mut descriptor, 1, timeout) };
        if ready > 0 {
            return Ok(true);
        }
        if ready == 0 {
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

struct Response {
    hit: bool,
    server_ns: u128,
    parse_ns: u128,
    apply_ns: u128,
}

impl Response {
    fn miss() -> Self {
        Self {
            hit: false,
            server_ns: 0,
            parse_ns: 0,
            apply_ns: 0,
        }
    }
}

fn write_response(stream: &mut UnixStream, response: &Response) -> io::Result<()> {
    stream.write_all(&[u8::from(response.hit)])?;
    stream.write_all(&response.server_ns.to_le_bytes())?;
    stream.write_all(&response.parse_ns.to_le_bytes())?;
    stream.write_all(&response.apply_ns.to_le_bytes())
}

fn read_response(stream: &mut UnixStream) -> io::Result<Response> {
    let mut hit = [0_u8; 1];
    let mut server_ns = [0_u8; size_of::<u128>()];
    let mut parse_ns = [0_u8; size_of::<u128>()];
    let mut apply_ns = [0_u8; size_of::<u128>()];
    stream.read_exact(&mut hit)?;
    stream.read_exact(&mut server_ns)?;
    stream.read_exact(&mut parse_ns)?;
    stream.read_exact(&mut apply_ns)?;
    Ok(Response {
        hit: hit[0] == 1,
        server_ns: u128::from_le_bytes(server_ns),
        parse_ns: u128::from_le_bytes(parse_ns),
        apply_ns: u128::from_le_bytes(apply_ns),
    })
}

fn socket_path(cache_dir: &Path) -> Option<PathBuf> {
    let service_directory = env::var_os(SERVICE_DIRECTORY_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| cache_dir.to_path_buf());
    fs::create_dir_all(&service_directory).ok()?;
    let cache_key = sha2::Sha256::digest(cache_dir.as_os_str().as_encoded_bytes());
    let cache_key = u64::from_be_bytes(
        cache_key[..8]
            .try_into()
            .expect("SHA-256 prefix has exactly eight bytes"),
    );
    let path = service_directory.join(format!("macho-{cache_key:016x}.sock"));
    (path.as_os_str().as_encoded_bytes().len() < 100).then_some(path)
}

fn connect_or_start(cache_dir: &Path, socket: &Path) -> io::Result<UnixStream> {
    if let Ok(stream) = UnixStream::connect(socket) {
        return Ok(stream);
    }
    // A previous service can disappear between its last request and socket cleanup. Only remove
    // this exact socket after a failed connection; a live listener was returned above.
    if socket.exists() {
        fs::remove_file(socket)?;
    }
    let executable = env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg(DAEMON_ARGUMENT)
        .arg(cache_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null());
    if env::var_os(DIAGNOSTICS_ENV).is_some() {
        command.stderr(std::process::Stdio::inherit());
    } else {
        command.stderr(std::process::Stdio::null());
    }
    let _ = command.spawn()?;
    for _ in 0..STARTUP_RETRIES {
        if let Ok(stream) = UnixStream::connect(socket) {
            return Ok(stream);
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "cache service did not start"))
}

fn write_request(
    stream: &mut UnixStream,
    current_dir: &Path,
    command_line: &[String],
) -> io::Result<()> {
    stream.write_all(REQUEST_MAGIC)?;
    write_string(stream, &current_dir.to_string_lossy())?;
    write_u32(stream, u32::try_from(command_line.len()).map_err(frame_too_large)?)?;
    for argument in command_line {
        write_string(stream, argument)?;
    }
    Ok(())
}

struct Request {
    current_dir: PathBuf,
    command_line: Vec<String>,
}

fn read_request(stream: &mut UnixStream) -> io::Result<Request> {
    let mut magic = vec![0_u8; REQUEST_MAGIC.len()];
    stream.read_exact(&mut magic)?;
    if magic != REQUEST_MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "wrong cache service request"));
    }
    let current_dir = PathBuf::from(read_string(stream)?);
    let count = usize::try_from(read_u32(stream)?).map_err(frame_too_large)?;
    if count > MAX_ARGUMENTS {
        return Err(frame_too_large(count));
    }
    let mut command_line = Vec::with_capacity(count);
    for _ in 0..count {
        command_line.push(read_string(stream)?);
    }
    Ok(Request {
        current_dir,
        command_line,
    })
}

fn apply_request(request: Request, version: &str) -> crate::error::Result<Response> {
    let request_started = Instant::now();
    env::set_current_dir(request.current_dir)?;
    let arguments = || request.command_line.iter().map(String::as_str);
    let mut args = Args::new(arguments)?;
    args.set_version(version);
    args.parse(arguments)?;
    let Args::MachO(args) = args else {
        return Ok(Response::miss());
    };
    let parsed = request_started.elapsed();
    let hit = stable_layout_cache::try_apply(&args);
    Ok(Response {
        hit,
        server_ns: 0,
        parse_ns: parsed.as_nanos(),
        apply_ns: request_started.elapsed().as_nanos() - parsed.as_nanos(),
    })
}

fn write_u32(stream: &mut UnixStream, value: u32) -> io::Result<()> {
    stream.write_all(&value.to_le_bytes())
}

fn read_u32(stream: &mut UnixStream) -> io::Result<u32> {
    let mut bytes = [0_u8; size_of::<u32>()];
    stream.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn write_string(stream: &mut UnixStream, value: &str) -> io::Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(frame_too_large(bytes.len()));
    }
    write_u32(stream, u32::try_from(bytes.len()).map_err(frame_too_large)?)?;
    stream.write_all(bytes)
}

fn read_string(stream: &mut UnixStream) -> io::Result<String> {
    let length = usize::try_from(read_u32(stream)?).map_err(frame_too_large)?;
    if length > MAX_FRAME_BYTES {
        return Err(frame_too_large(length));
    }
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 request"))
}

fn frame_too_large<T: std::fmt::Display>(value: T) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("cache service frame is too large: {value}"))
}

struct SocketCleanup(PathBuf);

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// The resident image is intentionally process-local. Remove its APFS clone when this bounded
/// service stops so its warm-link speedup does not turn into a persistent cache allocation.
struct ResidentImageCleanup;

impl Drop for ResidentImageCleanup {
    fn drop(&mut self) {
        stable_layout_cache::clear_resident_image_cache();
    }
}

fn listener_path(path: &Path) -> &Path {
    path
}

#[cfg(test)]
mod tests {
    use super::DEFAULT_IDLE_TIMEOUT;
    use super::MAX_IDLE_TIMEOUT_SECONDS;
    use super::idle_timeout_from_seconds;
    use std::time::Duration;

    #[test]
    fn service_idle_timeout_is_explicit_and_bounded() {
        assert_eq!(idle_timeout_from_seconds(None), DEFAULT_IDLE_TIMEOUT);
        assert_eq!(idle_timeout_from_seconds(Some(0)), DEFAULT_IDLE_TIMEOUT);
        assert_eq!(idle_timeout_from_seconds(Some(120)), Duration::from_secs(120));
        assert_eq!(
            idle_timeout_from_seconds(Some(MAX_IDLE_TIMEOUT_SECONDS + 1)),
            DEFAULT_IDLE_TIMEOUT
        );
    }
}
