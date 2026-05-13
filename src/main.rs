//! PortScanner v2.1 — nmap-style port scanner with embedded web GUI
//! Usage:
//!   portscanner --gui                  Launch web GUI (opens browser)
//!   portscanner <target> -p <ports>    CLI scan
//!   portscanner --help                 Show help

#![allow(clippy::too_many_arguments)]

use crossbeam_channel::{bounded, Receiver, Sender};
use ipnetwork::IpNetwork;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::{transport_channel, TransportProtocol};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::fs;
use std::io::{self, BufRead, Read};
use std::net::{IpAddr, Ipv4Addr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use std::thread;
use tiny_http::{Header, Response, StatusCode};

// ─── Embedded HTML ────────────────────────────────────────────────────────────
const GUI_HTML: &str = include_str!("index.html");

// ─── Port presets ─────────────────────────────────────────────────────────────
const TOP_100: &[u16] = &[
    7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,
    144,179,194,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,
    631,646,873,990,993,995,1080,1099,1433,1521,1720,1723,1755,1900,2000,2001,
    2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,
    5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,
    8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157,
];

const PORT_PRESETS: &[(&str, &str)] = &[
    ("Common",  "21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5900,8080"),
    ("Top100",  "top100"),
    ("Full",    "1-65535"),
    ("Web+DB",  "80,443,8080,8443,3306,5432,1433,1521,6379,27017,9200,9300"),
    ("Dev",     "3000,4000,5000,8000,8080,8888,9000,3001,4200,5173"),
    ("SMB",     "135,137,138,139,445,593"),
    ("RTSP",    "554,8554,8888,10554"),
    ("Web",     "80,443,8000,8008,8080,8081,8443,8888"),
];

fn service_name(port: u16, proto: &str) -> &'static str {
    match (port, proto) {
        (21,_)=>"ftp",(22,_)=>"ssh",(23,_)=>"telnet",(25,_)=>"smtp",
        (53,_)=>"dns",(67,"udp")=>"dhcps",(69,"udp")=>"tftp",(79,_)=>"finger",
        (80,_)=>"http",(88,_)=>"kerberos",(110,_)=>"pop3",(111,_)=>"rpcbind",
        (123,"udp")=>"ntp",(135,_)=>"msrpc",(137,"udp")=>"netbios-ns",
        (139,_)=>"netbios",(143,_)=>"imap",(161,"udp")=>"snmp",
        (389,_)=>"ldap",(443,_)=>"https",(445,_)=>"smb",(465,_)=>"smtps",
        (514,"udp")=>"syslog",(554,_)=>"rtsp",(587,_)=>"smtp-sub",
        (631,_)=>"ipp",(636,_)=>"ldaps",(873,_)=>"rsync",(993,_)=>"imaps",
        (995,_)=>"pop3s",(1080,_)=>"socks",(1194,"udp")=>"openvpn",
        (1433,_)=>"mssql",(1521,_)=>"oracle",(1723,_)=>"pptp",
        (1900,"udp")=>"upnp",(2049,_)=>"nfs",(3306,_)=>"mysql",
        (3389,_)=>"rdp",(5060,_)=>"sip",(5432,_)=>"postgres",(5900,_)=>"vnc",
        (6379,_)=>"redis",(8080,_)=>"http-proxy",(8443,_)=>"https-alt",
        (9200,_)=>"elasticsearch",(27017,_)=>"mongodb",_=>"unknown",
    }
}

// ─── Types ────────────────────────────────────────────────────────────────────
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ScanMode { Tcp, Syn, Udp }

impl Default for ScanMode { fn default() -> Self { ScanMode::Tcp } }

impl fmt::Display for ScanMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ScanMode::Tcp => write!(f, "TCP Connect"),
            ScanMode::Syn => write!(f, "SYN Stealth"),
            ScanMode::Udp => write!(f, "UDP"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
enum Timing { T1, T2, T3, T4, T5 }

impl Default for Timing { fn default() -> Self { Timing::T3 } }

impl Timing {
    fn label(self) -> &'static str {
        match self {
            Timing::T1 => "T1 – Slowest  (3000ms, 10 threads)",
            Timing::T2 => "T2 – Slow     (1500ms, 25 threads)",
            Timing::T3 => "T3 – Normal   ( 800ms, 50 threads)",
            Timing::T4 => "T4 – Fast     ( 300ms, 200 threads)",
            Timing::T5 => "T5 – Fastest  ( 100ms, 500 threads)",
        }
    }
    fn params(self) -> (u64, usize) {
        match self {
            Timing::T1 => (3000, 10),
            Timing::T2 => (1500, 25),
            Timing::T3 => (800,  50),
            Timing::T4 => (300,  200),
            Timing::T5 => (100,  500),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct ScanResult {
    host:    String,
    port:    u16,
    proto:   String,
    state:   String,
    service: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct ScanTask { host: String, port: u16, proto: String }

#[derive(Serialize, Deserialize, Debug)]
struct SavedState {
    remaining: Vec<ScanTask>,
    completed: Vec<ScanResult>,
    timing:    Timing,
    mode:      ScanMode,
}

#[derive(Debug)]
enum ScanMsg {
    Result(ScanResult),
    Progress { done: usize, total: usize },
    Done     { elapsed_secs: f64 },
    Paused   { state_path: String },
    Log      (String),
}

// ─── HTTP Request body ───────────────────────────────────────────────────────
#[derive(Deserialize)]
struct ScanRequest {
    #[serde(default)]
    targets:      Vec<String>,
    #[serde(default = "default_ports")]
    ports:        String,
    #[serde(default)]
    mode:         ScanMode,
    #[serde(default = "default_timeout")]
    timeout_ms:   u64,
    #[serde(default = "default_threads")]
    thread_count: usize,
    #[serde(default = "default_state_file")]
    state_file:   String,
    output_file:  Option<String>,
    input_file:   Option<String>,
    input_dir:    Option<String>,
    resume_file:  Option<String>,
}
fn default_ports()      -> String { "1-1024".into() }
fn default_timeout()    -> u64    { 500 }
fn default_threads()    -> usize  { 100 }
fn default_state_file() -> String { "scan_state.json".into() }

// ─── Live scan state (shared across HTTP threads for reconnect) ───────────────
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ScanStatus { Idle, Scanning, Paused, Done }

#[derive(Serialize, Clone, Debug)]
struct LiveScanState {
    status:     ScanStatus,
    done:       usize,
    total:      usize,
    results:    Vec<ScanResult>,
    mode:       String,
    timeout_ms: u64,
    threads:    usize,
    state_file: String,
    elapsed_ms: u64,
}
impl Default for LiveScanState {
    fn default() -> Self {
        Self { status: ScanStatus::Idle, done: 0, total: 0, results: vec![],
               mode: "tcp".into(), timeout_ms: 800, threads: 50,
               state_file: "scan_state.json".into(), elapsed_ms: 0 }
    }
}

// ─── ChannelReader — bridges channel → HTTP stream ────────────────────────────
struct ChannelReader {
    rx:  Receiver<Option<Vec<u8>>>,
    buf: Vec<u8>,
    pos: usize,
}

impl ChannelReader {
    fn new(rx: Receiver<Option<Vec<u8>>>) -> Self {
        ChannelReader { rx, buf: Vec::new(), pos: 0 }
    }
}

impl Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() { return Ok(0); }
        // Drain buffered bytes first
        if self.pos < self.buf.len() {
            let n = (self.buf.len() - self.pos).min(out.len());
            out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        // Block for next chunk from channel
        match self.rx.recv() {
            Ok(Some(data)) => {
                let n = data.len().min(out.len());
                out[..n].copy_from_slice(&data[..n]);
                if n < data.len() {
                    self.buf = data[n..].to_vec();
                    self.pos = 0;
                } else {
                    self.buf.clear();
                    self.pos = 0;
                }
                Ok(n)
            }
            Ok(None) | Err(_) => Ok(0), // EOF
        }
    }
}

// ─── TCP Connect ──────────────────────────────────────────────────────────────
fn tcp_connect(host: &str, port: u16, timeout_ms: u64) -> String {
    let addr = format!("{}:{}", host, port);
    match addr.to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(sa) => match TcpStream::connect_timeout(&sa, Duration::from_millis(timeout_ms)) {
                Ok(_)  => "open".into(),
                Err(e) => if e.to_string().contains("refused") { "closed".into() } else { "filtered".into() },
            },
            None => "filtered".into(),
        },
        Err(_) => "filtered".into(),
    }
}

// ─── SYN scan ─────────────────────────────────────────────────────────────────
fn resolve_v4(host: &str) -> Option<Ipv4Addr> {
    format!("{}:0", host).to_socket_addrs().ok()?
        .find_map(|sa| match sa.ip() { IpAddr::V4(ip) => Some(ip), _ => None })
}
fn source_ip_for(dst: Ipv4Addr) -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect((dst, 80)).ok()?;
    match sock.local_addr().ok()?.ip() { IpAddr::V4(ip) => Some(ip), _ => None }
}
fn rand_u32() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default()
        .subsec_nanos().wrapping_mul(1_664_525).wrapping_add(1_013_904_223)
}
fn syn_scan(host: &str, port: u16, timeout_ms: u64) -> String {
    let dst_ip = match resolve_v4(host) { Some(ip) => ip, None => return "filtered".into() };
    let src_ip = match source_ip_for(dst_ip) { Some(ip) => ip, None => return "filtered".into() };
    let src_port: u16 = 40000 + (port % 20000);
    let proto = Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    let (mut tx, mut rx) = match transport_channel(4096, proto) {
        Ok(ch) => ch,
        Err(_) => return tcp_connect(host, port, timeout_ms),
    };
    let mut buf = vec![0u8; MutableTcpPacket::minimum_packet_size()];
    {
        let mut pkt = MutableTcpPacket::new(&mut buf).unwrap();
        pkt.set_source(src_port); pkt.set_destination(port);
        pkt.set_sequence(rand_u32()); pkt.set_data_offset(5);
        pkt.set_flags(TcpFlags::SYN); pkt.set_window(64240);
        let ck = pnet::packet::tcp::ipv4_checksum(&pkt.to_immutable(), &src_ip, &dst_ip);
        pkt.set_checksum(ck);
    }
    if tx.send_to(TcpPacket::new(&buf).unwrap(), IpAddr::V4(dst_ip)).is_err() {
        return "filtered".into();
    }
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut iter = pnet::transport::tcp_packet_iter(&mut rx);
    loop {
        if Instant::now() >= deadline { break "filtered".into(); }
        match iter.next() {
            Ok((pkt, addr)) => {
                if addr != IpAddr::V4(dst_ip) { continue; }
                if pkt.get_destination() != src_port || pkt.get_source() != port { continue; }
                let flags = pkt.get_flags();
                if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                    let mut rbuf = vec![0u8; MutableTcpPacket::minimum_packet_size()];
                    let mut rst = MutableTcpPacket::new(&mut rbuf).unwrap();
                    rst.set_source(src_port); rst.set_destination(port);
                    rst.set_sequence(pkt.get_acknowledgement()); rst.set_data_offset(5);
                    rst.set_flags(TcpFlags::RST);
                    let ck = pnet::packet::tcp::ipv4_checksum(&rst.to_immutable(), &src_ip, &dst_ip);
                    rst.set_checksum(ck);
                    let _ = tx.send_to(TcpPacket::new(&rbuf).unwrap(), IpAddr::V4(dst_ip));
                    break "open".into();
                } else if flags & TcpFlags::RST != 0 { break "closed".into(); }
            }
            Err(_) => break "filtered".into(),
        }
    }
}

// ─── UDP scan ─────────────────────────────────────────────────────────────────
fn udp_scan(host: &str, port: u16, timeout_ms: u64) -> String {
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => {
            sock.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok();
            let addr = format!("{}:{}", host, port);
            match addr.to_socket_addrs() {
                Ok(mut it) => if let Some(sa) = it.next() {
                    if sock.send_to(&[0u8; 4], sa).is_err() { return "filtered".into(); }
                    let mut buf = [0u8; 128];
                    match sock.recv_from(&mut buf) {
                        Ok(_)  => "open".into(),
                        Err(e) => if e.to_string().contains("refused") || e.to_string().contains("10054") {
                            "closed".into()
                        } else { "open|filtered".into() },
                    }
                } else { "filtered".into() },
                Err(_) => "filtered".into(),
            }
        }
        Err(_) => "filtered".into(),
    }
}

// ─── Port parser ──────────────────────────────────────────────────────────────
fn parse_ports(spec: &str) -> Vec<u16> {
    let s = spec.trim();
    if s.eq_ignore_ascii_case("top100") { return TOP_100.to_vec(); }
    for (name, ports) in PORT_PRESETS {
        if s.eq_ignore_ascii_case(name) { return parse_ports(ports); }
    }
    let mut out = Vec::new();
    for part in s.split(',') {
        let p = part.trim();
        if p.contains('-') {
            let h: Vec<&str> = p.splitn(2, '-').collect();
            if h.len() == 2 {
                if let (Ok(a), Ok(b)) = (h[0].parse::<u16>(), h[1].parse::<u16>()) {
                    for n in a..=b { out.push(n); }
                }
            }
        } else if let Ok(n) = p.parse::<u16>() { out.push(n); }
    }
    out.dedup();
    out
}

// ─── Target helpers ───────────────────────────────────────────────────────────
fn expand_target(t: &str) -> Vec<String> {
    let t = t.trim();
    if t.contains('/') {
        match t.parse::<IpNetwork>() {
            Ok(net) => net.iter().map(|ip| ip.to_string()).collect(),
            Err(_)  => if t.is_empty() { vec![] } else { vec![t.to_string()] },
        }
    } else if !t.is_empty() { vec![t.to_string()] } else { vec![] }
}
fn hosts_from_file(path: &str) -> Vec<String> {
    match std::fs::File::open(path) {
        Ok(f) => io::BufReader::new(f).lines().flatten()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .flat_map(|l| expand_target(&l)).collect(),
        Err(_) => vec![],
    }
}
fn hosts_from_dir(dir: &str) -> Vec<String> {
    match fs::read_dir(dir) {
        Ok(entries) => entries.flatten()
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("txt"))
            .flat_map(|e| hosts_from_file(e.path().to_str().unwrap_or("")))
            .collect(),
        Err(_) => vec![],
    }
}

// ─── Build task list ──────────────────────────────────────────────────────────
fn build_tasks(
    targets: &[String],
    input_file: Option<&str>,
    input_dir:  Option<&str>,
    port_spec:  &str,
    mode:       ScanMode,
) -> Result<Vec<ScanTask>, String> {
    let mut hosts: Vec<String> = Vec::new();
    for t in targets {
        for part in t.split(',') {
            hosts.extend(expand_target(part.trim()));
        }
    }
    if let Some(f) = input_file {
        if !f.trim().is_empty() {
            if std::path::Path::new(f.trim()).exists() {
                hosts.extend(hosts_from_file(f.trim()));
            } else {
                return Err(format!("File not found: {}", f.trim()));
            }
        }
    }
    if let Some(d) = input_dir {
        if !d.trim().is_empty() {
            if std::path::Path::new(d.trim()).is_dir() {
                hosts.extend(hosts_from_dir(d.trim()));
            } else {
                return Err(format!("Directory not found: {}", d.trim()));
            }
        }
    }
    let mut seen = HashSet::new();
    hosts.retain(|h| seen.insert(h.clone()));
    let ports = parse_ports(port_spec);
    if ports.is_empty() { return Err("No valid ports parsed from spec.".into()); }
    if hosts.is_empty() { return Err("No targets specified.".into()); }
    let proto = if mode == ScanMode::Udp { "udp" } else { "tcp" };
    Ok(hosts.iter().flat_map(|h| ports.iter().map(move |&p| ScanTask {
        host: h.clone(), port: p, proto: proto.to_string(),
    })).collect())
}

// ─── Scanner thread pool ──────────────────────────────────────────────────────
fn run_scan(
    tasks:       Vec<ScanTask>,
    timeout_ms:  u64,
    threads:     usize,
    mode:        ScanMode,
    tx:          Sender<ScanMsg>,
    pause_flag:  Arc<AtomicBool>,
    stop_flag:   Arc<AtomicBool>,
    state_path:  String,
    prior:       Vec<ScanResult>,
) {
    let total  = tasks.len() + prior.len();
    let done   = Arc::new(AtomicUsize::new(prior.len()));
    let queue  = Arc::new(Mutex::new(VecDeque::from(tasks)));
    let store  = Arc::new(Mutex::new(prior));
    let start  = Instant::now();
    let _ = tx.send(ScanMsg::Progress { done: 0, total });

    let mut handles = Vec::new();
    for _ in 0..threads.min(total.max(1)) {
        let q    = Arc::clone(&queue);
        let st   = Arc::clone(&store);
        let d    = Arc::clone(&done);
        let tx2  = tx.clone();
        let pf   = Arc::clone(&pause_flag);
        let sf   = Arc::clone(&stop_flag);
        handles.push(thread::spawn(move || {
            loop {
                if pf.load(Ordering::Relaxed) || sf.load(Ordering::Relaxed) { break; }
                let task = q.lock().unwrap().pop_front();
                match task {
                    None => break,
                    Some(t) => {
                        let state = match mode {
                            ScanMode::Tcp => tcp_connect(&t.host, t.port, timeout_ms),
                            ScanMode::Syn => syn_scan(&t.host, t.port, timeout_ms),
                            ScanMode::Udp => udp_scan(&t.host, t.port, timeout_ms),
                        };
                        let rec = ScanResult {
                            host:    t.host.clone(),
                            port:    t.port,
                            proto:   t.proto.clone(),
                            state,
                            service: service_name(t.port, &t.proto).to_string(),
                        };
                        st.lock().unwrap().push(rec.clone());
                        let _ = tx2.send(ScanMsg::Result(rec));
                        let n = d.fetch_add(1, Ordering::Relaxed) + 1;
                        let _ = tx2.send(ScanMsg::Progress { done: n, total });
                    }
                }
            }
        }));
    }
    for h in handles { h.join().ok(); }

    if pause_flag.load(Ordering::Relaxed) {
        let remaining: Vec<ScanTask> = queue.lock().unwrap().drain(..).collect();
        let completed = store.lock().unwrap().clone();
        let state = SavedState { remaining, completed, timing: Timing::T3, mode };
        if let Ok(json) = serde_json::to_string_pretty(&state) { fs::write(&state_path, json).ok(); }
        let _ = tx.send(ScanMsg::Paused { state_path });
    } else {
        let _ = tx.send(ScanMsg::Done { elapsed_secs: start.elapsed().as_secs_f64() });
    }
}

// ─── Save outputs ──────────────────────────────────────────────────────────────
fn save_outputs(results: &[ScanResult], base: &str) {
    if base.trim().is_empty() { return; }
    // JSON
    if let Ok(j) = serde_json::to_string_pretty(results) {
        fs::write(format!("{}.json", base), j).ok();
    }
    // TXT
    let mut out = format!("{:<20}{:<14}{:<12}{}\n", "HOST", "PORT/PROTO", "STATE", "SERVICE");
    out.push_str(&"-".repeat(60));
    out.push('\n');
    for r in results {
        out.push_str(&format!("{:<20}{:<14}{:<12}{}\n",
            r.host, format!("{}/{}", r.port, r.proto), r.state, r.service));
    }
    fs::write(format!("{}.txt", base), out).ok();
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
fn ndjson_line(val: serde_json::Value) -> Vec<u8> {
    let mut b = serde_json::to_vec(&val).unwrap_or_default();
    b.push(b'\n');
    b
}

fn open_browser(url: &str) {
    // Try platform-specific openers; ignore failures
    #[cfg(target_os = "linux")]
    { let _ = std::process::Command::new("xdg-open").arg(url).spawn(); }
    #[cfg(target_os = "macos")]
    { let _ = std::process::Command::new("open").arg(url).spawn(); }
    #[cfg(target_os = "windows")]
    { let _ = std::process::Command::new("cmd").args(["/c", "start", "", url]).spawn(); }
    let _ = url; // suppress unused-variable on unknown targets
}

fn make_header(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap()
}

// ─── GUI HTTP server ──────────────────────────────────────────────────────────
// ─── GUI HTTP server ──────────────────────────────────────────────────────────
//
// Each incoming request is dispatched to its own thread so that a long-running
// streaming scan response never blocks /api/stop or /api/pause requests.
fn run_gui() {
    let addr = "127.0.0.1:7681";
    let server = Arc::new(match tiny_http::Server::http(addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[ERROR] Cannot bind {}: {}", addr, e);
            eprintln!("[HINT]  Try a different port or check if another instance is running.");
            std::process::exit(1);
        }
    });

    println!("╔══════════════════════════════════════════════╗");
    println!("║   PortScanner v2.1  —  Web GUI Mode          ║");
    println!("╠══════════════════════════════════════════════╣");
    println!("║  URL: http://{}                  ║", addr);
    println!("║  Press Ctrl+C to quit.                       ║");
    println!("╚══════════════════════════════════════════════╝");

    let url2 = format!("http://{}", addr);
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(350));
        open_browser(&url2);
    });

    // Shared scan-control flags: each request thread gets an Arc clone.
    let stop_flag  = Arc::new(AtomicBool::new(false));
    let pause_flag = Arc::new(AtomicBool::new(false));
    let live_state: Arc<Mutex<LiveScanState>> = Arc::new(Mutex::new(LiveScanState::default()));

    loop {
        let request = match server.recv() {
            Ok(rq)  => rq,
            Err(_)  => break,
        };
        let sf = Arc::clone(&stop_flag);
        let pf = Arc::clone(&pause_flag);
        let ls = Arc::clone(&live_state);
        thread::spawn(move || serve_request(request, sf, pf, ls));
    }
}

/// Handle a single HTTP request on its own thread.
fn serve_request(
    mut request: tiny_http::Request,
    stop_flag:   Arc<AtomicBool>,
    pause_flag:  Arc<AtomicBool>,
    live_state:  Arc<Mutex<LiveScanState>>,
) {
    let method   = format!("{}", request.method());
    let url_path = request.url().split('?').next().unwrap_or("/").to_string();

    if method == "OPTIONS" {
        request.respond(
            Response::empty(StatusCode(200))
                .with_header(make_header("Access-Control-Allow-Origin",  "*"))
                .with_header(make_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS"))
                .with_header(make_header("Access-Control-Allow-Headers", "Content-Type")),
        ).ok();
        return;
    }

    match (method.as_str(), url_path.as_str()) {

        // ── Serve embedded HTML ──────────────────────────────────────────────
        ("GET", "/") | ("GET", "/index.html") => {
            request.respond(
                Response::from_string(GUI_HTML)
                    .with_header(make_header("Content-Type",  "text/html; charset=utf-8"))
                    .with_header(make_header("Cache-Control", "no-store")),
            ).ok();
        }

        // ── Start scan ────────────────────────────────────────────────────────
        ("POST", "/api/scan") => {
            let mut body = String::new();
            if request.as_reader().read_to_string(&mut body).is_err() {
                request.respond(
                    Response::from_string("bad request body")
                        .with_status_code(StatusCode(400)),
                ).ok();
                return;
            }

            let req: ScanRequest = match serde_json::from_str(&body) {
                Ok(r)  => r,
                Err(e) => {
                    let err = ndjson_line(serde_json::json!({"type":"error","msg":e.to_string()}));
                    request.respond(Response::new(
                        StatusCode(400),
                        vec![make_header("Content-Type", "application/x-ndjson")],
                        std::io::Cursor::new(err),
                        None, None,
                    )).ok();
                    return;
                }
            };

            // Build task list (or load from resume file)
            let (tasks, prior): (Vec<ScanTask>, Vec<ScanResult>) =
                if let Some(ref rf) = req.resume_file {
                    match fs::read_to_string(rf) {
                        Ok(data) => match serde_json::from_str::<SavedState>(&data) {
                            Ok(saved) => (saved.remaining, saved.completed),
                            Err(e)    => {
                                let msg = ndjson_line(serde_json::json!({"type":"error","msg":format!("State parse error: {}",e)}));
                                request.respond(Response::new(StatusCode(200),
                                    vec![make_header("Content-Type","application/x-ndjson")],
                                    std::io::Cursor::new(msg), None, None)).ok();
                                return;
                            }
                        },
                        Err(e) => {
                            let msg = ndjson_line(serde_json::json!({"type":"error","msg":format!("Cannot read state: {}",e)}));
                            request.respond(Response::new(StatusCode(200),
                                vec![make_header("Content-Type","application/x-ndjson")],
                                std::io::Cursor::new(msg), None, None)).ok();
                            return;
                        }
                    }
                } else {
                    let targets = req.targets.clone();
                    match build_tasks(&targets, req.input_file.as_deref(),
                                      req.input_dir.as_deref(), &req.ports, req.mode) {
                        Ok(t)  => (t, vec![]),
                        Err(e) => {
                            let msg = ndjson_line(serde_json::json!({"type":"error","msg":e}));
                            request.respond(Response::new(StatusCode(200),
                                vec![make_header("Content-Type","application/x-ndjson")],
                                std::io::Cursor::new(msg), None, None)).ok();
                            return;
                        }
                    }
                };

            let total        = tasks.len() + prior.len();
            let timeout_ms   = req.timeout_ms;
            let thread_count = req.thread_count;
            let mode         = req.mode;
            let state_file   = req.state_file.clone();
            let output_file  = req.output_file.clone();

            // Reset control flags for this scan
            stop_flag.store(false,  Ordering::SeqCst);
            pause_flag.store(false, Ordering::SeqCst);

            // Initialize live state for reconnect support
            {
                let mut ls = live_state.lock().unwrap();
                ls.status     = ScanStatus::Scanning;
                ls.done       = prior.len();
                ls.total      = total;
                ls.results    = prior.clone();
                ls.mode       = format!("{}", mode);
                ls.timeout_ms = timeout_ms;
                ls.threads    = thread_count;
                ls.state_file = state_file.clone();
                ls.elapsed_ms = 0;
            }

            // scan thread  →  (scan_tx / scan_rx)  →  serializer thread
            // serializer   →  (http_tx / http_rx)  →  ChannelReader → HTTP body
            let (scan_tx, scan_rx) = bounded::<ScanMsg>(65536);
            let (http_tx, http_rx) = bounded::<Option<Vec<u8>>>(65536);

            let sf = Arc::clone(&stop_flag);
            let pf = Arc::clone(&pause_flag);

            // Emit "start" event immediately so the browser shows progress UI
            http_tx.send(Some(ndjson_line(serde_json::json!({
                "type":       "start",
                "total":      total,
                "mode":       format!("{}", mode),
                "timeout_ms": timeout_ms,
                "threads":    thread_count,
            })))).ok();

            // Spawn scan worker pool
            let prior_clone = prior.clone();
            thread::spawn(move || {
                run_scan(tasks, timeout_ms, thread_count, mode,
                         scan_tx, pf, sf, state_file, prior_clone);
            });

            // Spawn serializer: drains scan channel → writes NDJSON to http channel
            let http_tx2 = http_tx.clone();
            let mut all_results: Vec<ScanResult> = prior.clone();
            let ls2 = Arc::clone(&live_state);
            thread::spawn(move || {
                loop {
                    match scan_rx.recv() {
                        Ok(ScanMsg::Result(r)) => {
                            all_results.push(r.clone());
                            if let Ok(mut ls) = ls2.lock() {
                                ls.results.push(r.clone());
                            }
                            http_tx2.send(Some(ndjson_line(serde_json::json!({
                                "type":    "result",
                                "host":    r.host,
                                "port":    r.port,
                                "proto":   r.proto,
                                "state":   r.state,
                                "service": r.service,
                            })))).ok();
                        }
                        Ok(ScanMsg::Progress { done, total }) => {
                            if let Ok(mut ls) = ls2.lock() {
                                ls.done  = done;
                                ls.total = total;
                            }
                            http_tx2.send(Some(ndjson_line(serde_json::json!({
                                "type":  "progress",
                                "done":  done,
                                "total": total,
                            })))).ok();
                        }
                        Ok(ScanMsg::Done { elapsed_secs }) => {
                            let open = all_results.iter().filter(|r| r.state == "open").count();
                            let elapsed_ms = (elapsed_secs * 1000.0) as u64;
                            if let Ok(mut ls) = ls2.lock() {
                                ls.status     = ScanStatus::Done;
                                ls.done       = ls.total;
                                ls.elapsed_ms = elapsed_ms;
                            }
                            http_tx2.send(Some(ndjson_line(serde_json::json!({
                                "type":       "done",
                                "elapsed_ms": elapsed_ms,
                                "total_open": open,
                            })))).ok();
                            if let Some(ref base) = output_file { save_outputs(&all_results, base); }
                            http_tx2.send(None).ok(); // EOF
                            break;
                        }
                        Ok(ScanMsg::Paused { state_path }) => {
                            if let Ok(mut ls) = ls2.lock() {
                                ls.status = ScanStatus::Paused;
                            }
                            http_tx2.send(Some(ndjson_line(serde_json::json!({
                                "type":       "paused",
                                "state_path": state_path,
                            })))).ok();
                            if let Some(ref base) = output_file { save_outputs(&all_results, base); }
                            http_tx2.send(None).ok(); // EOF
                            break;
                        }
                        Ok(ScanMsg::Log(msg)) => {
                            http_tx2.send(Some(ndjson_line(serde_json::json!({
                                "type": "log",
                                "msg":  msg,
                            })))).ok();
                        }
                        Err(_) => {
                            if let Ok(mut ls) = ls2.lock() {
                                // Mark as done if stopped mid-scan
                                if ls.status == ScanStatus::Scanning {
                                    ls.status = ScanStatus::Done;
                                }
                            }
                            http_tx2.send(None).ok();
                            break;
                        }
                    }
                }
            });

            // Respond with streaming NDJSON body (blocks this thread until EOF)
            request.respond(Response::new(
                StatusCode(200),
                vec![
                    make_header("Content-Type",      "application/x-ndjson"),
                    make_header("Cache-Control",     "no-cache"),
                    make_header("X-Accel-Buffering", "no"),
                    make_header("Access-Control-Allow-Origin", "*"),
                ],
                ChannelReader::new(http_rx),
                None,
                None,
            )).ok();
        }

        // ── Stop scan ─────────────────────────────────────────────────────────
        ("POST", "/api/stop") => {
            stop_flag.store(true, Ordering::SeqCst);
            request.respond(
                Response::from_string("{\"ok\":true}")
                    .with_header(make_header("Content-Type",  "application/json"))
                    .with_header(make_header("Access-Control-Allow-Origin", "*")),
            ).ok();
        }

        // ── Pause scan ────────────────────────────────────────────────────────
        ("POST", "/api/pause") => {
            pause_flag.store(true, Ordering::SeqCst);
            request.respond(
                Response::from_string("{\"ok\":true}")
                    .with_header(make_header("Content-Type",  "application/json"))
                    .with_header(make_header("Access-Control-Allow-Origin", "*")),
            ).ok();
        }

        // ── Get live scan status (for reconnect on page refresh) ─────────────
        ("GET", "/api/status") => {
            let state = live_state.lock().unwrap();
            let json = serde_json::to_string(&*state).unwrap_or_else(|_| "{}".into());
            drop(state);
            request.respond(
                Response::from_string(json)
                    .with_header(make_header("Content-Type",  "application/json"))
                    .with_header(make_header("Cache-Control", "no-store"))
                    .with_header(make_header("Access-Control-Allow-Origin", "*")),
            ).ok();
        }

        // ── 404 ──────────────────────────────────────────────────────────────
        _ => {
            request.respond(
                Response::from_string("Not Found")
                    .with_status_code(StatusCode(404)),
            ).ok();
        }
    }
}


// ─── CLI mode ──────────────────────────────────────────────────────────────────
fn run_cli(args: &[String]) {
    let mut targets   = Vec::new();
    let mut port_spec = "1-1024".to_string();
    let mut mode      = ScanMode::Tcp;
    let mut timeout   = 500u64;
    let mut threads   = 100usize;
    let mut output    = String::new();
    let mut state_file = "scan_state.json".to_string();
    let mut input_file = None::<String>;
    let mut resume    = None::<String>;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p"         => { i += 1; if i < args.len() { port_spec = args[i].clone(); } }
            "-t"         => { i += 1; if i < args.len() { threads = args[i].parse().unwrap_or(100); } }
            "-T"         => { i += 1; if i < args.len() { timeout = args[i].parse().unwrap_or(500); } }
            "-o"         => { i += 1; if i < args.len() { output = args[i].clone(); } }
            "-iL"        => { i += 1; if i < args.len() { input_file = Some(args[i].clone()); } }
            "-F"         => { port_spec = "top100".into(); }
            "--syn"      => { mode = ScanMode::Syn; }
            "--udp"      => { mode = ScanMode::Udp; }
            "--state"    => { i += 1; if i < args.len() { state_file = args[i].clone(); } }
            "--resume"   => { i += 1; if i < args.len() { resume = Some(args[i].clone()); } }
            "--gui"      => { /* handled before */ }
            "--help"|"-h"=> { print_help(); return; }
            a if !a.starts_with('-') => { targets.push(a.to_string()); }
            _ => {}
        }
        i += 1;
    }

    let (tasks, prior) = if let Some(ref rf) = resume {
        match fs::read_to_string(rf) {
            Ok(data) => match serde_json::from_str::<SavedState>(&data) {
                Ok(saved) => { println!("[▶] Resuming {} remaining tasks.", saved.remaining.len()); (saved.remaining, saved.completed) }
                Err(e) => { eprintln!("State parse error: {}", e); return; }
            },
            Err(e) => { eprintln!("Cannot read state file: {}", e); return; }
        }
    } else {
        match build_tasks(&targets, input_file.as_deref(), None, &port_spec, mode) {
            Ok(t)  => (t, vec![]),
            Err(e) => { eprintln!("[ERROR] {}", e); return; }
        }
    };

    let total = tasks.len() + prior.len();
    println!("[*] Starting {} | {} tasks | {}ms timeout | {} threads",
             mode, total, timeout, threads);

    let (tx, rx) = bounded::<ScanMsg>(65536);
    let stop_flag  = Arc::new(AtomicBool::new(false));
    let pause_flag = Arc::new(AtomicBool::new(false));
    let pf = Arc::clone(&pause_flag);
    let sf = Arc::clone(&stop_flag);

    // Ctrl+C → pause
    {
        let pf2 = Arc::clone(&pf);
        ctrlc_handler(move || { pf2.store(true, Ordering::SeqCst); });
    }

    thread::spawn(move || { run_scan(tasks, timeout, threads, mode, tx, pf, sf, state_file, prior); });

    let mut results = Vec::new();
    loop {
        match rx.recv() {
            Ok(ScanMsg::Result(r)) => {
                if r.state == "open" {
                    println!("{:<20} {:>5}/{:<4}  {}", r.host, r.port, r.proto, r.service);
                }
                results.push(r);
            }
            Ok(ScanMsg::Progress { done, total }) => {
                let pct = if total > 0 { done * 100 / total } else { 0 };
                eprint!("\r[{:>3}%] {}/{}", pct, done, total);
            }
            Ok(ScanMsg::Done { elapsed_secs }) => {
                let open = results.iter().filter(|r| r.state == "open").count();
                eprintln!("\r[✓] Scan complete in {:.1}s — {} open port(s).", elapsed_secs, open);
                if !output.is_empty() { save_outputs(&results, &output); }
                break;
            }
            Ok(ScanMsg::Paused { state_path }) => {
                eprintln!("\n[⏸] Paused — state saved to {}", state_path);
                if !output.is_empty() { save_outputs(&results, &output); }
                break;
            }
            Ok(ScanMsg::Log(_)) => {}
            Err(_) => break,
        }
    }
}

#[allow(unused_variables)]
fn ctrlc_handler(f: impl Fn() + Send + 'static) {
    // Basic SIGINT handler via a thread watching for stdin close or signal
    // For production, use the `ctrlc` crate; here we keep deps minimal.
    thread::spawn(move || {
        let _ = std::io::stdin().read(&mut [0u8]);
        f();
    });
}

fn print_help() {
    println!(r#"
PortScanner v2.1 — nmap-style port scanner with embedded web GUI

USAGE:
  portscanner --gui                   Launch web GUI (opens browser at localhost:7681)
  portscanner <target> [options]      CLI scan

TARGET:
  <ip>          Single IPv4 address or hostname
  <cidr>        CIDR range, e.g. 192.168.1.0/24
  -iL <file>    Load targets from file (one per line)

PORT OPTIONS:
  -p <spec>     Port spec: 80,443 | 1-1024 | top100 | 1-65535  (default: 1-1024)
  -F            Fast mode: scan nmap top-100 ports

SCAN MODES:
  (default)     TCP Connect (no root required)
  --syn         SYN Stealth (requires root/admin)
  --udp         UDP scan    (requires root)

TIMING:
  -T <ms>       Timeout per port in milliseconds (default: 500)
  -t <n>        Thread count (default: 100)

OUTPUT:
  -o <base>     Save results to <base>.txt and <base>.json

PAUSE / RESUME:
  Ctrl+C        Pause and save state to scan_state.json
  --resume <f>  Resume from saved state file

EXAMPLES:
  portscanner --gui
  portscanner 192.168.1.1 -p 1-1024
  portscanner 10.0.0.0/24 -p top100 -t 200
  portscanner 192.168.1.1 --syn -p 1-65535 -o results
"#);
}

// ─── Entry point ──────────────────────────────────────────────────────────────
fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args.iter().any(|a| a == "--gui") {
        run_gui();
    } else {
        run_cli(&args);
    }
}
