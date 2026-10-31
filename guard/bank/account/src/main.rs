//! A minimal std-only HTTP/1.1 server for the demo account service. Fake data only.

use account::route;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let port = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080u16);
    let log_path = std::env::var("ACCESS_LOG").unwrap_or_else(|_| "logs/access.log".to_string());
    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind");
    println!("account listening on {}", port);
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let log_path = log_path.clone();
            std::thread::spawn(move || handle(stream, &log_path));
        }
    }
}

fn handle(mut stream: TcpStream, log_path: &str) {
    let peer = stream.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();

    // read headers, keeping the forwarded client IP for the access log
    let mut forwarded = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        let lower = trimmed.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("x-forwarded-for:") {
            forwarded = value.trim().split(',').next().unwrap_or("").trim().to_string();
        }
    }

    let path = target.split('?').next().unwrap_or("/");
    let (status, content_type, body) = route(&method, path);
    let client_ip = if forwarded.is_empty() { peer } else { forwarded };
    write_log(log_path, &client_ip, &method, &target, status);

    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        reason(status),
        content_type,
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        404 => "Not Found",
        _ => "OK",
    }
}

fn write_log(path: &str, ip: &str, method: &str, target: &str, status: u16) {
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let line = format!("{} {} - \"{} {} HTTP/1.1\" {}\n", secs, ip, method, target, status);
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = file.write_all(line.as_bytes());
    }
}
