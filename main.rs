#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

// SPDX-License-Identifier: AGPL-3.0-only
// rproxy is a local proxy server for HTTP, HTTPS CONNECT, SOCKS5 TCP, and SOCKS5 UDP.
// It listens only on IPv4 and IPv6 loopback addresses by default. Do not expose it
// to the public Internet unless authentication, rate limits, and firewall rules are added.

// Standard library imports cover file logging, socket addresses, threads, channels, and time.
// Tokio imports provide asynchronous TCP, UDP, DNS lookup, timeouts, and bidirectional stream copying.
// socket2 is used where the standard library does not expose enough low-level socket configuration.
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, TcpKeepalive, Type};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;

// Port and runtime constants. These values define the local proxy ports,
// maximum connection counts, timeout values, keepalive timing, and buffer sizes.
// They are intentionally centralized so open-source users can audit or adjust them easily.
const httpProxyPort: u16 = 1080;
const httpsConnectProxyPort: u16 = 1081;
const socks5ProxyPort: u16 = 1082;
const logFilePath: &str = "rproxy.log";
const listenerBacklog: i32 = 1024;
const maxTcpConnectionsPerService: usize = 4096;
const maxHttpHeaderSize: usize = 64 * 1024;
const tcpIdleTimeoutSeconds: u64 = 300;
const udpResponseTimeoutSeconds: u64 = 20;
const tcpKeepaliveIdleSeconds: u64 = 60;
const tcpKeepaliveIntervalSeconds: u64 = 20;
const bufferSize: usize = 16 * 1024;
const udpBufferSize: usize = 65_535;

#[derive(Clone)]
// Simple cloneable logger handle. Each clone sends log lines to the same background writer.
struct Logger {
    sender: mpsc::Sender<String>,
}

impl Logger {
    // Print an information message and send it to the background log writer.
    fn info(&self, message: impl AsRef<str>) {
        self.write("INFO", message.as_ref());
    }

    // Print a warning message and send it to the background log writer.
    fn warn(&self, message: impl AsRef<str>) {
        self.write("WARN", message.as_ref());
    }

    // Print an error message and send it to the background log writer.
    fn error(&self, message: impl AsRef<str>) {
        self.write("ERROR", message.as_ref());
    }

    // The logging channel prevents network tasks from blocking on file I/O.
    fn write(&self, level: &str, message: &str) {
        let logLine = format!("{} [{}] {}", currentUnixTimestamp(), level, message);
        println!("{}", logLine);

        let sendResult = self.sender.send(logLine);

        if sendResult.is_err() {
            eprintln!("logger channel is closed");
        }
    }
}

#[derive(Clone)]
// Small HTTP header representation that keeps the original header name and value text.
struct HeaderField {
    headerName: String,
    headerValue: String,
}

// Parsed HTTP request metadata used by the HTTP proxy path.
struct HttpRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<HeaderField>,
}

// Parsed HTTP response metadata used to determine response framing and keep-alive behavior.
struct HttpResponse {
    version: String,
    statusCode: u16,
    reason: String,
    headers: Vec<HeaderField>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
// HTTP body framing mode detected from request or response headers.
enum BodyMode {
    None,
    ContentLength(u64),
    Chunked,
    UntilClose,
}

#[tokio::main(flavor = "multi_thread")]
// Program entry point. Starts all proxy listeners concurrently on the Tokio multi-thread runtime.
async fn main() -> io::Result<()> {
    let logger = createLogger(logFilePath);

    let httpIpv4Address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), httpProxyPort);
    let httpIpv6Address = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), httpProxyPort);
    let httpsIpv4Address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), httpsConnectProxyPort);
    let httpsIpv6Address = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), httpsConnectProxyPort);
    let socksIpv4Address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), socks5ProxyPort);
    let socksIpv6Address = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), socks5ProxyPort);

    logger.info("rproxy starting");
    logger.info(format!("HTTP IPv4 proxy listening on {}", httpIpv4Address));
    logger.info(format!("HTTP IPv6 proxy listening on {}", httpIpv6Address));
    logger.info(format!("HTTPS CONNECT IPv4 proxy listening on {}", httpsIpv4Address));
    logger.info(format!("HTTPS CONNECT IPv6 proxy listening on {}", httpsIpv6Address));
    logger.info(format!("SOCKS5 TCP IPv4 proxy listening on {}", socksIpv4Address));
    logger.info(format!("SOCKS5 TCP IPv6 proxy listening on {}", socksIpv6Address));
    logger.info(format!("SOCKS5 UDP IPv4 proxy listening on {}", socksIpv4Address));
    logger.info(format!("SOCKS5 UDP IPv6 proxy listening on {}", socksIpv6Address));
    logger.info(format!("log file path: {}", logFilePath));

    let serverResult = tokio::try_join!(
        runHttpProxy(httpIpv4Address, "HTTP-IPv4-1080", logger.clone()),
        runHttpProxy(httpIpv6Address, "HTTP-IPv6-1080", logger.clone()),
        runHttpProxy(httpsIpv4Address, "HTTPS-CONNECT-IPv4-1081", logger.clone()),
        runHttpProxy(httpsIpv6Address, "HTTPS-CONNECT-IPv6-1081", logger.clone()),
        runSocks5TcpProxy(socksIpv4Address, "SOCKS5-TCP-IPv4-1082", logger.clone()),
        runSocks5TcpProxy(socksIpv6Address, "SOCKS5-TCP-IPv6-1082", logger.clone()),
        runSocks5UdpProxy(socksIpv4Address, "SOCKS5-UDP-IPv4-1082", logger.clone()),
        runSocks5UdpProxy(socksIpv6Address, "SOCKS5-UDP-IPv6-1082", logger.clone())
    );

    match serverResult {
        Ok(serverCompletionValues) => {
            logger.warn(format!("server loop unexpectedly completed: {:?}", serverCompletionValues));
            Ok(())
        }
        Err(error) => {
            logger.error(format!("server failed: {}", error));
            Err(error)
        }
    }
}

// Create the logger and start a background file-writer thread for rproxy.log.
fn createLogger(filePath: &str) -> Logger {
    let channelPair = mpsc::channel::<String>();
    let sender = channelPair.0;
    let receiver = channelPair.1;
    let ownedFilePath = filePath.to_string();

    // The file writer runs on a standard thread so async network tasks do not block on disk writes.
    thread::spawn(move || {
        let fileResult = OpenOptions::new().create(true).append(true).open(&ownedFilePath);

        let mut logFile = match fileResult {
            Ok(file) => file,
            Err(error) => {
                eprintln!("failed to open log file {}: {}", ownedFilePath, error);
                return;
            }
        };

        while let Ok(line) = receiver.recv() {
            let writeResult = writeln!(logFile, "{}", line);

            if writeResult.is_err() {
                eprintln!("failed to write log line");
            }

            let flushResult = logFile.flush();

            if flushResult.is_err() {
                eprintln!("failed to flush log file");
            }
        }
    });

    Logger { sender }
}

// Return a compact Unix timestamp used as the prefix for each log line.
fn currentUnixTimestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// Create a non-blocking TCP listener with explicit IPv4 or IPv6 socket configuration.
fn createTcpListener(listenAddress: SocketAddr) -> io::Result<TcpListener> {
    let socketDomain = if listenAddress.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(socketDomain, Type::STREAM, Some(Protocol::TCP))?;

    // Reuse address makes local restart faster after the previous process exits.
    socket.set_reuse_address(true)?;

    // IPv6 listeners are kept IPv6-only because this program binds IPv4 separately.
    if listenAddress.is_ipv6() {
        socket.set_only_v6(true)?;
    }

    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(listenAddress))?;
    socket.listen(listenerBacklog)?;

    let standardListener: std::net::TcpListener = socket.into();
    standardListener.set_nonblocking(true)?;

    TcpListener::from_std(standardListener)
}

// Create a non-blocking UDP socket with explicit IPv4 or IPv6 socket configuration.
fn createUdpSocket(bindAddress: SocketAddr) -> io::Result<UdpSocket> {
    let socketDomain = if bindAddress.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(socketDomain, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;

    if bindAddress.is_ipv6() {
        socket.set_only_v6(true)?;
    }

    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(bindAddress))?;

    let standardSocket: std::net::UdpSocket = socket.into();
    standardSocket.set_nonblocking(true)?;

    UdpSocket::from_std(standardSocket)
}

// Apply TCP options used by long-lived proxy connections.
fn configureTcpStream(stream: &TcpStream) -> io::Result<()> {
    // TCP_NODELAY reduces latency for proxy tunnels that send small packets.
    stream.set_nodelay(true)?;

    // TCP keepalive helps detect broken long-lived connections.
    let socketReference = SockRef::from(stream);
    socketReference.set_keepalive(true)?;

    let keepaliveConfig = TcpKeepalive::new()
        .with_time(Duration::from_secs(tcpKeepaliveIdleSeconds))
        .with_interval(Duration::from_secs(tcpKeepaliveIntervalSeconds));

    socketReference.set_tcp_keepalive(&keepaliveConfig)?;

    Ok(())
}

// Accept HTTP or HTTPS CONNECT clients and dispatch each connection into an async task.
async fn runHttpProxy(listenAddress: SocketAddr, serviceName: &'static str, logger: Logger) -> io::Result<()> {
    let listener = match createTcpListener(listenAddress) {
        Ok(listener) => listener,
        Err(error) => {
            logger.error(format!("{} bind failed on {}: {}", serviceName, listenAddress, error));
            return Ok(());
        }
    };

    let connectionLimit = Arc::new(Semaphore::new(maxTcpConnectionsPerService));
    logger.info(format!("{} ready on {}", serviceName, listenAddress));

    loop {
        let acceptResult = listener.accept().await;
        let clientPair = match acceptResult {
            Ok(clientPair) => clientPair,
            Err(error) => {
                logger.warn(format!("{} accept failed: {}", serviceName, error));
                continue;
            }
        };

        let clientStream = clientPair.0;
        let clientAddress = clientPair.1;
        let permitResult = connectionLimit.clone().try_acquire_owned();

        let connectionPermit = match permitResult {
            Ok(connectionPermit) => connectionPermit,
            Err(error) => {
                logger.warn(format!("{} rejected {} because connection limit was reached: {}", serviceName, clientAddress, error));
                continue;
            }
        };

        let taskLogger = logger.clone();

        tokio::spawn(async move {
            taskLogger.info(format!("{} accepted {}", serviceName, clientAddress));

            let clientResult = handleHttpClient(clientStream, serviceName, taskLogger.clone()).await;

            if let Err(error) = clientResult {
                taskLogger.warn(format!("{} client {} closed with error: {}", serviceName, clientAddress, error));
            }

            drop(connectionPermit);
        });
    }
}

// Process one client-side HTTP proxy connection, including repeated keep-alive requests.
async fn handleHttpClient(mut clientStream: TcpStream, serviceName: &'static str, logger: Logger) -> io::Result<()> {
    configureTcpStream(&clientStream)?;

    let mut clientBuffer = Vec::with_capacity(bufferSize);

    loop {
        let requestHeaderOption = readHttpHeader(&mut clientStream, &mut clientBuffer).await?;

        let requestHeader = match requestHeaderOption {
            Some(requestHeader) => requestHeader,
            None => return Ok(()),
        };

        let request = parseHttpRequest(&requestHeader)?;

        // CONNECT creates a raw TCP tunnel, which is the standard way to proxy HTTPS.
        if request.method.eq_ignore_ascii_case("CONNECT") {
            logger.info(format!("{} CONNECT {}", serviceName, request.target));
            handleHttpConnectTunnel(clientStream, &request.target).await?;
            return Ok(());
        }

        let closeAfterResponse = handlePlainHttpRequest(&mut clientStream, &mut clientBuffer, request, serviceName, logger.clone()).await?;

        if closeAfterResponse {
            return Ok(());
        }
    }
}

// Handle HTTP CONNECT by creating a raw TCP tunnel to the requested authority.
async fn handleHttpConnectTunnel(mut clientStream: TcpStream, target: &str) -> io::Result<()> {
    let remoteAddress = normalizeAuthority(target, 443)?;
    let mut remoteStream = TcpStream::connect(remoteAddress.as_str()).await?;

    configureTcpStream(&remoteStream)?;

    clientStream
        .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: rproxy\r\n\r\n")
        .await?;

    // copy_bidirectional runs the tunnel in both directions until one side closes.
    let transferSizes = copy_bidirectional(&mut clientStream, &mut remoteStream).await?;
    println!("CONNECT tunnel closed, client_to_remote={}, remote_to_client={}", transferSizes.0, transferSizes.1);

    Ok(())
}

// Forward one normal HTTP request and relay the remote HTTP response back to the client.
async fn handlePlainHttpRequest(
    clientStream: &mut TcpStream,
    clientBuffer: &mut Vec<u8>,
    request: HttpRequest,
    serviceName: &'static str,
    logger: Logger,
) -> io::Result<bool> {
    let targetPair = parseHttpTarget(&request.target, &request.headers)?;
    let remoteAddress = targetPair.0;
    let originPath = targetPair.1;
    let requestBodyMode = getRequestBodyMode(&request.headers)?;
    let requestKeepAlive = shouldKeepAlive(&request.version, &request.headers);
    let forwardHeader = buildForwardRequestHeader(&request, &originPath, &remoteAddress);

    let mut remoteStream = TcpStream::connect(remoteAddress.as_str()).await?;
    configureTcpStream(&remoteStream)?;

    remoteStream.write_all(forwardHeader.as_bytes()).await?;
    forwardBodyByMode(clientStream, clientBuffer, &mut remoteStream, requestBodyMode).await?;

    let mut remoteBuffer = Vec::with_capacity(bufferSize);
    let responseHeaderOption = readHttpHeader(&mut remoteStream, &mut remoteBuffer).await?;

    let responseHeader = match responseHeaderOption {
        Some(responseHeader) => responseHeader,
        None => return Err(invalidData("remote server closed before response header")),
    };

    let response = parseHttpResponse(&responseHeader)?;
    let responseBodyMode = getResponseBodyMode(&request.method, response.statusCode, &response.headers)?;
    let responseCanKeepAlive = responseBodyMode != BodyMode::UntilClose;
    let closeAfterResponse = !requestKeepAlive || !responseCanKeepAlive;
    let clientResponseHeader = buildClientResponseHeader(&response, !closeAfterResponse);

    clientStream.write_all(clientResponseHeader.as_bytes()).await?;
    forwardBodyByMode(&mut remoteStream, &mut remoteBuffer, clientStream, responseBodyMode).await?;

    logger.info(format!(
        "{} {} {} -> {} {}",
        serviceName, request.method, request.target, response.statusCode, response.reason
    ));

    Ok(closeAfterResponse)
}

// Read bytes until the HTTP header terminator is found, while preserving extra body bytes.
async fn readHttpHeader(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    loop {
        let headerEndOption = findHttpHeaderEnd(buffer);

        if let Some(headerEndIndex) = headerEndOption {
            let header = buffer.drain(..headerEndIndex).collect::<Vec<u8>>();
            return Ok(Some(header));
        }

        if buffer.len() > maxHttpHeaderSize {
            return Err(invalidData("HTTP header is too large"));
        }

        let mut temporaryBuffer = [0u8; bufferSize];
        let readResult = timeout(Duration::from_secs(tcpIdleTimeoutSeconds), stream.read(&mut temporaryBuffer)).await;

        let bytesRead = match readResult {
            Ok(streamReadResult) => streamReadResult?,
            Err(timeError) => {
                let errorMessage = format!("HTTP connection idle timeout: {}", timeError);
                return Err(io::Error::new(io::ErrorKind::TimedOut, errorMessage));
            }
        };

        if bytesRead == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }

            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed during HTTP header"));
        }

        buffer.extend_from_slice(&temporaryBuffer[..bytesRead]);
    }
}

// Find the byte index immediately after the CRLF CRLF HTTP header terminator.
fn findHttpHeaderEnd(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|windowBytes| windowBytes == b"\r\n\r\n").map(|headerStartIndex| headerStartIndex + 4)
}

// Parse the client request line and headers into a lightweight internal request struct.
fn parseHttpRequest(headerBytes: &[u8]) -> io::Result<HttpRequest> {
    let headerText = std::str::from_utf8(headerBytes).map_err(|conversionError| {
        let errorMessage = format!("invalid HTTP request header encoding: {}", conversionError);
        invalidData(&errorMessage)
    })?;

    let mut lineIterator = headerText.split("\r\n");
    let requestLine = lineIterator.next().ok_or_else(|| invalidData("missing HTTP request line"))?;
    let mut requestPartIterator = requestLine.split_whitespace();

    let method = requestPartIterator.next().ok_or_else(|| invalidData("missing HTTP method"))?.to_string();
    let target = requestPartIterator.next().ok_or_else(|| invalidData("missing HTTP target"))?.to_string();
    let version = requestPartIterator.next().unwrap_or("HTTP/1.1").to_string();
    let headers = parseHeaderFields(lineIterator)?;

    Ok(HttpRequest { method, target, version, headers })
}

// Parse the upstream server status line and headers into a lightweight response struct.
fn parseHttpResponse(headerBytes: &[u8]) -> io::Result<HttpResponse> {
    let headerText = std::str::from_utf8(headerBytes).map_err(|conversionError| {
        let errorMessage = format!("invalid HTTP response header encoding: {}", conversionError);
        invalidData(&errorMessage)
    })?;

    let mut lineIterator = headerText.split("\r\n");
    let statusLine = lineIterator.next().ok_or_else(|| invalidData("missing HTTP status line"))?;
    let mut statusPartIterator = statusLine.splitn(3, ' ');

    let version = statusPartIterator.next().unwrap_or("HTTP/1.1").to_string();
    let statusCodeText = statusPartIterator.next().ok_or_else(|| invalidData("missing HTTP status code"))?;
    let statusCode = statusCodeText.parse::<u16>().map_err(|parseError| {
        let errorMessage = format!("invalid HTTP status code: {}", parseError);
        invalidData(&errorMessage)
    })?;
    let reason = statusPartIterator.next().unwrap_or("").to_string();
    let headers = parseHeaderFields(lineIterator)?;

    Ok(HttpResponse { version, statusCode, reason, headers })
}

fn parseHeaderFields<'a>(lineIterator: impl Iterator<Item = &'a str>) -> io::Result<Vec<HeaderField>> {
    let mut headers = Vec::new();

    for lineText in lineIterator {
        if lineText.is_empty() {
            break;
        }

        let splitOption = lineText.split_once(':');

        let headerPair = match splitOption {
            Some(headerPair) => headerPair,
            None => return Err(invalidData("invalid HTTP header line")),
        };

        headers.push(HeaderField {
            headerName: headerPair.0.trim().to_string(),
            headerValue: headerPair.1.trim().to_string(),
        });
    }

    Ok(headers)
}

// Convert an HTTP proxy target into an upstream address and origin-form request path.
fn parseHttpTarget(target: &str, headers: &[HeaderField]) -> io::Result<(String, String)> {
    if let Some(restText) = target.strip_prefix("http://") {
        let splitIndex = restText.find(['/', '?']).unwrap_or(restText.len());
        let authority = &restText[..splitIndex];

        let originPath = if splitIndex >= restText.len() {
            "/".to_string()
        } else if restText.as_bytes()[splitIndex] == b'?' {
            format!("/{}", &restText[splitIndex..])
        } else {
            restText[splitIndex..].to_string()
        };

        return Ok((normalizeAuthority(authority, 80)?, originPath));
    }

    if target.starts_with('/') {
        let host = headerValue(headers, "host").ok_or_else(|| invalidData("missing Host header"))?;
        return Ok((normalizeAuthority(&host, 80)?, target.to_string()));
    }

    Err(invalidData("unsupported HTTP target"))
}

// Normalize host, IPv4, IPv6, and optional port into a connectable host:port string.
fn normalizeAuthority(authority: &str, defaultPort: u16) -> io::Result<String> {
    let trimmedAuthority = authority.trim();

    if trimmedAuthority.is_empty() {
        return Err(invalidData("empty authority"));
    }

    let authorityWithoutUserInfo = if let Some(authorityPair) = trimmedAuthority.rsplit_once('@') {
        authorityPair.1
    } else {
        trimmedAuthority
    };

    if authorityWithoutUserInfo.starts_with('[') {
        if authorityWithoutUserInfo.contains("]:") {
            return Ok(authorityWithoutUserInfo.to_string());
        }

        return Ok(format!("{}:{}", authorityWithoutUserInfo, defaultPort));
    }

    let colonCount = authorityWithoutUserInfo.matches(':').count();

    if colonCount == 0 {
        return Ok(format!("{}:{}", authorityWithoutUserInfo, defaultPort));
    }

    if colonCount == 1 {
        if let Some(authorityPair) = authorityWithoutUserInfo.rsplit_once(':') {
            let portText = authorityPair.1;

            if portText.chars().all(|character| character.is_ascii_digit()) {
                return Ok(authorityWithoutUserInfo.to_string());
            }
        }
    }

    Ok(format!("[{}]:{}", authorityWithoutUserInfo, defaultPort))
}

// Build the upstream HTTP request header and remove hop-by-hop proxy headers.
fn buildForwardRequestHeader(request: &HttpRequest, originPath: &str, remoteAddress: &str) -> String {
    let mut output = String::new();
    let mut hasHostHeader = false;

    output.push_str(&request.method);
    output.push(' ');
    output.push_str(originPath);
    output.push(' ');
    output.push_str(&request.version);
    output.push_str("\r\n");

    for headerField in &request.headers {
        if isRemovedRequestHeader(&headerField.headerName) {
            continue;
        }

        if headerField.headerName.eq_ignore_ascii_case("host") {
            hasHostHeader = true;
        }

        output.push_str(&headerField.headerName);
        output.push_str(": ");
        output.push_str(&headerField.headerValue);
        output.push_str("\r\n");
    }

    if !hasHostHeader {
        output.push_str("Host: ");
        output.push_str(remoteAddress);
        output.push_str("\r\n");
    }

    // The upstream side is intentionally closed per request for simpler and safer message framing.
    output.push_str("Connection: close\r\n");
    output.push_str("\r\n");

    output
}

// Build the response header sent back to the client and set the connection policy.
fn buildClientResponseHeader(response: &HttpResponse, keepAlive: bool) -> String {
    let mut output = String::new();

    output.push_str(&response.version);
    output.push(' ');
    output.push_str(&response.statusCode.to_string());

    if !response.reason.is_empty() {
        output.push(' ');
        output.push_str(&response.reason);
    }

    output.push_str("\r\n");

    for headerField in &response.headers {
        if isRemovedResponseHeader(&headerField.headerName) {
            continue;
        }

        output.push_str(&headerField.headerName);
        output.push_str(": ");
        output.push_str(&headerField.headerValue);
        output.push_str("\r\n");
    }

    if keepAlive {
        output.push_str("Connection: keep-alive\r\n");
    } else {
        output.push_str("Connection: close\r\n");
    }

    output.push_str("\r\n");

    output
}

// Return true for hop-by-hop request headers that should not be forwarded upstream.
fn isRemovedRequestHeader(headerName: &str) -> bool {
    let lowerName = headerName.to_ascii_lowercase();

    matches!(
        lowerName.as_str(),
        "connection" | "proxy-connection" | "proxy-authorization" | "keep-alive" | "upgrade"
    )
}

// Return true for hop-by-hop response headers that should not be forwarded to the client.
fn isRemovedResponseHeader(headerName: &str) -> bool {
    let lowerName = headerName.to_ascii_lowercase();

    matches!(
        lowerName.as_str(),
        "connection" | "proxy-connection" | "proxy-authenticate" | "keep-alive" | "upgrade"
    )
}

// Return the first matching HTTP header value using case-insensitive header-name matching.
fn headerValue(headers: &[HeaderField], targetName: &str) -> Option<String> {
    for headerField in headers {
        if headerField.headerName.eq_ignore_ascii_case(targetName) {
            return Some(headerField.headerValue.clone());
        }
    }

    None
}

// Check whether a comma-separated HTTP header contains a specific token.
fn headerContainsToken(headers: &[HeaderField], targetName: &str, targetToken: &str) -> bool {
    for headerField in headers {
        if !headerField.headerName.eq_ignore_ascii_case(targetName) {
            continue;
        }

        for tokenText in headerField.headerValue.split(',') {
            if tokenText.trim().eq_ignore_ascii_case(targetToken) {
                return true;
            }
        }
    }

    false
}

// Decide whether the client-side HTTP connection may remain open for another request.
fn shouldKeepAlive(version: &str, headers: &[HeaderField]) -> bool {
    if headerContainsToken(headers, "connection", "close") {
        return false;
    }

    if version.eq_ignore_ascii_case("HTTP/1.0") {
        return headerContainsToken(headers, "connection", "keep-alive");
    }

    true
}

// Determine how the HTTP request body is framed.
fn getRequestBodyMode(headers: &[HeaderField]) -> io::Result<BodyMode> {
    if headerContainsToken(headers, "transfer-encoding", "chunked") {
        return Ok(BodyMode::Chunked);
    }

    if let Some(contentLength) = parseContentLength(headers)? {
        return Ok(BodyMode::ContentLength(contentLength));
    }

    Ok(BodyMode::None)
}

// Determine how the HTTP response body is framed for this request/response pair.
fn getResponseBodyMode(method: &str, statusCode: u16, headers: &[HeaderField]) -> io::Result<BodyMode> {
    if method.eq_ignore_ascii_case("HEAD") {
        return Ok(BodyMode::None);
    }

    if (100..200).contains(&statusCode) || statusCode == 204 || statusCode == 304 {
        return Ok(BodyMode::None);
    }

    if headerContainsToken(headers, "transfer-encoding", "chunked") {
        return Ok(BodyMode::Chunked);
    }

    if let Some(contentLength) = parseContentLength(headers)? {
        return Ok(BodyMode::ContentLength(contentLength));
    }

    Ok(BodyMode::UntilClose)
}

// Parse and validate Content-Length, rejecting conflicting duplicate values.
fn parseContentLength(headers: &[HeaderField]) -> io::Result<Option<u64>> {
    let mut contentLengthValues = Vec::new();

    for headerField in headers {
        if headerField.headerName.eq_ignore_ascii_case("content-length") {
            for valueText in headerField.headerValue.split(',') {
                let trimmedValue = valueText.trim();

                if trimmedValue.is_empty() {
                    return Err(invalidData("empty Content-Length value"));
                }

                contentLengthValues.push(trimmedValue.to_string());
            }
        }
    }

    if contentLengthValues.is_empty() {
        return Ok(None);
    }

    let firstValue = &contentLengthValues[0];

    for valueText in &contentLengthValues {
        if valueText != firstValue {
            return Err(invalidData("conflicting Content-Length values"));
        }
    }

    let parsedLength = firstValue.parse::<u64>().map_err(|parseError| {
        let errorMessage = format!("invalid Content-Length value: {}", parseError);
        invalidData(&errorMessage)
    })?;

    Ok(Some(parsedLength))
}

// Dispatch HTTP body forwarding according to the detected framing mode.
async fn forwardBodyByMode(
    reader: &mut TcpStream,
    readerBuffer: &mut Vec<u8>,
    writer: &mut TcpStream,
    bodyMode: BodyMode,
) -> io::Result<()> {
    match bodyMode {
        BodyMode::None => Ok(()),
        BodyMode::ContentLength(contentLength) => forwardExactBytes(reader, readerBuffer, writer, contentLength).await,
        BodyMode::Chunked => forwardChunkedBody(reader, readerBuffer, writer).await,
        BodyMode::UntilClose => forwardUntilClose(reader, readerBuffer, writer).await,
    }
}

// Forward exactly the requested number of body bytes and preserve any surplus bytes already read.
async fn forwardExactBytes(
    reader: &mut TcpStream,
    readerBuffer: &mut Vec<u8>,
    writer: &mut TcpStream,
    mut remainingBytes: u64,
) -> io::Result<()> {
    while remainingBytes > 0 {
        if !readerBuffer.is_empty() {
            let takeSize = std::cmp::min(remainingBytes as usize, readerBuffer.len());
            writer.write_all(&readerBuffer[..takeSize]).await?;
            readerBuffer.drain(..takeSize);
            remainingBytes -= takeSize as u64;
            continue;
        }

        let mut temporaryBuffer = [0u8; bufferSize];
        let readResult = timeout(Duration::from_secs(tcpIdleTimeoutSeconds), reader.read(&mut temporaryBuffer)).await;

        let bytesRead = match readResult {
            Ok(streamReadResult) => streamReadResult?,
            Err(timeError) => {
                let errorMessage = format!("body forwarding timeout: {}", timeError);
                return Err(io::Error::new(io::ErrorKind::TimedOut, errorMessage));
            }
        };

        if bytesRead == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed during body forwarding"));
        }

        let takeSize = std::cmp::min(remainingBytes as usize, bytesRead);
        writer.write_all(&temporaryBuffer[..takeSize]).await?;

        if takeSize < bytesRead {
            readerBuffer.extend_from_slice(&temporaryBuffer[takeSize..bytesRead]);
        }

        remainingBytes -= takeSize as u64;
    }

    Ok(())
}

// Forward a chunked transfer body while preserving chunk framing and trailers.
async fn forwardChunkedBody(reader: &mut TcpStream, readerBuffer: &mut Vec<u8>, writer: &mut TcpStream) -> io::Result<()> {
    loop {
        let chunkLine = readCrLfLine(reader, readerBuffer).await?;
        writer.write_all(&chunkLine).await?;

        let lineText = std::str::from_utf8(&chunkLine).map_err(|conversionError| {
            let errorMessage = format!("invalid chunk size line: {}", conversionError);
            invalidData(&errorMessage)
        })?;

        let cleanLine = lineText.trim_end_matches("\r\n");
        let sizeText = cleanLine.split(';').next().unwrap_or("").trim();
        let chunkSize = u64::from_str_radix(sizeText, 16).map_err(|parseError| {
            let errorMessage = format!("invalid chunk size: {}", parseError);
            invalidData(&errorMessage)
        })?;

        if chunkSize == 0 {
            loop {
                let trailerLine = readCrLfLine(reader, readerBuffer).await?;
                writer.write_all(&trailerLine).await?;

                if trailerLine == b"\r\n" {
                    return Ok(());
                }
            }
        }

        forwardExactBytes(reader, readerBuffer, writer, chunkSize + 2).await?;
    }
}

// Read one CRLF-terminated line from a TCP stream and its pending buffer.
async fn readCrLfLine(reader: &mut TcpStream, readerBuffer: &mut Vec<u8>) -> io::Result<Vec<u8>> {
    loop {
        if let Some(lineEndIndex) = findCrLf(readerBuffer) {
            let line = readerBuffer.drain(..lineEndIndex).collect::<Vec<u8>>();
            return Ok(line);
        }

        if readerBuffer.len() > maxHttpHeaderSize {
            return Err(invalidData("HTTP line is too large"));
        }

        let mut temporaryBuffer = [0u8; bufferSize];
        let readResult = timeout(Duration::from_secs(tcpIdleTimeoutSeconds), reader.read(&mut temporaryBuffer)).await;

        let bytesRead = match readResult {
            Ok(streamReadResult) => streamReadResult?,
            Err(timeError) => {
                let errorMessage = format!("line read timeout: {}", timeError);
                return Err(io::Error::new(io::ErrorKind::TimedOut, errorMessage));
            }
        };

        if bytesRead == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed during line read"));
        }

        readerBuffer.extend_from_slice(&temporaryBuffer[..bytesRead]);
    }
}

// Find the byte index immediately after a CRLF line terminator.
fn findCrLf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|windowBytes| windowBytes == b"\r\n").map(|lineStartIndex| lineStartIndex + 2)
}

// Forward bytes until the reader closes, used when the body has no explicit boundary.
async fn forwardUntilClose(reader: &mut TcpStream, readerBuffer: &mut Vec<u8>, writer: &mut TcpStream) -> io::Result<()> {
    if !readerBuffer.is_empty() {
        writer.write_all(readerBuffer).await?;
        readerBuffer.clear();
    }

    let mut temporaryBuffer = [0u8; bufferSize];

    loop {
        let readResult = timeout(Duration::from_secs(tcpIdleTimeoutSeconds), reader.read(&mut temporaryBuffer)).await;

        let bytesRead = match readResult {
            Ok(streamReadResult) => streamReadResult?,
            Err(timeError) => {
                let errorMessage = format!("stream forwarding timeout: {}", timeError);
                return Err(io::Error::new(io::ErrorKind::TimedOut, errorMessage));
            }
        };

        if bytesRead == 0 {
            return Ok(());
        }

        writer.write_all(&temporaryBuffer[..bytesRead]).await?;
    }
}

// Accept SOCKS5 TCP control connections and dispatch each client into an async task.
async fn runSocks5TcpProxy(listenAddress: SocketAddr, serviceName: &'static str, logger: Logger) -> io::Result<()> {
    let listener = match createTcpListener(listenAddress) {
        Ok(listener) => listener,
        Err(error) => {
            logger.error(format!("{} bind failed on {}: {}", serviceName, listenAddress, error));
            return Ok(());
        }
    };

    let connectionLimit = Arc::new(Semaphore::new(maxTcpConnectionsPerService));
    logger.info(format!("{} ready on {}", serviceName, listenAddress));

    loop {
        let acceptResult = listener.accept().await;
        let clientPair = match acceptResult {
            Ok(clientPair) => clientPair,
            Err(error) => {
                logger.warn(format!("{} accept failed: {}", serviceName, error));
                continue;
            }
        };

        let clientStream = clientPair.0;
        let clientAddress = clientPair.1;
        let permitResult = connectionLimit.clone().try_acquire_owned();

        let connectionPermit = match permitResult {
            Ok(connectionPermit) => connectionPermit,
            Err(error) => {
                logger.warn(format!("{} rejected {} because connection limit was reached: {}", serviceName, clientAddress, error));
                continue;
            }
        };

        let taskLogger = logger.clone();

        tokio::spawn(async move {
            taskLogger.info(format!("{} accepted {}", serviceName, clientAddress));

            let clientResult = handleSocks5TcpClient(clientStream, taskLogger.clone()).await;

            if let Err(error) = clientResult {
                taskLogger.warn(format!("{} client {} error: {}", serviceName, clientAddress, error));
            }

            drop(connectionPermit);
        });
    }
}

// Perform the SOCKS5 greeting, parse the command, and route CONNECT or UDP ASSOCIATE.
async fn handleSocks5TcpClient(mut clientStream: TcpStream, logger: Logger) -> io::Result<()> {
    configureTcpStream(&clientStream)?;

    let mut greetingHeader = [0u8; 2];
    clientStream.read_exact(&mut greetingHeader).await?;

    if greetingHeader[0] != 0x05 {
        return Err(invalidData("unsupported SOCKS version"));
    }

    let methodCount = greetingHeader[1] as usize;
    let mut methodBuffer = vec![0u8; methodCount];

    clientStream.read_exact(&mut methodBuffer).await?;

    // This minimal server supports SOCKS5 without authentication.
    if !methodBuffer.contains(&0x00) {
        clientStream.write_all(&[0x05, 0xff]).await?;
        return Err(invalidData("SOCKS5 no-auth method is not supported by client"));
    }

    clientStream.write_all(&[0x05, 0x00]).await?;

    let mut requestHeader = [0u8; 4];
    clientStream.read_exact(&mut requestHeader).await?;

    if requestHeader[0] != 0x05 || requestHeader[2] != 0x00 {
        return Err(invalidData("invalid SOCKS5 request header"));
    }

    let command = requestHeader[1];
    let addressType = requestHeader[3];
    let targetPair = readSocks5TargetAddress(&mut clientStream, addressType).await?;
    let targetHost = targetPair.0;
    let targetPort = targetPair.1;

    match command {
        0x01 => handleSocks5Connect(clientStream, targetHost, targetPort, logger).await,
        0x03 => handleSocks5UdpAssociate(clientStream, logger).await,
        commandValue => {
            sendSocks5Reply(&mut clientStream, 0x07, unspecifiedSocketAddress()).await?;
            Err(invalidData(&format!("unsupported SOCKS5 command {}", commandValue)))
        }
    }
}

// Handle the SOCKS5 CONNECT command by opening a TCP tunnel to the target.
async fn handleSocks5Connect(mut clientStream: TcpStream, targetHost: String, targetPort: u16, logger: Logger) -> io::Result<()> {
    let targetAddress = formatHostAndPort(&targetHost, targetPort);
    logger.info(format!("SOCKS5 CONNECT {}", targetAddress));

    match TcpStream::connect(targetAddress.as_str()).await {
        Ok(mut remoteStream) => {
            configureTcpStream(&remoteStream)?;

            let boundAddress = remoteStream.local_addr().unwrap_or_else(|addressError| {
                logger.warn(format!("failed to read remote local address: {}", addressError));
                unspecifiedSocketAddress()
            });

            sendSocks5Reply(&mut clientStream, 0x00, boundAddress).await?;

            let transferSizes = copy_bidirectional(&mut clientStream, &mut remoteStream).await?;
            logger.info(format!(
                "SOCKS5 tunnel closed, client_to_remote={}, remote_to_client={}",
                transferSizes.0, transferSizes.1
            ));

            Ok(())
        }
        Err(error) => {
            sendSocks5Reply(&mut clientStream, 0x05, unspecifiedSocketAddress()).await?;
            Err(io::Error::new(error.kind(), format!("SOCKS5 connect {} failed: {}", targetAddress, error)))
        }
    }
}

// Reply to SOCKS5 UDP ASSOCIATE and keep the TCP control connection alive.
async fn handleSocks5UdpAssociate(mut clientStream: TcpStream, logger: Logger) -> io::Result<()> {
    let clientLocalAddress = clientStream.local_addr().unwrap_or_else(|addressError| {
        logger.warn(format!("failed to read client local address: {}", addressError));
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), socks5ProxyPort)
    });

    let udpBindAddress = if clientLocalAddress.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), socks5ProxyPort)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), socks5ProxyPort)
    };

    sendSocks5Reply(&mut clientStream, 0x00, udpBindAddress).await?;
    logger.info(format!("SOCKS5 UDP ASSOCIATE relay {}", udpBindAddress));

    // SOCKS5 keeps the UDP association alive while this TCP control connection is alive.
    let mut drainBuffer = [0u8; bufferSize];

    loop {
        let bytesRead = clientStream.read(&mut drainBuffer).await?;

        if bytesRead == 0 {
            return Ok(());
        }
    }
}

// Read a SOCKS5 address field supporting IPv4, domain names, and IPv6.
async fn readSocks5TargetAddress(clientStream: &mut TcpStream, addressType: u8) -> io::Result<(String, u16)> {
    match addressType {
        0x01 => {
            let mut addressBytes = [0u8; 4];
            clientStream.read_exact(&mut addressBytes).await?;

            let port = readSocks5Port(clientStream).await?;
            let host = Ipv4Addr::from(addressBytes).to_string();

            Ok((host, port))
        }
        0x03 => {
            let mut lengthBuffer = [0u8; 1];
            clientStream.read_exact(&mut lengthBuffer).await?;

            let domainLength = lengthBuffer[0] as usize;

            if domainLength == 0 {
                return Err(invalidData("empty SOCKS5 domain"));
            }

            let mut domainBuffer = vec![0u8; domainLength];
            clientStream.read_exact(&mut domainBuffer).await?;

            let port = readSocks5Port(clientStream).await?;
            let domain = String::from_utf8(domainBuffer).map_err(|conversionError| {
                let errorMessage = format!("invalid SOCKS5 domain: {}", conversionError);
                invalidData(&errorMessage)
            })?;

            Ok((domain, port))
        }
        0x04 => {
            let mut addressBytes = [0u8; 16];
            clientStream.read_exact(&mut addressBytes).await?;

            let port = readSocks5Port(clientStream).await?;
            let host = Ipv6Addr::from(addressBytes).to_string();

            Ok((host, port))
        }
        addressTypeValue => Err(invalidData(&format!("unsupported SOCKS5 address type {}", addressTypeValue))),
    }
}

// Read the two-byte big-endian SOCKS5 destination port.
async fn readSocks5Port(clientStream: &mut TcpStream) -> io::Result<u16> {
    let mut portBytes = [0u8; 2];
    clientStream.read_exact(&mut portBytes).await?;
    Ok(u16::from_be_bytes(portBytes))
}

// Send a SOCKS5 reply packet to the client.
async fn sendSocks5Reply(clientStream: &mut TcpStream, replyCode: u8, boundAddress: SocketAddr) -> io::Result<()> {
    let replyPacket = buildSocks5ReplyPacket(replyCode, boundAddress);
    clientStream.write_all(&replyPacket).await
}

// Build a SOCKS5 reply packet with IPv4 or IPv6 bound address encoding.
fn buildSocks5ReplyPacket(replyCode: u8, boundAddress: SocketAddr) -> Vec<u8> {
    let mut packet = Vec::with_capacity(22);

    packet.push(0x05);
    packet.push(replyCode);
    packet.push(0x00);

    match boundAddress.ip() {
        IpAddr::V4(ipv4Address) => {
            packet.push(0x01);
            packet.extend_from_slice(&ipv4Address.octets());
        }
        IpAddr::V6(ipv6Address) => {
            packet.push(0x04);
            packet.extend_from_slice(&ipv6Address.octets());
        }
    }

    packet.extend_from_slice(&boundAddress.port().to_be_bytes());

    packet
}

// Receive SOCKS5 UDP relay packets and dispatch each datagram into an async task.
async fn runSocks5UdpProxy(listenAddress: SocketAddr, serviceName: &'static str, logger: Logger) -> io::Result<()> {
    let udpSocket = match createUdpSocket(listenAddress) {
        Ok(udpSocket) => udpSocket,
        Err(error) => {
            logger.error(format!("{} bind failed on {}: {}", serviceName, listenAddress, error));
            return Ok(());
        }
    };

    let sharedSocket = Arc::new(udpSocket);
    let mut packetBuffer = vec![0u8; udpBufferSize];

    logger.info(format!("{} ready on {}", serviceName, listenAddress));

    loop {
        let receiveResult = sharedSocket.recv_from(&mut packetBuffer).await;

        let receivePair = match receiveResult {
            Ok(receivePair) => receivePair,
            Err(error) => {
                logger.warn(format!("{} UDP receive failed: {}", serviceName, error));
                continue;
            }
        };

        let packetSize = receivePair.0;
        let clientAddress = receivePair.1;
        let packet = packetBuffer[..packetSize].to_vec();
        let socketClone = sharedSocket.clone();
        let taskLogger = logger.clone();

        tokio::spawn(async move {
            let packetResult = handleSocks5UdpPacket(socketClone, clientAddress, packet, taskLogger.clone()).await;

            if let Err(error) = packetResult {
                taskLogger.warn(format!("SOCKS5 UDP client {} error: {}", clientAddress, error));
            }
        });
    }
}

// Parse one SOCKS5 UDP packet, forward its payload, and wrap the UDP response.
async fn handleSocks5UdpPacket(
    serverSocket: Arc<UdpSocket>,
    clientAddress: SocketAddr,
    packet: Vec<u8>,
    logger: Logger,
) -> io::Result<()> {
    if packet.len() < 4 {
        return Ok(());
    }

    // SOCKS5 UDP request starts with RSV RSV FRAG. This server rejects fragmented UDP packets.
    if packet[0] != 0x00 || packet[1] != 0x00 || packet[2] != 0x00 {
        return Ok(());
    }

    let targetInfo = parseSocks5UdpTarget(&packet)?;
    let targetHost = targetInfo.0;
    let targetPort = targetInfo.1;
    let payloadStartIndex = targetInfo.2;

    if payloadStartIndex >= packet.len() {
        return Ok(());
    }

    let targetAddress = resolveFirstSocketAddress(&targetHost, targetPort).await?;
    let relayBindAddress = if targetAddress.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };

    let relaySocket = UdpSocket::bind(relayBindAddress).await?;
    relaySocket.send_to(&packet[payloadStartIndex..], targetAddress).await?;

    logger.info(format!("SOCKS5 UDP {} -> {}", clientAddress, targetAddress));

    let mut responseBuffer = vec![0u8; udpBufferSize];
    let receiveResult = timeout(Duration::from_secs(udpResponseTimeoutSeconds), relaySocket.recv_from(&mut responseBuffer)).await;

    let responsePair = match receiveResult {
        Ok(socketResult) => socketResult?,
        Err(timeoutError) => {
            logger.warn(format!("SOCKS5 UDP response timeout from {}: {}", targetAddress, timeoutError));
            return Ok(());
        }
    };

    let responseSize = responsePair.0;
    let remoteAddress = responsePair.1;
    let mut responsePacket = Vec::with_capacity(responseSize + 22);

    appendSocks5UdpHeader(&mut responsePacket, remoteAddress);
    responsePacket.extend_from_slice(&responseBuffer[..responseSize]);

    serverSocket.send_to(&responsePacket, clientAddress).await?;

    Ok(())
}

// Resolve a host and port and return the first available socket address.
async fn resolveFirstSocketAddress(host: &str, port: u16) -> io::Result<SocketAddr> {
    let targetAddressText = formatHostAndPort(host, port);
    let mut addressIterator = lookup_host(targetAddressText.as_str()).await?;

    match addressIterator.next() {
        Some(socketAddress) => Ok(socketAddress),
        None => Err(invalidData("DNS resolution returned no address")),
    }
}

// Parse the SOCKS5 UDP request header and return the target plus payload offset.
fn parseSocks5UdpTarget(packet: &[u8]) -> io::Result<(String, u16, usize)> {
    let addressType = packet[3];
    let mut offset = 4usize;

    let host = match addressType {
        0x01 => {
            if packet.len() < offset + 4 + 2 {
                return Err(invalidData("invalid IPv4 UDP packet"));
            }

            let address = Ipv4Addr::new(packet[offset], packet[offset + 1], packet[offset + 2], packet[offset + 3]);
            offset += 4;
            address.to_string()
        }
        0x03 => {
            if packet.len() < offset + 1 {
                return Err(invalidData("invalid domain UDP packet"));
            }

            let domainLength = packet[offset] as usize;
            offset += 1;

            if domainLength == 0 || packet.len() < offset + domainLength + 2 {
                return Err(invalidData("invalid domain length in UDP packet"));
            }

            let domainBytes = &packet[offset..offset + domainLength];
            offset += domainLength;

            String::from_utf8(domainBytes.to_vec()).map_err(|conversionError| {
                let errorMessage = format!("invalid UDP domain: {}", conversionError);
                invalidData(&errorMessage)
            })?
        }
        0x04 => {
            if packet.len() < offset + 16 + 2 {
                return Err(invalidData("invalid IPv6 UDP packet"));
            }

            let mut addressBytes = [0u8; 16];
            addressBytes.copy_from_slice(&packet[offset..offset + 16]);
            offset += 16;

            Ipv6Addr::from(addressBytes).to_string()
        }
        addressTypeValue => return Err(invalidData(&format!("unsupported SOCKS5 UDP address type {}", addressTypeValue))),
    };

    if packet.len() < offset + 2 {
        return Err(invalidData("missing UDP target port"));
    }

    let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    offset += 2;

    Ok((host, port, offset))
}

// Append the SOCKS5 UDP response header before sending data back to the client.
fn appendSocks5UdpHeader(packet: &mut Vec<u8>, remoteAddress: SocketAddr) {
    packet.push(0x00);
    packet.push(0x00);
    packet.push(0x00);

    match remoteAddress.ip() {
        IpAddr::V4(ipv4Address) => {
            packet.push(0x01);
            packet.extend_from_slice(&ipv4Address.octets());
        }
        IpAddr::V6(ipv6Address) => {
            packet.push(0x04);
            packet.extend_from_slice(&ipv6Address.octets());
        }
    }

    packet.extend_from_slice(&remoteAddress.port().to_be_bytes());
}

// Format IPv4, domain, or IPv6 host text together with a port.
fn formatHostAndPort(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

// Return a neutral placeholder address used in failure replies.
fn unspecifiedSocketAddress() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

// Create a consistent InvalidData I/O error for protocol parsing failures.
fn invalidData(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}
