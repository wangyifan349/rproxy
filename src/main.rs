#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

// SPDX-License-Identifier: AGPL-3.0-only
// rproxy is a local proxy server for HTTP, HTTPS CONNECT, SOCKS5 TCP, and SOCKS5 UDP.
// It listens only on IPv4 and IPv6 loopback addresses by default. Do not expose it
// to the public Internet unless authentication, rate limits, and firewall rules are added.

// Imports are intentionally small and explicit.
// The program avoids a large framework and uses only Tokio, socket2, and the Rust standard library.
// socket2 exposes low-level socket options that Tokio's high-level bind helpers do not configure directly.
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, TcpKeepalive, Type};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
// copy_bidirectional is the core tunnel primitive used by HTTPS CONNECT and SOCKS5 CONNECT.
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
// Tokio networking types provide non-blocking TCP, UDP, and DNS resolution.
use tokio::net::{lookup_host, TcpListener, TcpStream, UdpSocket};
// Semaphore limits concurrent TCP clients per listener.
use tokio::sync::Semaphore;
// timeout prevents stalled clients or upstream servers from holding resources forever.
use tokio::time::timeout;

// Central proxy configuration.
// Changing these constants changes ports, timeouts, connection limits, and buffer sizes.
// Port for plain HTTP proxy requests.
const httpProxyPort: u16 = 1080;
// Port for HTTPS CONNECT tunnel requests.
const httpsConnectProxyPort: u16 = 1081;
// Shared SOCKS5 port for TCP control connections and UDP relay packets.
const socks5ProxyPort: u16 = 1082;
// Runtime log file written by the background logger thread.
const logFilePath: &str = "rproxy.log";
// TCP listen backlog passed to the operating system.
const listenerBacklog: i32 = 1024;
// Per-listener connection cap to prevent unlimited task creation.
const maxTcpConnectionsPerService: usize = 4096;
// Upper bound for one HTTP header block, protecting memory usage.
const maxHttpHeaderSize: usize = 64 * 1024;
// Idle timeout for TCP reads used by HTTP parsing and forwarding.
const tcpIdleTimeoutSeconds: u64 = 300;
// Maximum wait time for one UDP response before dropping that UDP relay attempt.
const udpResponseTimeoutSeconds: u64 = 20;
// Time before TCP keepalive probes begin on an idle TCP connection.
const tcpKeepaliveIdleSeconds: u64 = 60;
// Interval between TCP keepalive probes.
const tcpKeepaliveIntervalSeconds: u64 = 20;
// General TCP read buffer size.
const bufferSize: usize = 16 * 1024;
// Maximum UDP datagram buffer size.
const udpBufferSize: usize = 65_535;

#[derive(Clone)]
// Cloneable logging handle shared by all async tasks.
// Only the sending side is stored here; the receiving side lives inside the background file-writer thread.
struct Logger {
// Sending side of the log channel. Cloning Logger clones this sender.
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
// Minimal HTTP header representation.
// The proxy keeps header names and values as strings because it only needs lightweight parsing and forwarding.
struct HeaderField {
// Header name, such as Host or Content-Length.
    headerName: String,
// Header value text after the colon, trimmed by parseHeaderFields.
    headerValue: String,
}

// Parsed HTTP request metadata.
// The raw body is deliberately not stored here; body bytes are streamed directly between sockets.
struct HttpRequest {
// HTTP method, for example GET, POST, HEAD, or CONNECT.
    method: String,
// HTTP request target. Proxy requests may use absolute-form targets.
    target: String,
// HTTP version string, usually HTTP/1.0 or HTTP/1.1.
    version: String,
// Parsed HTTP headers in original order.
    headers: Vec<HeaderField>,
}

// Parsed HTTP response metadata.
// The proxy uses statusCode and headers to decide how to forward the response body.
struct HttpResponse {
// HTTP version string, usually HTTP/1.0 or HTTP/1.1.
    version: String,
// Numeric HTTP response status code.
    statusCode: u16,
// Optional HTTP reason phrase after the status code.
    reason: String,
// Parsed HTTP headers in original order.
    headers: Vec<HeaderField>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
// HTTP message-body framing strategy.
// Correct body framing is necessary for keep-alive because the proxy must know where one message ends.
enum BodyMode {
// No message body should be forwarded.
    None,
// Body length is known exactly from Content-Length.
    ContentLength(u64),
// Body uses HTTP chunked transfer coding.
    Chunked,
// Body ends only when the upstream connection closes.
    UntilClose,
}

#[tokio::main(flavor = "multi_thread")]
// Program entry point.
// Tokio starts a multi-thread runtime, then this function starts every listener concurrently.
// Each listener is an endless loop; if any listener returns an error, tokio::try_join! returns and the program logs that failure.
async fn main() -> io::Result<()> {
    println!("rproxy function:");
    println!("  Local HTTP proxy forwarding");
    println!("  Local HTTPS CONNECT tunnel forwarding");
    println!("  Local SOCKS5 TCP proxy forwarding");
    println!("  Local SOCKS5 UDP relay forwarding");
    println!();
    println!("Sponsor addresses:");
    println!("Bitcoin (BTC):");
    println!("bc1qxqfhumpqtnxrznkx9r4xsp8m6zsedtgusjns7p");
    println!();
    println!("Ethereum (ETH):");
    println!("0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b");
    println!();
    println!("USDT (ERC-20):");
    println!("0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b");
    println!();
    println!("Solana (SOL):");
    println!("B7N4e3KG9zWQBwMrtydS1B9wVBp2w62fAdryZdxAMBiz");
    println!();
// Start logging before any listener is created so startup and bind errors are captured.
    let logger = createLogger(logFilePath);

// Bind HTTP proxy on IPv4 loopback.
    let httpIpv4Address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), httpProxyPort);
// Bind HTTP proxy on IPv6 loopback.
    let httpIpv6Address = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), httpProxyPort);
// Bind HTTPS CONNECT proxy on IPv4 loopback.
    let httpsIpv4Address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), httpsConnectProxyPort);
// Bind HTTPS CONNECT proxy on IPv6 loopback.
    let httpsIpv6Address = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), httpsConnectProxyPort);
// Bind SOCKS5 TCP and UDP services on IPv4 loopback.
    let socksIpv4Address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), socks5ProxyPort);
// Bind SOCKS5 TCP and UDP services on IPv6 loopback.
    let socksIpv6Address = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), socks5ProxyPort);

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

// Run all listeners concurrently. In normal operation these futures never finish.
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

// Create a lightweight logger handle.
// Every network task can clone Logger and send log lines through an mpsc channel.
// The background thread owns the file handle, so async tasks do not block on disk I/O.
fn createLogger(filePath: &str) -> Logger {
// The channel decouples logging calls from file writes.
    let channelPair = mpsc::channel::<String>();
    let sender = channelPair.0;
    let receiver = channelPair.1;
// Move an owned path string into the logger thread.
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

// Return the current Unix timestamp in seconds.
// This keeps log lines compact and avoids pulling in an external time-formatting dependency.
fn currentUnixTimestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// Create a Tokio TcpListener from a socket2 socket.
// socket2 is used because it exposes socket options before bind/listen.
// The function supports both IPv4 and IPv6; IPv6 sockets are made IPv6-only because IPv4 is bound separately.
fn createTcpListener(listenAddress: SocketAddr) -> io::Result<TcpListener> {
// Choose the socket address family from the requested bind address.
    let socketDomain = if listenAddress.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
// Create a TCP socket before binding so options can be set first.
    let socket = Socket::new(socketDomain, Type::STREAM, Some(Protocol::TCP))?;

    // Reuse address makes local restart faster after the previous process exits.
    socket.set_reuse_address(true)?;

    // IPv6 listeners are kept IPv6-only because this program binds IPv4 separately.
    if listenAddress.is_ipv6() {
        socket.set_only_v6(true)?;
    }

// Tokio requires sockets passed into from_std to be non-blocking.
    socket.set_nonblocking(true)?;
// Bind the TCP socket to its local listen address.
    socket.bind(&SockAddr::from(listenAddress))?;
// Start accepting TCP connections with the configured backlog.
    socket.listen(listenerBacklog)?;

// Convert socket2's socket into the standard library listener type before handing it to Tokio.
    let standardListener: std::net::TcpListener = socket.into();
    standardListener.set_nonblocking(true)?;

    TcpListener::from_std(standardListener)
}

// Create a Tokio UdpSocket from a socket2 UDP socket.
// SOCKS5 UDP relay needs UDP sockets for both IPv4 and IPv6 listeners.
fn createUdpSocket(bindAddress: SocketAddr) -> io::Result<UdpSocket> {
    let socketDomain = if bindAddress.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
// Create a UDP socket before binding so options can be set first.
    let socket = Socket::new(socketDomain, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;

    if bindAddress.is_ipv6() {
        socket.set_only_v6(true)?;
    }

// Tokio requires sockets passed into from_std to be non-blocking.
    socket.set_nonblocking(true)?;
// Bind the UDP socket to its relay address.
    socket.bind(&SockAddr::from(bindAddress))?;

// Convert socket2's socket into the standard library UDP type before handing it to Tokio.
    let standardSocket: std::net::UdpSocket = socket.into();
    standardSocket.set_nonblocking(true)?;

    UdpSocket::from_std(standardSocket)
}

// Configure accepted or outbound TCP streams.
// TCP_NODELAY reduces latency for small packets, and TCP keepalive helps detect dead long-lived tunnels.
fn configureTcpStream(stream: &TcpStream) -> io::Result<()> {
    // TCP_NODELAY reduces latency for proxy tunnels that send small packets.
    stream.set_nodelay(true)?;

    // TCP keepalive helps detect broken long-lived connections.
// SockRef lets socket2 configure an already-created Tokio TCP stream.
    let socketReference = SockRef::from(stream);
// Enable operating-system TCP keepalive on this stream.
    socketReference.set_keepalive(true)?;

// Configure keepalive timing values.
    let keepaliveConfig = TcpKeepalive::new()
        .with_time(Duration::from_secs(tcpKeepaliveIdleSeconds))
        .with_interval(Duration::from_secs(tcpKeepaliveIntervalSeconds));

    socketReference.set_tcp_keepalive(&keepaliveConfig)?;

    Ok(())
}

// Run one HTTP-style listener.
// This function is reused for the normal HTTP proxy port and the HTTPS CONNECT proxy port.
// Each accepted connection gets a permit and then runs in its own Tokio task.
async fn runHttpProxy(listenAddress: SocketAddr, serviceName: &'static str, logger: Logger) -> io::Result<()> {
// Create the listener and treat bind failure as a logged service-level failure.
    let listener = match createTcpListener(listenAddress) {
        Ok(listener) => listener,
        Err(error) => {
            logger.error(format!("{} bind failed on {}: {}", serviceName, listenAddress, error));
            return Ok(());
        }
    };

// Each service has its own connection limit.
    let connectionLimit = Arc::new(Semaphore::new(maxTcpConnectionsPerService));
    logger.info(format!("{} ready on {}", serviceName, listenAddress));

    loop {
// Wait for one incoming TCP client.
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
// Try to reserve capacity before spawning a task for the new client.
        let permitResult = connectionLimit.clone().try_acquire_owned();

        let connectionPermit = match permitResult {
            Ok(connectionPermit) => connectionPermit,
            Err(error) => {
                logger.warn(format!("{} rejected {} because connection limit was reached: {}", serviceName, clientAddress, error));
                continue;
            }
        };

        let taskLogger = logger.clone();

// Move this connection into its own asynchronous task.
        tokio::spawn(async move {
            taskLogger.info(format!("{} accepted {}", serviceName, clientAddress));

            let clientResult = handleHttpClient(clientStream, serviceName, taskLogger.clone()).await;

            if let Err(error) = clientResult {
                taskLogger.warn(format!("{} client {} closed with error: {}", serviceName, clientAddress, error));
            }

// Explicitly release the connection permit when the task finishes.
            drop(connectionPermit);
        });
    }
}

// Handle one client TCP connection speaking HTTP proxy syntax.
// A keep-alive HTTP client can send more than one request on the same TCP connection, so this function loops.
async fn handleHttpClient(mut clientStream: TcpStream, serviceName: &'static str, logger: Logger) -> io::Result<()> {
// Apply TCP options immediately after accepting the client stream.
    configureTcpStream(&clientStream)?;

// This buffer stores bytes already read from the client but not yet forwarded.
    let mut clientBuffer = Vec::with_capacity(bufferSize);

    loop {
// Read one complete HTTP request header from the client connection.
        let requestHeaderOption = readHttpHeader(&mut clientStream, &mut clientBuffer).await?;

        let requestHeader = match requestHeaderOption {
            Some(requestHeader) => requestHeader,
            None => return Ok(()),
        };

// Parse the request header so the proxy can decide CONNECT versus normal HTTP forwarding.
        let request = parseHttpRequest(&requestHeader)?;

        // CONNECT creates a raw TCP tunnel, which is the standard way to proxy HTTPS.
        if request.method.eq_ignore_ascii_case("CONNECT") {
            logger.info(format!("{} CONNECT {}", serviceName, request.target));
// CONNECT consumes the TCP connection permanently as a tunnel, so this function returns afterward.
            handleHttpConnectTunnel(clientStream, &request.target).await?;
            return Ok(());
        }

// Forward exactly one normal HTTP request/response pair.
        let closeAfterResponse = handlePlainHttpRequest(&mut clientStream, &mut clientBuffer, request, serviceName, logger.clone()).await?;

        if closeAfterResponse {
            return Ok(());
        }
    }
}

// Handle an HTTP CONNECT request.
// The proxy connects to the requested host:port, returns 200, and then blindly relays bytes.
// This is why HTTPS remains end-to-end encrypted: rproxy never decrypts TLS.
async fn handleHttpConnectTunnel(mut clientStream: TcpStream, target: &str) -> io::Result<()> {
// CONNECT targets normally omit a scheme and use host:port authority form; default port is 443.
    let remoteAddress = normalizeAuthority(target, 443)?;
// Open the upstream TCP connection.
    let mut remoteStream = TcpStream::connect(remoteAddress.as_str()).await?;

    configureTcpStream(&remoteStream)?;

    clientStream
// Tell the client that the tunnel is ready; bytes after this belong to the tunneled protocol.
        .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: rproxy\r\n\r\n")
        .await?;

    // copy_bidirectional runs the tunnel in both directions until one side closes.
    let transferSizes = copy_bidirectional(&mut clientStream, &mut remoteStream).await?;
    println!("CONNECT tunnel closed, client_to_remote={}, remote_to_client={}", transferSizes.0, transferSizes.1);

    Ok(())
}

// Handle one non-CONNECT HTTP proxy request.
// The proxy parses the target, rewrites the request line into origin-form, forwards the body, reads the response, and returns it to the client.
async fn handlePlainHttpRequest(
    clientStream: &mut TcpStream,
    clientBuffer: &mut Vec<u8>,
    request: HttpRequest,
    serviceName: &'static str,
    logger: Logger,
) -> io::Result<bool> {
// Find the upstream server and the path that should appear in the forwarded request line.
    let targetPair = parseHttpTarget(&request.target, &request.headers)?;
    let remoteAddress = targetPair.0;
    let originPath = targetPair.1;
// Detect whether the client request has no body, fixed-length body, or chunked body.
    let requestBodyMode = getRequestBodyMode(&request.headers)?;
// Remember client keep-alive preference before rewriting hop-by-hop headers.
    let requestKeepAlive = shouldKeepAlive(&request.version, &request.headers);
// Build the upstream request header in origin-form.
    let forwardHeader = buildForwardRequestHeader(&request, &originPath, &remoteAddress);

// Open the upstream TCP connection.
    let mut remoteStream = TcpStream::connect(remoteAddress.as_str()).await?;
    configureTcpStream(&remoteStream)?;

// Send the rewritten request header upstream.
    remoteStream.write_all(forwardHeader.as_bytes()).await?;
// Forward the request body, if any, without reading beyond this request.
    forwardBodyByMode(clientStream, clientBuffer, &mut remoteStream, requestBodyMode).await?;

    let mut remoteBuffer = Vec::with_capacity(bufferSize);
// Read the upstream response header.
    let responseHeaderOption = readHttpHeader(&mut remoteStream, &mut remoteBuffer).await?;

    let responseHeader = match responseHeaderOption {
        Some(responseHeader) => responseHeader,
        None => return Err(invalidData("remote server closed before response header")),
    };

// Parse response metadata to determine body framing and keep-alive safety.
    let response = parseHttpResponse(&responseHeader)?;
// Detect how the response body should be forwarded.
    let responseBodyMode = getResponseBodyMode(&request.method, response.statusCode, &response.headers)?;
// If the response is close-delimited, the proxy cannot safely keep the client connection open afterward.
    let responseCanKeepAlive = responseBodyMode != BodyMode::UntilClose;
// Client connection remains open only when both client preference and response framing allow it.
    let closeAfterResponse = !requestKeepAlive || !responseCanKeepAlive;
// Build the response header with an explicit client-side Connection policy.
    let clientResponseHeader = buildClientResponseHeader(&response, !closeAfterResponse);

// Send the response header to the client.
    clientStream.write_all(clientResponseHeader.as_bytes()).await?;
// Stream the upstream response body back to the client.
    forwardBodyByMode(&mut remoteStream, &mut remoteBuffer, clientStream, responseBodyMode).await?;

    logger.info(format!(
        "{} {} {} -> {} {}",
        serviceName, request.method, request.target, response.statusCode, response.reason
    ));

    Ok(closeAfterResponse)
}

// Read bytes until a complete HTTP header is available.
// If the socket delivers extra body bytes after the header, they remain in buffer and are consumed by the body-forwarding functions.
async fn readHttpHeader(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    loop {
        let headerEndOption = findHttpHeaderEnd(buffer);

// A complete header is available in the buffer.
        if let Some(headerEndIndex) = headerEndOption {
// Remove only the header bytes and leave any already-read body bytes in the buffer.
            let header = buffer.drain(..headerEndIndex).collect::<Vec<u8>>();
            return Ok(Some(header));
        }

// Reject oversized headers to avoid unbounded memory growth.
        if buffer.len() > maxHttpHeaderSize {
            return Err(invalidData("HTTP header is too large"));
        }

        let mut temporaryBuffer = [0u8; bufferSize];
// Apply an idle timeout around the socket read.
        let readResult = timeout(Duration::from_secs(tcpIdleTimeoutSeconds), stream.read(&mut temporaryBuffer)).await;

        let bytesRead = match readResult {
            Ok(streamReadResult) => streamReadResult?,
            Err(timeError) => {
                let errorMessage = format!("HTTP connection idle timeout: {}", timeError);
                return Err(io::Error::new(io::ErrorKind::TimedOut, errorMessage));
            }
        };

// A zero-byte read means the peer closed its side of the TCP stream.
        if bytesRead == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }

            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed during HTTP header"));
        }

// Append newly-read bytes and loop until the header terminator appears.
        buffer.extend_from_slice(&temporaryBuffer[..bytesRead]);
    }
}

// Find the HTTP/1.x header terminator.
// The returned index points just after CRLF CRLF.
fn findHttpHeaderEnd(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|windowBytes| windowBytes == b"\r\n\r\n").map(|headerStartIndex| headerStartIndex + 4)
}

// Parse the request line and headers from a raw HTTP request header.
// The body is not parsed here; only request metadata is extracted.
fn parseHttpRequest(headerBytes: &[u8]) -> io::Result<HttpRequest> {
// HTTP headers must be valid UTF-8 for this lightweight parser.
    let headerText = std::str::from_utf8(headerBytes).map_err(|conversionError| {
        let errorMessage = format!("invalid HTTP request header encoding: {}", conversionError);
        invalidData(&errorMessage)
    })?;

    let mut lineIterator = headerText.split("\r\n");
// The first HTTP request line contains method, target, and version.
    let requestLine = lineIterator.next().ok_or_else(|| invalidData("missing HTTP request line"))?;
    let mut requestPartIterator = requestLine.split_whitespace();

    let method = requestPartIterator.next().ok_or_else(|| invalidData("missing HTTP method"))?.to_string();
    let target = requestPartIterator.next().ok_or_else(|| invalidData("missing HTTP target"))?.to_string();
    let version = requestPartIterator.next().unwrap_or("HTTP/1.1").to_string();
    let headers = parseHeaderFields(lineIterator)?;

    Ok(HttpRequest { method, target, version, headers })
}

// Parse the status line and headers from a raw HTTP response header.
// The status code is needed because responses such as 204 and 304 must not have a body.
fn parseHttpResponse(headerBytes: &[u8]) -> io::Result<HttpResponse> {
// HTTP headers must be valid UTF-8 for this lightweight parser.
    let headerText = std::str::from_utf8(headerBytes).map_err(|conversionError| {
        let errorMessage = format!("invalid HTTP response header encoding: {}", conversionError);
        invalidData(&errorMessage)
    })?;

    let mut lineIterator = headerText.split("\r\n");
// The first HTTP response line contains version, status code, and optional reason phrase.
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

// HTTP header fields are split at the first colon.
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

// Convert the client's proxy target into an upstream address and origin path.
// Absolute-form targets such as http://host/path are converted to host:port plus /path.
// Origin-form targets such as /path require a Host header.
fn parseHttpTarget(target: &str, headers: &[HeaderField]) -> io::Result<(String, String)> {
// Absolute-form HTTP proxy requests include scheme and authority in the request target.
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

// Origin-form requests rely on Host to identify the upstream server.
    if target.starts_with('/') {
        let host = headerValue(headers, "host").ok_or_else(|| invalidData("missing Host header"))?;
        return Ok((normalizeAuthority(&host, 80)?, target.to_string()));
    }

    Err(invalidData("unsupported HTTP target"))
}

// Normalize a host authority into a connectable host:port string.
// IPv6 literals are wrapped in brackets when needed; missing ports are filled with the protocol default.
fn normalizeAuthority(authority: &str, defaultPort: u16) -> io::Result<String> {
    let trimmedAuthority = authority.trim();

    if trimmedAuthority.is_empty() {
        return Err(invalidData("empty authority"));
    }

// Discard optional userinfo from authority; the TCP destination is only host and port.
    let authorityWithoutUserInfo = if let Some(authorityPair) = trimmedAuthority.rsplit_once('@') {
        authorityPair.1
    } else {
        trimmedAuthority
    };

// Bracketed authority indicates an IPv6 literal.
    if authorityWithoutUserInfo.starts_with('[') {
        if authorityWithoutUserInfo.contains("]:") {
            return Ok(authorityWithoutUserInfo.to_string());
        }

        return Ok(format!("{}:{}", authorityWithoutUserInfo, defaultPort));
    }

// Colon count distinguishes host:port, bare IPv6, and plain hostnames.
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

// Build the HTTP request header sent to the upstream server.
// Hop-by-hop proxy headers are removed because they describe only the client-proxy connection.
// The upstream connection is forced to close after one response to simplify message boundary handling.
fn buildForwardRequestHeader(request: &HttpRequest, originPath: &str, remoteAddress: &str) -> String {
    let mut output = String::new();
    let mut hasHostHeader = false;

// Start the upstream request line with the original HTTP method.
    output.push_str(&request.method);
    output.push(' ');
    output.push_str(originPath);
    output.push(' ');
    output.push_str(&request.version);
    output.push_str("\r\n");

    for headerField in &request.headers {
// Skip client-proxy hop-by-hop headers.
        if isRemovedRequestHeader(&headerField.headerName) {
            continue;
        }

// Track whether the original request already supplied Host.
        if headerField.headerName.eq_ignore_ascii_case("host") {
            hasHostHeader = true;
        }

        output.push_str(&headerField.headerName);
        output.push_str(": ");
        output.push_str(&headerField.headerValue);
        output.push_str("\r\n");
    }

// HTTP/1.1 requires Host; add one if the client omitted it.
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

// Build the HTTP response header sent back to the client.
// Hop-by-hop upstream headers are removed, then rproxy writes its own Connection policy.
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
// Skip upstream hop-by-hop headers before sending the response to the client.
        if isRemovedResponseHeader(&headerField.headerName) {
            continue;
        }

        output.push_str(&headerField.headerName);
        output.push_str(": ");
        output.push_str(&headerField.headerValue);
        output.push_str("\r\n");
    }

// Write an explicit client-side connection policy.
    if keepAlive {
        output.push_str("Connection: keep-alive\r\n");
    } else {
        output.push_str("Connection: close\r\n");
    }

    output.push_str("\r\n");

    output
}

// Check whether a request header is hop-by-hop or proxy-specific.
// Such headers must not be forwarded to the upstream target.
fn isRemovedRequestHeader(headerName: &str) -> bool {
    let lowerName = headerName.to_ascii_lowercase();

    matches!(
        lowerName.as_str(),
        "connection" | "proxy-connection" | "proxy-authorization" | "keep-alive" | "upgrade"
    )
}

// Check whether a response header is hop-by-hop or proxy-specific.
// Such headers must not be forwarded back to the client unchanged.
fn isRemovedResponseHeader(headerName: &str) -> bool {
    let lowerName = headerName.to_ascii_lowercase();

    matches!(
        lowerName.as_str(),
        "connection" | "proxy-connection" | "proxy-authenticate" | "keep-alive" | "upgrade"
    )
}

// Return the first matching header value.
// Header names are compared case-insensitively as required by HTTP.
fn headerValue(headers: &[HeaderField], targetName: &str) -> Option<String> {
    for headerField in headers {
        if headerField.headerName.eq_ignore_ascii_case(targetName) {
            return Some(headerField.headerValue.clone());
        }
    }

    None
}

// Check for a token inside a comma-separated HTTP header.
// Used for Connection and Transfer-Encoding style headers.
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

// Decide client-side HTTP keep-alive behavior.
// HTTP/1.1 defaults to keep-alive unless Connection: close appears; HTTP/1.0 requires explicit keep-alive.
fn shouldKeepAlive(version: &str, headers: &[HeaderField]) -> bool {
// Connection: close always disables client-side keep-alive.
    if headerContainsToken(headers, "connection", "close") {
        return false;
    }

// HTTP/1.0 uses keep-alive only when explicitly requested.
    if version.eq_ignore_ascii_case("HTTP/1.0") {
        return headerContainsToken(headers, "connection", "keep-alive");
    }

    true
}

// Determine request-body framing.
// The proxy must know exactly how many bytes belong to this request before it can safely read another request on the same client connection.
fn getRequestBodyMode(headers: &[HeaderField]) -> io::Result<BodyMode> {
// Chunked transfer coding has priority over Content-Length for this parser.
    if headerContainsToken(headers, "transfer-encoding", "chunked") {
        return Ok(BodyMode::Chunked);
    }

    if let Some(contentLength) = parseContentLength(headers)? {
        return Ok(BodyMode::ContentLength(contentLength));
    }

    Ok(BodyMode::None)
}

// Determine response-body framing.
// Some responses never have bodies, some use Content-Length, some use chunked encoding, and some end only when the server closes the connection.
fn getResponseBodyMode(method: &str, statusCode: u16, headers: &[HeaderField]) -> io::Result<BodyMode> {
// HEAD responses have headers only and no response body.
    if method.eq_ignore_ascii_case("HEAD") {
        return Ok(BodyMode::None);
    }

// Informational, 204, and 304 responses do not carry response bodies.
    if (100..200).contains(&statusCode) || statusCode == 204 || statusCode == 304 {
        return Ok(BodyMode::None);
    }

// Chunked transfer coding has priority over Content-Length for this parser.
    if headerContainsToken(headers, "transfer-encoding", "chunked") {
        return Ok(BodyMode::Chunked);
    }

    if let Some(contentLength) = parseContentLength(headers)? {
        return Ok(BodyMode::ContentLength(contentLength));
    }

    Ok(BodyMode::UntilClose)
}

// Parse Content-Length safely.
// Multiple Content-Length values are accepted only when they all contain the same number.
fn parseContentLength(headers: &[HeaderField]) -> io::Result<Option<u64>> {
    let mut contentLengthValues = Vec::new();

    for headerField in headers {
        if headerField.headerName.eq_ignore_ascii_case("content-length") {
// Handle comma-separated duplicate Content-Length values.
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
// Conflicting Content-Length values are unsafe, so reject the message.
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

// Forward an HTTP body according to its framing mode.
// This dispatcher keeps the protocol decision separate from the byte-copying implementations.
async fn forwardBodyByMode(
    reader: &mut TcpStream,
    readerBuffer: &mut Vec<u8>,
    writer: &mut TcpStream,
    bodyMode: BodyMode,
) -> io::Result<()> {
// Choose the correct forwarding strategy for the message body.
    match bodyMode {
        BodyMode::None => Ok(()),
        BodyMode::ContentLength(contentLength) => forwardExactBytes(reader, readerBuffer, writer, contentLength).await,
        BodyMode::Chunked => forwardChunkedBody(reader, readerBuffer, writer).await,
        BodyMode::UntilClose => forwardUntilClose(reader, readerBuffer, writer).await,
    }
}

// Forward exactly a known number of bytes.
// Buffered bytes are consumed before reading the socket so that already-received body bytes are not lost.
async fn forwardExactBytes(
    reader: &mut TcpStream,
    readerBuffer: &mut Vec<u8>,
    writer: &mut TcpStream,
    mut remainingBytes: u64,
) -> io::Result<()> {
// Continue until the exact declared body length has been forwarded.
    while remainingBytes > 0 {
// Use already-buffered bytes before reading more from the socket.
        if !readerBuffer.is_empty() {
// Do not forward more buffered bytes than this body owns.
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

// A zero-byte read means the peer closed its side of the TCP stream.
        if bytesRead == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed during body forwarding"));
        }

// If a socket read contains bytes beyond this body, keep the surplus in readerBuffer.
        let takeSize = std::cmp::min(remainingBytes as usize, bytesRead);
        writer.write_all(&temporaryBuffer[..takeSize]).await?;

// Preserve extra bytes for the next HTTP parsing step.
        if takeSize < bytesRead {
            readerBuffer.extend_from_slice(&temporaryBuffer[takeSize..bytesRead]);
        }

        remainingBytes -= takeSize as u64;
    }

    Ok(())
}

// Forward a chunked body while preserving its chunk framing.
// The function copies size lines, chunk data plus trailing CRLF, the zero-size chunk, and trailers.
async fn forwardChunkedBody(reader: &mut TcpStream, readerBuffer: &mut Vec<u8>, writer: &mut TcpStream) -> io::Result<()> {
    loop {
// Read the chunk-size line.
        let chunkLine = readCrLfLine(reader, readerBuffer).await?;
        writer.write_all(&chunkLine).await?;

        let lineText = std::str::from_utf8(&chunkLine).map_err(|conversionError| {
            let errorMessage = format!("invalid chunk size line: {}", conversionError);
            invalidData(&errorMessage)
        })?;

        let cleanLine = lineText.trim_end_matches("\r\n");
// Ignore chunk extensions when parsing the hexadecimal size.
        let sizeText = cleanLine.split(';').next().unwrap_or("").trim();
        let chunkSize = u64::from_str_radix(sizeText, 16).map_err(|parseError| {
            let errorMessage = format!("invalid chunk size: {}", parseError);
            invalidData(&errorMessage)
        })?;

// A zero-size chunk terminates the chunked body and is followed by optional trailers.
        if chunkSize == 0 {
            loop {
                let trailerLine = readCrLfLine(reader, readerBuffer).await?;
                writer.write_all(&trailerLine).await?;

                if trailerLine == b"\r\n" {
                    return Ok(());
                }
            }
        }

// Forward chunk data plus its trailing CRLF.
        forwardExactBytes(reader, readerBuffer, writer, chunkSize + 2).await?;
    }
}

// Read one CRLF-terminated line.
// This is used by chunked transfer coding, where size lines and trailer lines are CRLF-delimited.
async fn readCrLfLine(reader: &mut TcpStream, readerBuffer: &mut Vec<u8>) -> io::Result<Vec<u8>> {
    loop {
// A complete CRLF-terminated line is already buffered.
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

// A zero-byte read means the peer closed its side of the TCP stream.
        if bytesRead == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed during line read"));
        }

        readerBuffer.extend_from_slice(&temporaryBuffer[..bytesRead]);
    }
}

// Find the end of a CRLF-terminated line and return the index after the terminator.
fn findCrLf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|windowBytes| windowBytes == b"\r\n").map(|lineStartIndex| lineStartIndex + 2)
}

// Forward bytes until the reader reaches EOF.
// This is used for close-delimited HTTP responses where no Content-Length or chunked encoding is present.
async fn forwardUntilClose(reader: &mut TcpStream, readerBuffer: &mut Vec<u8>, writer: &mut TcpStream) -> io::Result<()> {
// Use already-buffered bytes before reading more from the socket.
    if !readerBuffer.is_empty() {
// Flush pending bytes before entering the read loop.
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

// A zero-byte read means the peer closed its side of the TCP stream.
        if bytesRead == 0 {
            return Ok(());
        }

        writer.write_all(&temporaryBuffer[..bytesRead]).await?;
    }
}

// Run one SOCKS5 TCP listener.
// The TCP listener handles SOCKS5 greeting, CONNECT, and UDP ASSOCIATE control connections.
async fn runSocks5TcpProxy(listenAddress: SocketAddr, serviceName: &'static str, logger: Logger) -> io::Result<()> {
// Create the listener and treat bind failure as a logged service-level failure.
    let listener = match createTcpListener(listenAddress) {
        Ok(listener) => listener,
        Err(error) => {
            logger.error(format!("{} bind failed on {}: {}", serviceName, listenAddress, error));
            return Ok(());
        }
    };

// Each service has its own connection limit.
    let connectionLimit = Arc::new(Semaphore::new(maxTcpConnectionsPerService));
    logger.info(format!("{} ready on {}", serviceName, listenAddress));

    loop {
// Wait for one incoming TCP client.
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
// Try to reserve capacity before spawning a task for the new client.
        let permitResult = connectionLimit.clone().try_acquire_owned();

        let connectionPermit = match permitResult {
            Ok(connectionPermit) => connectionPermit,
            Err(error) => {
                logger.warn(format!("{} rejected {} because connection limit was reached: {}", serviceName, clientAddress, error));
                continue;
            }
        };

        let taskLogger = logger.clone();

// Move this connection into its own asynchronous task.
        tokio::spawn(async move {
            taskLogger.info(format!("{} accepted {}", serviceName, clientAddress));

            let clientResult = handleSocks5TcpClient(clientStream, taskLogger.clone()).await;

            if let Err(error) = clientResult {
                taskLogger.warn(format!("{} client {} error: {}", serviceName, clientAddress, error));
            }

// Explicitly release the connection permit when the task finishes.
            drop(connectionPermit);
        });
    }
}

// Handle the SOCKS5 control protocol for one TCP client.
// The implementation supports no-auth mode, TCP CONNECT, and UDP ASSOCIATE.
async fn handleSocks5TcpClient(mut clientStream: TcpStream, logger: Logger) -> io::Result<()> {
// Apply TCP options immediately after accepting the client stream.
    configureTcpStream(&clientStream)?;

// SOCKS5 greeting starts with version and number of supported methods.
    let mut greetingHeader = [0u8; 2];
    clientStream.read_exact(&mut greetingHeader).await?;

// Only SOCKS version 5 is supported.
    if greetingHeader[0] != 0x05 {
        return Err(invalidData("unsupported SOCKS version"));
    }

// The client tells the proxy how many authentication methods follow.
    let methodCount = greetingHeader[1] as usize;
    let mut methodBuffer = vec![0u8; methodCount];

// Read the list of authentication methods exactly.
    clientStream.read_exact(&mut methodBuffer).await?;

    // This minimal server supports SOCKS5 without authentication.
    if !methodBuffer.contains(&0x00) {
        clientStream.write_all(&[0x05, 0xff]).await?;
        return Err(invalidData("SOCKS5 no-auth method is not supported by client"));
    }

// Select SOCKS5 no-authentication-required method.
    clientStream.write_all(&[0x05, 0x00]).await?;

// SOCKS5 request header contains VER, CMD, RSV, and ATYP.
    let mut requestHeader = [0u8; 4];
    clientStream.read_exact(&mut requestHeader).await?;

// Validate SOCKS version and reserved byte.
    if requestHeader[0] != 0x05 || requestHeader[2] != 0x00 {
        return Err(invalidData("invalid SOCKS5 request header"));
    }

// SOCKS5 command: 0x01 CONNECT, 0x03 UDP ASSOCIATE.
    let command = requestHeader[1];
// SOCKS5 address type controls how the destination address is encoded.
    let addressType = requestHeader[3];
    let targetPair = readSocks5TargetAddress(&mut clientStream, addressType).await?;
    let targetHost = targetPair.0;
    let targetPort = targetPair.1;

// Route the SOCKS5 command to the corresponding handler.
    match command {
        0x01 => handleSocks5Connect(clientStream, targetHost, targetPort, logger).await,
        0x03 => handleSocks5UdpAssociate(clientStream, logger).await,
        commandValue => {
            sendSocks5Reply(&mut clientStream, 0x07, unspecifiedSocketAddress()).await?;
            Err(invalidData(&format!("unsupported SOCKS5 command {}", commandValue)))
        }
    }
}

// Handle SOCKS5 CONNECT.
// After a successful SOCKS5 reply, rproxy relays TCP traffic bidirectionally between client and target.
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

// Send a success reply before starting the TCP relay.
            sendSocks5Reply(&mut clientStream, 0x00, boundAddress).await?;

            let transferSizes = copy_bidirectional(&mut clientStream, &mut remoteStream).await?;
            logger.info(format!(
                "SOCKS5 tunnel closed, client_to_remote={}, remote_to_client={}",
                transferSizes.0, transferSizes.1
            ));

            Ok(())
        }
        Err(error) => {
// Send a generic SOCKS5 failure reply when the upstream connection fails.
            sendSocks5Reply(&mut clientStream, 0x05, unspecifiedSocketAddress()).await?;
            Err(io::Error::new(error.kind(), format!("SOCKS5 connect {} failed: {}", targetAddress, error)))
        }
    }
}

// Handle SOCKS5 UDP ASSOCIATE.
// The UDP relay remains valid while this TCP control connection stays alive.
async fn handleSocks5UdpAssociate(mut clientStream: TcpStream, logger: Logger) -> io::Result<()> {
// Use the local address of the TCP control connection to choose an IPv4 or IPv6 UDP relay address.
    let clientLocalAddress = clientStream.local_addr().unwrap_or_else(|addressError| {
        logger.warn(format!("failed to read client local address: {}", addressError));
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), socks5ProxyPort)
    });

    let udpBindAddress = if clientLocalAddress.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), socks5ProxyPort)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), socks5ProxyPort)
    };

// Tell the client where to send SOCKS5 UDP relay packets.
    sendSocks5Reply(&mut clientStream, 0x00, udpBindAddress).await?;
    logger.info(format!("SOCKS5 UDP ASSOCIATE relay {}", udpBindAddress));

    // SOCKS5 keeps the UDP association alive while this TCP control connection is alive.
// The control connection is drained only to detect when the client closes it.
    let mut drainBuffer = [0u8; bufferSize];

    loop {
        let bytesRead = clientStream.read(&mut drainBuffer).await?;

// A zero-byte read means the peer closed its side of the TCP stream.
        if bytesRead == 0 {
            return Ok(());
        }
    }
}

// Read the target address from a SOCKS5 request.
// SOCKS5 address type 0x01 is IPv4, 0x03 is domain name, and 0x04 is IPv6.
async fn readSocks5TargetAddress(clientStream: &mut TcpStream, addressType: u8) -> io::Result<(String, u16)> {
    match addressType {
// SOCKS5 address type 0x01: IPv4 address.
        0x01 => {
            let mut addressBytes = [0u8; 4];
            clientStream.read_exact(&mut addressBytes).await?;

            let port = readSocks5Port(clientStream).await?;
            let host = Ipv4Addr::from(addressBytes).to_string();

            Ok((host, port))
        }
// SOCKS5 address type 0x03: domain name.
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
// SOCKS5 address type 0x04: IPv6 address.
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

// Read the SOCKS5 target port.
// SOCKS5 encodes ports as two bytes in network byte order.
async fn readSocks5Port(clientStream: &mut TcpStream) -> io::Result<u16> {
// Ports are encoded as two bytes in network byte order.
    let mut portBytes = [0u8; 2];
    clientStream.read_exact(&mut portBytes).await?;
    Ok(u16::from_be_bytes(portBytes))
}

// Send a SOCKS5 reply packet to the client.
// The reply contains a status code and the proxy bound address.
async fn sendSocks5Reply(clientStream: &mut TcpStream, replyCode: u8, boundAddress: SocketAddr) -> io::Result<()> {
    let replyPacket = buildSocks5ReplyPacket(replyCode, boundAddress);
    clientStream.write_all(&replyPacket).await
}

// Build a SOCKS5 reply packet.
// Packet layout: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT.
fn buildSocks5ReplyPacket(replyCode: u8, boundAddress: SocketAddr) -> Vec<u8> {
    let mut packet = Vec::with_capacity(22);

// SOCKS5 reply version.
    packet.push(0x05);
// SOCKS5 reply status code.
    packet.push(replyCode);
// Reserved byte required by the SOCKS5 packet format.
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

// Run one SOCKS5 UDP relay socket.
// Each received datagram is copied and processed in its own async task.
async fn runSocks5UdpProxy(listenAddress: SocketAddr, serviceName: &'static str, logger: Logger) -> io::Result<()> {
// Create the UDP relay socket for this address family.
    let udpSocket = match createUdpSocket(listenAddress) {
        Ok(udpSocket) => udpSocket,
        Err(error) => {
            logger.error(format!("{} bind failed on {}: {}", serviceName, listenAddress, error));
            return Ok(());
        }
    };

// Share the UDP socket across spawned datagram tasks.
    let sharedSocket = Arc::new(udpSocket);
    let mut packetBuffer = vec![0u8; udpBufferSize];

    logger.info(format!("{} ready on {}", serviceName, listenAddress));

    loop {
// Receive one SOCKS5 UDP relay datagram from a client.
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
// Copy the datagram because the shared receive buffer will be reused immediately.
        let packet = packetBuffer[..packetSize].to_vec();
        let socketClone = sharedSocket.clone();
        let taskLogger = logger.clone();

// Move this connection into its own asynchronous task.
        tokio::spawn(async move {
            let packetResult = handleSocks5UdpPacket(socketClone, clientAddress, packet, taskLogger.clone()).await;

            if let Err(error) = packetResult {
                taskLogger.warn(format!("SOCKS5 UDP client {} error: {}", clientAddress, error));
            }
        });
    }
}

// Handle one SOCKS5 UDP relay datagram.
// The function validates the SOCKS5 UDP header, extracts the target, forwards the payload, waits for one response, wraps it, and sends it back.
async fn handleSocks5UdpPacket(
    serverSocket: Arc<UdpSocket>,
    clientAddress: SocketAddr,
    packet: Vec<u8>,
    logger: Logger,
) -> io::Result<()> {
// A valid SOCKS5 UDP packet must contain at least RSV, RSV, FRAG, and ATYP.
    if packet.len() < 4 {
        return Ok(());
    }

    // SOCKS5 UDP request starts with RSV RSV FRAG. This server rejects fragmented UDP packets.
    if packet[0] != 0x00 || packet[1] != 0x00 || packet[2] != 0x00 {
        return Ok(());
    }

// Decode the SOCKS5 UDP target address and find where payload bytes begin.
    let targetInfo = parseSocks5UdpTarget(&packet)?;
    let targetHost = targetInfo.0;
    let targetPort = targetInfo.1;
    let payloadStartIndex = targetInfo.2;

// Drop packets that contain a valid header but no UDP payload.
    if payloadStartIndex >= packet.len() {
        return Ok(());
    }

// Resolve domain targets before forwarding the UDP payload.
    let targetAddress = resolveFirstSocketAddress(&targetHost, targetPort).await?;
// Bind the temporary outbound UDP socket to the same address family as the target.
    let relayBindAddress = if targetAddress.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };

// Use a temporary UDP socket for this one relay exchange.
    let relaySocket = UdpSocket::bind(relayBindAddress).await?;
// Forward only the original UDP payload, not the SOCKS5 wrapper header.
    relaySocket.send_to(&packet[payloadStartIndex..], targetAddress).await?;

    logger.info(format!("SOCKS5 UDP {} -> {}", clientAddress, targetAddress));

    let mut responseBuffer = vec![0u8; udpBufferSize];
// Wait briefly for a UDP response so the task does not live forever.
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

// Wrap the remote UDP response in a SOCKS5 UDP response header.
    appendSocks5UdpHeader(&mut responsePacket, remoteAddress);
    responsePacket.extend_from_slice(&responseBuffer[..responseSize]);

// Send the wrapped response back to the SOCKS5 UDP client.
    serverSocket.send_to(&responsePacket, clientAddress).await?;

    Ok(())
}

// Resolve a host and port into a SocketAddr.
// The first result is used; this keeps the implementation small and predictable.
async fn resolveFirstSocketAddress(host: &str, port: u16) -> io::Result<SocketAddr> {
// Build a host:port string acceptable to Tokio DNS lookup.
    let targetAddressText = formatHostAndPort(host, port);
    let mut addressIterator = lookup_host(targetAddressText.as_str()).await?;

    match addressIterator.next() {
        Some(socketAddress) => Ok(socketAddress),
        None => Err(invalidData("DNS resolution returned no address")),
    }
}

// Parse the SOCKS5 UDP request header.
// The return value contains target host, target port, and the index where the UDP payload starts.
fn parseSocks5UdpTarget(packet: &[u8]) -> io::Result<(String, u16, usize)> {
// In a SOCKS5 UDP request, ATYP follows RSV, RSV, and FRAG.
    let addressType = packet[3];
// Payload parsing starts immediately after RSV RSV FRAG ATYP.
    let mut offset = 4usize;

    let host = match addressType {
// SOCKS5 address type 0x01: IPv4 address.
        0x01 => {
            if packet.len() < offset + 4 + 2 {
                return Err(invalidData("invalid IPv4 UDP packet"));
            }

            let address = Ipv4Addr::new(packet[offset], packet[offset + 1], packet[offset + 2], packet[offset + 3]);
            offset += 4;
            address.to_string()
        }
// SOCKS5 address type 0x03: domain name.
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
// SOCKS5 address type 0x04: IPv6 address.
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

// Decode the target UDP port in network byte order.
    let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    offset += 2;

    Ok((host, port, offset))
}

// Append the SOCKS5 UDP response header.
// The remote sender address becomes the source address in the wrapped response sent back to the client.
fn appendSocks5UdpHeader(packet: &mut Vec<u8>, remoteAddress: SocketAddr) {
// Reserved byte required by the SOCKS5 packet format.
    packet.push(0x00);
// Reserved byte required by the SOCKS5 packet format.
    packet.push(0x00);
// Reserved byte required by the SOCKS5 packet format.
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

// Append BND.PORT or source port in network byte order.
    packet.extend_from_slice(&remoteAddress.port().to_be_bytes());
}

// Format host and port for Tokio connect or DNS lookup.
// IPv6 addresses must be bracketed when combined with a port.
fn formatHostAndPort(host: &str, port: u16) -> String {
// Unbracketed IPv6 text must be bracketed before appending :port.
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

// Return a neutral placeholder address.
// Used in SOCKS5 failure replies when no meaningful bound address exists.
fn unspecifiedSocketAddress() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

// Create a protocol parsing error with io::ErrorKind::InvalidData.
fn invalidData(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}
