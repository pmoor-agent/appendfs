use crate::remote::{MockRemoteStore, RemoteStore};
use quick_xml::escape::escape;
use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use url::Url;

/// One HTTP request as received by [`FakeS3Server`], recorded before it is served.
#[derive(Debug, Clone)]
pub struct FakeS3Request {
    pub method: String,
    /// Percent-decoded request path, including the leading `/{bucket}` segment.
    pub path: String,
    /// Percent-decoded query parameters in the order they were sent.
    pub query: Vec<(String, String)>,
    /// Header names are lowercased; values are trimmed.
    pub headers: Vec<(String, String)>,
}

impl FakeS3Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn query_param(&self, name: &str) -> Option<&str> {
        self.query.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

/// A minimal S3-compatible HTTP server on `127.0.0.1` for exercising `S3RemoteStore` and the CLI
/// end to end without a real object store.
///
/// It serves a single bucket in path-style addressing (`/{bucket}/{key}`) and implements exactly the
/// operations `S3RemoteStore` issues: ListObjectsV2 (with continuation tokens), GET (optionally with a
/// `Range`), HEAD, PUT (honoring `Content-MD5`) and DELETE. Objects live in a [`MockRemoteStore`] that
/// tests can seed and inspect directly. Every request is recorded so tests can assert on addressing and
/// headers. Signatures are not verified.
///
/// The server shuts down and joins all of its threads on drop.
pub struct FakeS3Server {
    addr: SocketAddr,
    shared: Arc<Shared>,
    accept_thread: Option<JoinHandle<()>>,
}

struct Shared {
    bucket: String,
    store: Arc<MockRemoteStore>,
    requests: Mutex<Vec<FakeS3Request>>,
    injected_errors: Mutex<VecDeque<(u16, String)>>,
    list_page_size: AtomicUsize,
    shutdown: AtomicBool,
}

impl FakeS3Server {
    /// Binds an ephemeral port on `127.0.0.1` and starts serving `bucket` from an empty store.
    pub fn start(bucket: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake S3 listener");
        let addr = listener.local_addr().unwrap();
        let shared = Arc::new(Shared {
            bucket: bucket.to_string(),
            store: Arc::new(MockRemoteStore::new()),
            requests: Mutex::new(Vec::new()),
            injected_errors: Mutex::new(VecDeque::new()),
            list_page_size: AtomicUsize::new(1000),
            shutdown: AtomicBool::new(false),
        });
        let accept_shared = shared.clone();
        let accept_thread = thread::spawn(move || accept_loop(listener, accept_shared));
        Self {
            addr,
            shared,
            accept_thread: Some(accept_thread),
        }
    }

    /// Base URL to pass as the S3 endpoint, e.g. `http://127.0.0.1:41234`.
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The backing object store; keys are relative to the bucket (they include any client prefix).
    pub fn store(&self) -> &Arc<MockRemoteStore> {
        &self.shared.store
    }

    /// All requests received so far, in arrival order.
    pub fn requests(&self) -> Vec<FakeS3Request> {
        self.shared.requests.lock().unwrap().clone()
    }

    /// Caps the number of keys returned per ListObjectsV2 page (default 1000, like S3).
    pub fn set_list_page_size(&self, page_size: usize) {
        assert!(page_size > 0, "list page size must be positive");
        self.shared.list_page_size.store(page_size, Ordering::SeqCst);
    }

    /// Answers the next request with an S3 error document instead of serving it. Multiple calls queue up.
    pub fn fail_next_request(&self, status: u16, code: &str) {
        self.shared
            .injected_errors
            .lock()
            .unwrap()
            .push_back((status, code.to_string()));
    }
}

impl Drop for FakeS3Server {
    fn drop(&mut self) {
        self.shared.shutdown.store(true, Ordering::SeqCst);
        // Wake the blocking accept() so the loop observes the shutdown flag.
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
    }
}

fn accept_loop(listener: TcpListener, shared: Arc<Shared>) {
    let mut connections: Vec<(TcpStream, JoinHandle<()>)> = Vec::new();
    for stream in listener.incoming() {
        if shared.shutdown.load(Ordering::SeqCst) {
            break;
        }
        let Ok(stream) = stream else { continue };
        let Ok(control) = stream.try_clone() else { continue };
        let conn_shared = shared.clone();
        let handle = thread::spawn(move || {
            // A failed connection (client hung up mid-request, shutdown) just ends that connection.
            let _ = serve_connection(stream, &conn_shared);
        });
        connections.push((control, handle));
    }
    // Clients pool keep-alive connections, so their handlers may still be parked in a read.
    for (control, handle) in connections {
        let _ = control.shutdown(Shutdown::Both);
        let _ = handle.join();
    }
}

fn serve_connection(stream: TcpStream, shared: &Shared) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    loop {
        let mut request_line = String::new();
        if reader.read_line(&mut request_line)? == 0 {
            return Ok(());
        }
        let mut parts = request_line.split_whitespace();
        let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "malformed request line"));
        };

        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }

        let url = Url::parse(&format!("http://fake-s3{}", target))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let request = FakeS3Request {
            method: method.to_string(),
            path: percent_decode(url.path()),
            query: url
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect(),
            headers,
        };

        let content_length = request
            .header("content-length")
            .map(|v| v.parse::<u64>())
            .transpose()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .unwrap_or(0);
        let mut body = Vec::new();
        (&mut reader).take(content_length).read_to_end(&mut body)?;
        if body.len() as u64 != content_length {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        shared.requests.lock().unwrap().push(request.clone());
        let response = handle_request(shared, &request, body);
        response.write_to(&mut writer, request.method == "HEAD")?;
    }
}

struct Response {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl Response {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body,
        }
    }

    fn error(status: u16, code: &str, message: &str) -> Self {
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{}</Code><Message>{}</Message></Error>",
            escape(code),
            escape(message)
        );
        Self {
            status,
            headers: vec![("Content-Type", "application/xml".to_string())],
            body: body.into_bytes(),
        }
    }

    fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    fn write_to(&self, out: &mut impl Write, head_only: bool) -> io::Result<()> {
        let mut head = format!("HTTP/1.1 {} {}\r\n", self.status, reason_phrase(self.status));
        for (name, value) in &self.headers {
            head.push_str(&format!("{}: {}\r\n", name, value));
        }
        // HEAD responses advertise the object size themselves and must not carry a body.
        if !head_only {
            head.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        head.push_str("\r\n");
        out.write_all(head.as_bytes())?;
        if !head_only {
            out.write_all(&self.body)?;
        }
        out.flush()
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        206 => "Partial Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        416 => "Range Not Satisfiable",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

fn handle_request(shared: &Shared, req: &FakeS3Request, body: Vec<u8>) -> Response {
    if let Some((status, code)) = shared.injected_errors.lock().unwrap().pop_front() {
        return Response::error(status, &code, "injected by FakeS3Server");
    }

    let path = req.path.trim_start_matches('/');
    let (bucket, key) = path.split_once('/').unwrap_or((path, ""));
    if bucket != shared.bucket {
        return Response::error(404, "NoSuchBucket", &format!("bucket '{}' does not exist", bucket));
    }
    let store = &shared.store;

    match (req.method.as_str(), key.is_empty()) {
        ("GET", true) if req.query_param("list-type") == Some("2") => list_objects_v2(shared, req),
        ("GET", false) => {
            let Some(data) = store.get_raw_bytes(key) else {
                return Response::error(404, "NoSuchKey", key);
            };
            let etag = etag_of(store, key);
            match req.header("range") {
                None => Response::ok(data).header("ETag", etag),
                Some(range) => match parse_range(range, data.len() as u64) {
                    Some((start, end)) => {
                        let content_range = format!("bytes {}-{}/{}", start, end, data.len());
                        let mut resp = Response::ok(data[start as usize..=end as usize].to_vec())
                            .header("ETag", etag)
                            .header("Content-Range", content_range);
                        resp.status = 206;
                        resp
                    }
                    None => Response::error(416, "InvalidRange", range),
                },
            }
        }
        ("HEAD", false) => match store.head_object(key) {
            Ok(Some(obj)) => Response::ok(Vec::new())
                .header("Content-Length", obj.size.to_string())
                .header("ETag", obj.etag.unwrap_or_default()),
            Ok(None) => Response {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
            },
            Err(e) => Response::error(500, "InternalError", &e.to_string()),
        },
        ("PUT", false) => {
            let content_md5 = match req.header("content-md5").map(decode_content_md5) {
                Some(Some(md5)) => Some(md5),
                Some(None) => return Response::error(400, "InvalidDigest", "Content-MD5 is not valid base64 MD5"),
                None => None,
            };
            let len = body.len() as u64;
            match store.put_object(key, &mut body.as_slice(), len, content_md5.as_ref()) {
                Ok(()) => Response::ok(Vec::new()).header("ETag", etag_of(store, key)),
                Err(e) if e.kind() == io::ErrorKind::InvalidData => Response::error(400, "BadDigest", &e.to_string()),
                Err(e) => Response::error(500, "InternalError", &e.to_string()),
            }
        }
        ("DELETE", false) => match store.delete_object(key) {
            // S3 answers 204 whether or not the key existed.
            Ok(()) => Response {
                status: 204,
                headers: Vec::new(),
                body: Vec::new(),
            },
            Err(e) => Response::error(500, "InternalError", &e.to_string()),
        },
        _ => Response::error(405, "MethodNotAllowed", &format!("{} {}", req.method, req.path)),
    }
}

fn list_objects_v2(shared: &Shared, req: &FakeS3Request) -> Response {
    let prefix = req.query_param("prefix").unwrap_or("");
    let objects = match shared.store.list_objects(prefix) {
        Ok(objects) => objects,
        Err(e) => return Response::error(500, "InternalError", &e.to_string()),
    };
    // The continuation token is simply the last key of the previous page; listings are key-ordered.
    let start_after = req.query_param("continuation-token");
    let remaining: Vec<_> = objects
        .into_iter()
        .filter(|o| start_after.is_none_or(|after| o.key.as_str() > after))
        .collect();
    let page_size = shared.list_page_size.load(Ordering::SeqCst);
    let page = &remaining[..remaining.len().min(page_size)];
    let truncated = remaining.len() > page.len();

    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    xml.push_str(&format!("<Name>{}</Name>", escape(&shared.bucket)));
    xml.push_str(&format!("<Prefix>{}</Prefix>", escape(prefix)));
    xml.push_str(&format!("<KeyCount>{}</KeyCount>", page.len()));
    xml.push_str(&format!("<MaxKeys>{}</MaxKeys>", page_size));
    xml.push_str(&format!("<IsTruncated>{}</IsTruncated>", truncated));
    if truncated {
        let last = &page.last().unwrap().key;
        xml.push_str(&format!(
            "<NextContinuationToken>{}</NextContinuationToken>",
            escape(last)
        ));
    }
    for obj in page {
        xml.push_str(&format!(
            "<Contents><Key>{}</Key><Size>{}</Size><ETag>{}</ETag><StorageClass>STANDARD</StorageClass></Contents>",
            escape(&obj.key),
            obj.size,
            escape(obj.etag.as_deref().unwrap_or_default())
        ));
    }
    xml.push_str("</ListBucketResult>");
    Response::ok(xml.into_bytes()).header("Content-Type", "application/xml")
}

fn etag_of(store: &MockRemoteStore, key: &str) -> String {
    store
        .head_object(key)
        .ok()
        .flatten()
        .and_then(|o| o.etag)
        .unwrap_or_default()
}

/// Parses a single `bytes=start-end` range (inclusive end, clamped to the object like S3 does).
fn parse_range(range: &str, len: u64) -> Option<(u64, u64)> {
    let (start, end) = range.strip_prefix("bytes=")?.split_once('-')?;
    let start: u64 = start.parse().ok()?;
    let end: u64 = if end.is_empty() { u64::MAX } else { end.parse().ok()? };
    if start >= len || end < start {
        return None;
    }
    Some((start, end.min(len - 1)))
}

fn decode_content_md5(value: &str) -> Option<[u8; 16]> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .ok()?
        .try_into()
        .ok()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(byte) = s.get(i + 1..i + 3).and_then(|hex| u8::from_str_radix(hex, 16).ok())
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
