//! Phase 1 验收的端到端测试（无 GUI）：
//! 本地起一个 TLS 目标站（证书由测试 CA 签发），客户端经代理 CONNECT +
//! TLS 握手（信任测试 CA）发起 HTTPS 请求，验证：
//!   1. hudsucker 完成 MITM 解密并正确转发/回包
//!   2. TrafficHandler 把完整请求/响应写入 SQLite
//!   3. FlowSink 收到与库里一致的事件载荷
//! 与生产唯一差异：上游 connector 额外信任测试 CA（生产用 webpki 公共根）。

use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair,
    date_time_ymd,
};
use hudsucker::rustls::crypto::aws_lc_rs;
use hudsucker::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use hudsucker::rustls::{ClientConfig, RootCertStore, ServerConfig};
use hudsucker::Proxy;
use rustforge_lib::proxy::ca;
use rustforge_lib::proxy::interceptor::{FlowSink, TrafficHandler};
use rustforge_lib::storage::db::{open_pool, Pool};
use rustforge_lib::storage::models::TrafficSummary;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const CA_SCOPE_HOST: &str = "localhost";
const BODY: &str = "hello rustforge mitm";

#[derive(Clone, Default)]
struct VecSink(Arc<Mutex<Vec<TrafficSummary>>>);

impl FlowSink for VecSink {
    fn on_flow(&self, summary: &TrafficSummary) {
        self.0.lock().unwrap().push(summary.clone());
    }
}

fn test_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rustforge-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pki(name: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    // 由测试 CA 签发 localhost 叶子证书
    let dir = test_dir();
    let material = ca::ensure_ca(&dir).unwrap();
    let issuer = Issuer::from_ca_cert_pem(
        &material.cert_pem,
        KeyPair::from_pem(&material.key_pem).unwrap(),
    )
    .unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    params.not_before = date_time_ymd(2024, 1, 1);
    params.not_after = date_time_ymd(2036, 1, 1);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = params.signed_by(&leaf_key, &issuer).unwrap();

    let ca_der = pem::parse(&material.cert_pem).unwrap().contents().to_vec();
    let chain = vec![leaf.der().clone(), CertificateDer::from(ca_der)];
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    (chain, key)
}

fn ca_der() -> CertificateDer<'static> {
    let dir = test_dir();
    let material = ca::ensure_ca(&dir).unwrap();
    CertificateDer::from(pem::parse(&material.cert_pem).unwrap().contents().to_vec())
}

/// 本地 TLS 目标站：固定返回 200 text/plain
async fn spawn_origin() -> u16 {
    let (chain, key) = pki(CA_SCOPE_HOST);
    let config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = acceptor.accept(tcp).await.unwrap();
                let mut buf = vec![0u8; 8192];
                let _ = tls.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{}",
                    BODY.len(),
                    BODY
                );
                tls.write_all(resp.as_bytes()).await.unwrap();
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

/// 起代理：真实 TrafficHandler + 临时 SQLite + VecSink
async fn spawn_proxy(origin_port: u16, db: Pool, sink: VecSink) -> (u16, oneshot::Sender<()>) {
    let dir = test_dir();
    let material = ca::ensure_ca(&dir).unwrap();
    let authority: RcgenAuthority = ca::build_authority(&material).unwrap();

    // 上游 connector：信任测试 CA（生产路径是 with_rustls_connector + webpki 公共根）
    let mut roots = RootCertStore::empty();
    roots.add(ca_der()).unwrap();
    let tls_config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let handler = TrafficHandler::new(db, Arc::new(sink));
    let (tx, rx) = oneshot::channel::<()>();
    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(authority)
        .with_http_connector(https)
        .with_http_handler(handler)
        .with_graceful_shutdown(async move {
            rx.await.unwrap_or_default();
        })
        .build()
        .unwrap();
    tokio::spawn(proxy.start());
    let _ = origin_port;
    (proxy_port, tx)
}

use tokio::sync::oneshot;

/// 读直到拿到完整 HTTP 头（\r\n\r\n）
async fn read_head(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn mitm_https_end_to_end() {
    // 1) 项目 + Scope：只拦截 localhost
    let dir = test_dir();
    let pool = open_pool(&dir.join("test.db")).unwrap();
    {
        let d = pool.get().unwrap();
        d
            .execute(
                "INSERT INTO projects(name, target_host, scope) VALUES('t', 'localhost', '[\"localhost\"]')",
                [],
            )
            .unwrap();
        let pid = d.last_insert_rowid();
        d
            .execute(
                "INSERT INTO settings(key, value) VALUES('current_project_id', ?1)",
                [pid.to_string()],
            )
            .unwrap();
    }

    // 2) 目标站 + 代理
    let origin_port = spawn_origin().await;
    let sink = VecSink::default();
    let (proxy_port, shutdown) = spawn_proxy(origin_port, pool.clone(), sink.clone()).await;

    // 3) 客户端：CONNECT → TLS（信任测试 CA）→ GET
    let client = async {
        let mut tcp = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        tcp.write_all(
            format!("CONNECT {CA_SCOPE_HOST}:{origin_port} HTTP/1.1\r\nHost: {CA_SCOPE_HOST}:{origin_port}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let head = read_head(&mut tcp).await;
        assert!(head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200"), "CONNECT 被拒: {head}");

        let mut roots = RootCertStore::empty();
        roots.add(ca_der()).unwrap();
        let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(CA_SCOPE_HOST).unwrap().to_owned();
        let mut tls = connector.connect(server_name, tcp).await.expect("MITM TLS 握手失败");

        tls.write_all(b"GET /data.json?q=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        tls.read_to_end(&mut resp).await.unwrap();
        let resp = String::from_utf8_lossy(&resp).into_owned();
        assert!(resp.starts_with("HTTP/1.1 200"), "响应异常: {resp}");
        assert!(resp.contains(BODY), "响应体不对: {resp}");
    };
    tokio::time::timeout(Duration::from_secs(30), client)
        .await
        .expect("客户端流程超时");

    // 4) 断言：DB 里有完整记录（handle_response 先落库后回包，此时必然已写入）
    let d = pool.get().unwrap();
    let (method, host, path, status, resp_body, url): (
        String,
        String,
        String,
        i64,
        Vec<u8>,
        String,
    ) = d
        .query_row(
            "SELECT method, host, path, status, resp_body, url FROM traffic WHERE host = 'localhost'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .expect("流量未写入数据库");
    assert_eq!(method, "GET");
    assert_eq!(host, "localhost");
    assert_eq!(path, "/data.json?q=1");
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&resp_body).contains(BODY));
    assert!(url.starts_with("https://localhost"), "url 异常: {url}");
    assert!(url.contains("/data.json?q=1"), "url 异常: {url}");
    let project_count: i64 = d
        .query_row("SELECT COUNT(*) FROM traffic", [], |row| row.get(0))
        .unwrap();
    assert_eq!(project_count, 1, "Scope 外流量不应被记录");
    drop(d);

    // 5) 断言：事件载荷与落库一致
    let events = sink.0.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].status, Some(200));
    assert_eq!(events[0].path, "/data.json?q=1");

    let _ = shutdown.send(());
}

#[tokio::test]
async fn out_of_scope_not_recorded() {
    // Scope 只有 localhost；向 other-host 发明文 HTTP，应只转发不记录
    let dir = test_dir();
    std::fs::remove_file(dir.join("test2.db")).ok();
    let pool = open_pool(&dir.join("test2.db")).unwrap();
    {
        let d = pool.get().unwrap();
        d
            .execute(
                "INSERT INTO projects(name, target_host, scope) VALUES('t', 'localhost', '[\"localhost\"]')",
                [],
            )
            .unwrap();
        let pid = d.last_insert_rowid();
        d
            .execute(
                "INSERT INTO settings(key, value) VALUES('current_project_id', ?1)",
                [pid.to_string()],
            )
            .unwrap();
    }

    // 本地明文 HTTP 站
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut tcp, _) = origin.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _ = tcp.read(&mut buf).await;
                let body = b"ok";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n",
                    body.len()
                );
                tcp.write_all(resp.as_bytes()).await.unwrap();
                tcp.write_all(body).await.unwrap();
            });
        }
    });

    let sink = VecSink::default();
    let (proxy_port, shutdown) = spawn_proxy(origin_port, pool.clone(), sink.clone()).await;

    // 明文 HTTP 走代理，但 Host 头伪装成 Scope 外的域名
    let mut tcp = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    tcp.write_all(
        format!("GET http://not-in-scope.example:{origin_port}/x HTTP/1.1\r\nHost: not-in-scope.example\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    // 读一会儿就关（域名解析会失败，代理回 502；这里只关心"不记录"）
    let mut buf = vec![0u8; 4096];
    let _ = tokio::time::timeout(Duration::from_secs(10), tcp.read(&mut buf)).await;
    drop(tcp);

    tokio::time::sleep(Duration::from_millis(300)).await;
    let d = pool.get().unwrap();
    let count: i64 = d
        .query_row("SELECT COUNT(*) FROM traffic", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0, "Scope 外流量不应被记录");
    assert!(sink.0.lock().unwrap().is_empty());
    let _ = shutdown.send(());
}
