//! MITM 代理生命周期管理：启动/停止/状态查询。
//! hudsucker 0.25 用法（已对照官方源码确认）：
//!   Proxy::builder().with_listener(..).with_ca(..).with_rustls_connector(..)
//!     .with_http_handler(..).with_graceful_shutdown(oneshot).build() → proxy.start().await

pub mod ca;
pub mod interceptor;

use crate::storage::db::Pool;
use hudsucker::Proxy;
use hudsucker::rustls::crypto::aws_lc_rs;
use interceptor::{TauriSink, TrafficHandler};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::oneshot;

#[derive(Debug, Clone, Serialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub port: u16,
}

struct ProxyInner {
    /// 优雅停机触发器（Some 即代表运行中）
    shutdown: Option<oneshot::Sender<()>>,
    port: u16,
}

/// 代理全局状态（挂在 AppState 上）
pub struct ProxyManager {
    inner: Mutex<ProxyInner>,
}

impl Default for ProxyManager {
    fn default() -> Self {
        Self {
            inner: Mutex::new(ProxyInner { shutdown: None, port: 0 }),
        }
    }
}

impl ProxyManager {
    pub fn status(&self) -> ProxyStatus {
        match self.inner.lock() {
            Ok(i) => ProxyStatus { running: i.shutdown.is_some(), port: i.port },
            Err(_) => ProxyStatus { running: false, port: 0 },
        }
    }

    /// 启动代理。同步阶段完成端口绑定和 CA 加载，错误直接返回给调用方；
    /// 之后 proxy.start() 在后台任务里跑，退出时清理状态并广播 proxy:status。
    pub async fn start(
        &self,
        app: AppHandle,
        db: Pool,
        app_data_dir: PathBuf,
        port: u16,
    ) -> Result<ProxyStatus, String> {
        {
            let inner = self.inner.lock().map_err(|e| e.to_string())?;
            if inner.shutdown.is_some() {
                return Err(format!("代理已在运行（端口 {}）", inner.port));
            }
        }

        // CA 证书：不存在则生成（首次使用需引导用户安装信任）
        let material = ca::ensure_ca(&app_data_dir)?;
        let authority = ca::build_authority(&material)?;

        // 先绑端口，占用/权限错误立刻可见
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("端口 {port} 绑定失败: {e}"))?;

        let (tx, rx) = oneshot::channel::<()>();
        let handler = TrafficHandler::new(db, Arc::new(TauriSink(app.clone())));
        let proxy = Proxy::builder()
            .with_listener(listener)
            .with_ca(authority)
            .with_rustls_connector(aws_lc_rs::default_provider())
            .with_http_handler(handler)
            .with_graceful_shutdown(async move {
                rx.await.unwrap_or_default();
            })
            .build()
            .map_err(|e| format!("代理构建失败: {e}"))?;

        {
            let mut inner = self.inner.lock().map_err(|e| e.to_string())?;
            inner.shutdown = Some(tx);
            inner.port = port;
        }
        let _ = app.emit("proxy:status", self.status());

        // 后台跑代理主循环；结束（主动停止或出错）时清理状态并通知前端
        let app2 = app.clone();
        tauri::async_runtime::spawn(async move {
            let result = proxy.start().await;
            let status = match app2.try_state::<crate::AppState>() {
                Some(state) => {
                    if let Ok(mut inner) = state.proxy.inner.lock() {
                        inner.shutdown = None;
                    }
                    state.proxy.status()
                }
                None => ProxyStatus { running: false, port: 0 },
            };
            let _ = app2.emit("proxy:status", status);
            if let Err(e) = result {
                let _ = app2.emit("proxy:error", format!("代理异常退出: {e}"));
            }
        });

        Ok(self.status())
    }

    /// 停止代理（graceful：hudsucker 会等服务连接收尾后退出主循环）
    pub fn stop(&self, app: &AppHandle) -> Result<ProxyStatus, String> {
        let tx = {
            let mut inner = self.inner.lock().map_err(|e| e.to_string())?;
            inner.shutdown.take()
        };
        match tx {
            Some(tx) => {
                let _ = tx.send(());
                // 状态清理由后台任务兜底；这里立刻广播一次让 UI 响应更快
                let _ = app.emit("proxy:status", self.status());
                Ok(self.status())
            }
            None => Err("代理未在运行".into()),
        }
    }
}
