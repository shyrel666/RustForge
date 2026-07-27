use super::migrations;
use rusqlite::Connection;
use std::path::Path;

/// 测试和离线构建报告使用的单连接数据库句柄。
pub struct Db {
    pub conn: Connection,
}

/// 连接级 PRAGMA：必须逐连接设置。foreign_keys 是连接级开关（级联删除依赖它），
/// busy_timeout 让并发写入排队而非直接 SQLITE_BUSY 报错。WAL 是库级持久设置，
/// 但每连接重复设置无害。
const PRAGMAS: &str = "\
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
PRAGMA synchronous = NORMAL;
";

impl Db {
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(PRAGMAS).map_err(|e| e.to_string())?;
        migrations::migrate(&mut conn).map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }
}

/// r2d2 + rusqlite 连接池类型别名，全应用共享一个池。
pub type Pool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
/// 从池里借出的连接；Deref 到 rusqlite::Connection，可直接当连接用。
pub type PooledConn = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

/// 打开数据库连接池：先使用独占连接完成版本迁移，再创建连接池。池中的每条连接
/// 经 with_init 启用连接级 PRAGMA（外键/超时/WAL）。相比单连接 + 全局 Mutex，
/// 代理写入与 UI 查询可各持一条连接并行。
pub fn open_pool(path: &Path) -> Result<Pool, String> {
    let mut migration_conn =
        Connection::open(path).map_err(|e| format!("打开数据库进行迁移失败: {e}"))?;
    migration_conn
        .execute_batch(PRAGMAS)
        .map_err(|e| format!("初始化数据库参数失败: {e}"))?;
    migrations::migrate(&mut migration_conn).map_err(|e| format!("迁移数据库失败: {e}"))?;
    drop(migration_conn);

    let manager =
        r2d2_sqlite::SqliteConnectionManager::file(path).with_init(|c| c.execute_batch(PRAGMAS));
    let pool = r2d2::Pool::builder()
        .max_size(8)
        .build(manager)
        .map_err(|e| format!("初始化数据库连接池失败: {e}"))?;
    let conn = pool.get().map_err(|e| e.to_string())?;
    let version = migrations::schema_version(&conn).map_err(|e| e.to_string())?;
    if version != migrations::LATEST_SCHEMA_VERSION {
        return Err(format!(
            "数据库迁移后版本异常: 期望 v{}，实际 v{version}",
            migrations::LATEST_SCHEMA_VERSION
        ));
    }
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 每条池连接都必须开启 foreign_keys，否则级联删除失效——这里直接验证级联。
    #[test]
    fn pool_enforces_foreign_key_cascade() {
        let dir = std::env::temp_dir().join(format!("rustforge-pool-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pool.db");
        let _ = std::fs::remove_file(&path);

        let pool = open_pool(&path).unwrap();
        let conn = pool.get().unwrap();
        assert_eq!(
            migrations::schema_version(&conn).unwrap(),
            migrations::LATEST_SCHEMA_VERSION
        );
        conn.execute("INSERT INTO projects(name) VALUES('p')", [])
            .unwrap();
        let pid = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO traffic(project_id, method, host, url) VALUES(?1,'GET','h','u')",
            [pid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO findings(project_id, source, title) VALUES(?1,'rule','t')",
            [pid],
        )
        .unwrap();

        conn.execute("DELETE FROM projects WHERE id = ?1", [pid])
            .unwrap();

        let traffic: i64 = conn
            .query_row("SELECT COUNT(*) FROM traffic", [], |r| r.get(0))
            .unwrap();
        let findings: i64 = conn
            .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            traffic, 0,
            "删除项目应级联清空流量（依赖每连接 foreign_keys=ON）"
        );
        assert_eq!(findings, 0, "删除项目应级联清空发现");
    }
}
