use super::migrations;
use rusqlite::Connection;
use std::path::{Path, PathBuf};

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
        migrate_with_backup(&mut conn, path)?;
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
    migrate_with_backup(&mut migration_conn, path)?;
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

/// Released databases are snapshotted with SQLite itself immediately before an
/// upgrade. `VACUUM INTO` includes committed WAL pages and avoids a torn
/// filesystem copy while the connection is open. Fresh databases and already
/// current schemas do not create a backup.
fn migrate_with_backup(conn: &mut Connection, path: &Path) -> Result<(), String> {
    let from_version =
        migrations::schema_version(conn).map_err(|error| format!("读取数据库版本失败: {error}"))?;
    if from_version > 0
        && from_version < migrations::LATEST_SCHEMA_VERSION
        && path.exists()
        && path.is_file()
    {
        let backup_path = next_migration_backup_path(path, from_version)?;
        let backup_text = backup_path
            .to_str()
            .ok_or_else(|| "数据库备份路径不是有效 Unicode".to_string())?;
        conn.execute("VACUUM INTO ?1", [backup_text])
            .map_err(|error| format!("创建迁移前备份失败: {error}"))?;
    }
    migrations::migrate(conn).map_err(|error| format!("迁移数据库失败: {error}"))?;
    Ok(())
}

fn next_migration_backup_path(path: &Path, from_version: u32) -> Result<PathBuf, String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "数据库文件名不是有效 Unicode".to_string())?;
    let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S-%3f");
    let base = format!(
        "{file_name}.pre-v{from_version}-to-v{}-{timestamp}",
        migrations::LATEST_SCHEMA_VERSION
    );
    for suffix in 0..1000_u16 {
        let name = if suffix == 0 {
            format!("{base}.bak")
        } else {
            format!("{base}-{suffix}.bak")
        };
        let candidate = path.with_file_name(name);
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err("无法分配迁移前备份文件名".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::model::CreateTaskNodeInput;
    use crate::tree::service as tree_service;

    fn manual_input(
        project_id: i64,
        parent_id: Option<i64>,
        title: &str,
        prerequisites: Vec<i64>,
    ) -> CreateTaskNodeInput {
        CreateTaskNodeInput {
            project_id,
            parent_id,
            node_type: "test".to_string(),
            title: title.to_string(),
            description: String::new(),
            why: String::new(),
            how_to: String::new(),
            verify_criteria: String::new(),
            priority: 50,
            required_role: String::new(),
            required_session: String::new(),
            expected_observation: String::new(),
            actual_observation: String::new(),
            prerequisite_ids: prerequisites,
        }
    }

    /// 每条池连接都必须开启 foreign_keys，否则级联删除失效——这里直接验证级联。
    #[test]
    fn pool_enforces_foreign_key_cascade() {
        let dir = std::env::temp_dir().join(format!("rustforge-pool-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pool.db");
        let _ = std::fs::remove_file(&path);

        let pool = open_pool(&path).unwrap();
        let mut conn = pool.get().unwrap();
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
        tree_service::create_manual_node(
            &mut conn,
            &manual_input(pid, None, "plan node", Vec::new()),
            "test",
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
        let plan_events: i64 = conn
            .query_row("SELECT COUNT(*) FROM task_plan_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(plan_events, 0, "项目生命周期删除允许计划事件级联");
    }

    #[test]
    fn test_plan_shape_status_and_dependencies_survive_reopen() {
        let dir =
            std::env::temp_dir().join(format!("rustforge-test-plan-reopen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plan.db");
        let _ = std::fs::remove_file(&path);

        let mut db = Db::open(&path).unwrap();
        db.conn
            .execute("INSERT INTO projects(name) VALUES('plan')", [])
            .unwrap();
        let project_id = db.conn.last_insert_rowid();
        let root = tree_service::create_manual_node(
            &mut db.conn,
            &manual_input(project_id, None, "root", Vec::new()),
            "test",
        )
        .unwrap();
        let child = tree_service::create_manual_node(
            &mut db.conn,
            &manual_input(project_id, Some(root), "child", vec![root]),
            "test",
        )
        .unwrap();
        tree_service::update_status(&mut db.conn, root, "in_progress", None, "test").unwrap();
        tree_service::update_status(&mut db.conn, child, "blocked", Some("等待授权窗口"), "test")
            .unwrap();
        let revision = tree_service::get_plan(&db.conn, project_id)
            .unwrap()
            .revision;
        drop(db);

        let reopened = Db::open(&path).unwrap();
        let nodes = tree_service::load_nodes(&reopened.conn, project_id, false).unwrap();
        assert_eq!(nodes.len(), 2);
        let persisted_root = nodes.iter().find(|node| node.id == root).unwrap();
        let persisted_child = nodes.iter().find(|node| node.id == child).unwrap();
        assert_eq!(persisted_root.status, "in_progress");
        assert_eq!(persisted_child.parent_id, Some(root));
        assert_eq!(persisted_child.prerequisite_ids, vec![root]);
        assert_eq!(persisted_child.status, "blocked");
        assert_eq!(persisted_child.blocker_reason, "等待授权窗口");
        assert_eq!(
            tree_service::get_plan(&reopened.conn, project_id)
                .unwrap()
                .revision,
            revision
        );
    }

    #[test]
    fn released_schema_is_backed_up_before_upgrade() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upgrade.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(PRAGMAS).unwrap();
            conn.execute_batch(super::migrations::SCHEMA_V1).unwrap();
            conn.execute_batch(super::migrations::SCHEMA_V2).unwrap();
            conn.execute_batch(super::migrations::SCHEMA_V3).unwrap();
            conn.pragma_update(None, "user_version", 3).unwrap();
            conn.execute(
                "INSERT INTO settings(key, value) VALUES('marker', 'before')",
                [],
            )
            .unwrap();
        }

        let upgraded = Db::open(&path).unwrap();
        assert_eq!(
            super::migrations::schema_version(&upgraded.conn).unwrap(),
            super::migrations::LATEST_SCHEMA_VERSION
        );
        let backup_path = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|candidate| {
                candidate
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("upgrade.db.pre-v3-to-v4-") && name.ends_with(".bak")
                    })
            })
            .expect("migration backup");
        let backup = Connection::open(&backup_path).unwrap();
        let marker: String = backup
            .query_row("SELECT value FROM settings WHERE key='marker'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(marker, "before");
    }
}
