mod commands;
// pub 暴露给集成测试（tests/）做无 GUI 的端到端验证
pub mod ai;
pub mod knowledge;
pub mod proxy;
pub mod report;
pub mod rules;
pub mod storage;
pub mod tree;

use storage::db::Pool;
use tauri::Manager;

/// 全局应用状态：数据库连接池（代理与 UI 各借独立连接，避免单连接竞争/中毒）
/// + 代理生命周期管理
pub struct AppState {
    pub db: Pool,
    pub proxy: proxy::ProxyManager,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            #[cfg(desktop)]
            app.handle()
                .plugin(tauri_plugin_updater::Builder::new().build())?;
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let db = storage::db::open_pool(&dir.join("rustforge.db"))
                .map_err(|e| format!("打开数据库失败: {e}"))?;
            app.manage(AppState {
                db,
                proxy: proxy::ProxyManager::default(),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_setting,
            commands::set_setting,
            commands::get_all_settings,
            commands::fetch_models,
            commands::list_projects,
            commands::create_project,
            commands::delete_project,
            commands::get_current_project,
            commands::set_current_project,
            commands::update_project_scope,
            commands::start_proxy,
            commands::stop_proxy,
            commands::proxy_status,
            commands::get_ca_info,
            commands::export_ca_cert,
            commands::install_ca_cert,
            commands::reveal_ca_cert,
            commands::get_runtime_info,
            commands::reveal_app_data_dir,
            commands::list_traffic,
            commands::get_traffic_detail,
            commands::clear_traffic,
            commands::analyze_traffic,
            commands::get_analysis,
            commands::list_findings,
            commands::update_finding_status,
            commands::delete_finding,
            commands::get_prompt_template,
            commands::set_prompt_template,
            commands::reset_prompt_template,
            commands::get_task_tree,
            commands::generate_task_tree,
            commands::expand_task_node,
            commands::alternative_task_node,
            commands::next_task,
            commands::update_task_status,
            commands::create_task_node,
            commands::delete_task_node,
            commands::get_task_findings,
            commands::get_knowledge_cards,
            commands::replay_request,
            commands::build_report,
            commands::export_report,
            commands::count_traffic,
            commands::get_token_usage,
            commands::reset_token_usage,
            commands::open_url,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
