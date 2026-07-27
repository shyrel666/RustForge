mod commands;
// pub 暴露给集成测试（tests/）做无 GUI 的端到端验证
pub mod ai;
pub mod authorization;
pub mod knowledge;
pub mod proxy;
pub mod report;
pub mod rules;
pub mod secrets;
pub mod storage;
pub mod tree;

use std::sync::Arc;
use storage::db::Pool;
use tauri::Manager;

/// 全局应用状态：数据库连接池（代理与 UI 各借独立连接，避免单连接竞争/中毒）
/// + 代理生命周期管理
pub struct AppState {
    pub db: Pool,
    pub proxy: proxy::ProxyManager,
    pub secrets: Arc<dyn secrets::SecretStore>,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            #[cfg(desktop)]
            app.handle()
                .plugin(tauri_plugin_updater::Builder::new().build())?;
            knowledge::validate_builtin_registry()
                .map_err(|e| format!("内置安全标准知识包校验失败: {e}"))?;
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let db = storage::db::open_pool(&dir.join("rustforge.db"))
                .map_err(|e| format!("打开数据库失败: {e}"))?;
            {
                let conn = db.get().map_err(|e| format!("检查设置安全基线失败: {e}"))?;
                secrets::validate_no_plaintext_settings(&conn)?;
            }
            app.manage(AppState {
                db,
                proxy: proxy::ProxyManager::default(),
                secrets: Arc::new(secrets::SystemSecretStore::new()),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_setting,
            commands::set_setting,
            commands::get_all_settings,
            commands::get_ai_data_policy,
            commands::set_ai_data_policy,
            commands::set_provider_api_key,
            commands::delete_provider_api_key,
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
            commands::preview_ai_context,
            commands::analyze_traffic,
            commands::get_analysis,
            commands::get_analysis_run,
            commands::list_findings,
            commands::update_finding_status,
            commands::delete_finding,
            commands::get_prompt_template,
            commands::list_prompt_versions,
            commands::set_prompt_template,
            commands::copy_prompt_template,
            commands::rollback_prompt_template,
            commands::reset_prompt_template,
            commands::get_task_tree,
            commands::preview_task_ai,
            commands::generate_task_tree,
            commands::expand_task_node,
            commands::alternative_task_node,
            commands::next_task,
            commands::update_task_status,
            commands::create_task_node,
            commands::delete_task_node,
            commands::get_task_findings,
            commands::get_knowledge_cards,
            commands::authorize_replay_target,
            commands::replay_request,
            commands::build_report,
            commands::export_report,
            commands::count_traffic,
            commands::get_token_usage,
            commands::reset_token_usage,
            commands::get_usage_trend,
            commands::open_url,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod security_config_tests {
    #[test]
    fn production_csp_is_enabled_and_frontend_network_is_limited_to_tauri_ipc() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let security = &config["app"]["security"];
        assert_eq!(security["csp"]["connect-src"], "ipc: http://ipc.localhost");
        assert_eq!(security["csp"]["object-src"], "'none'");
        assert_eq!(security["csp"]["frame-src"], "'none'");
        assert!(security["devCsp"]["connect-src"]
            .as_str()
            .unwrap()
            .contains("ws://localhost:1420"));
    }
}
