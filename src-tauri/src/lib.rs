mod commands;
// pub 暴露给集成测试（tests/）做无 GUI 的端到端验证
pub mod ai;
pub mod assessment;
pub mod authorization;
pub mod evidence;
pub mod knowledge;
pub mod proxy;
pub mod replay;
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
    pub assessments: Arc<assessment::AssessmentManager>,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
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
                let mut conn = db.get().map_err(|e| format!("检查设置安全基线失败: {e}"))?;
                secrets::validate_no_plaintext_settings(&conn)?;
                replay::service::recover_interrupted_attempts(&conn)
                    .map_err(|e| format!("恢复中断的 Repeater 请求失败: {e}"))?;
                assessment::service::recover_interrupted_runs(&mut conn)
                    .map_err(|e| format!("恢复中断的 AI 评估失败: {e}"))?;
            }
            app.manage(AppState {
                db,
                proxy: proxy::ProxyManager::default(),
                secrets: Arc::new(secrets::SystemSecretStore::new()),
                assessments: Arc::new(assessment::AssessmentManager::default()),
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
            commands::fetch_models_for_draft,
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
            commands::list_finding_traffic,
            commands::list_finding_rule_hits,
            commands::list_finding_evidence,
            commands::list_finding_events,
            commands::create_finding_evidence,
            commands::create_task_evidence,
            commands::set_finding_evidence_accepted,
            commands::get_rule_diagnostics,
            commands::update_finding_status,
            commands::update_finding_review,
            commands::delete_finding,
            commands::get_prompt_template,
            commands::list_prompt_versions,
            commands::set_prompt_template,
            commands::copy_prompt_template,
            commands::rollback_prompt_template,
            commands::reset_prompt_template,
            commands::get_task_tree,
            commands::get_test_plan,
            commands::list_task_plan_events,
            commands::preview_task_ai,
            commands::generate_task_tree,
            commands::expand_task_node,
            commands::alternative_task_node,
            commands::apply_task_plan_proposal,
            commands::reject_task_plan_proposal,
            commands::next_task,
            commands::update_task_status,
            commands::create_task_node,
            commands::update_task_node,
            commands::delete_task_node,
            commands::get_task_findings,
            commands::get_knowledge_cards,
            commands::authorize_replay_target,
            commands::list_replay_sessions,
            commands::create_replay_session,
            commands::update_replay_session,
            commands::select_replay_session,
            commands::delete_replay_session,
            commands::list_replay_runs,
            commands::get_replay_run,
            commands::compare_replay_runs,
            commands::replay_request,
            commands::list_assessment_auth_profiles,
            commands::create_assessment_auth_profile,
            commands::set_assessment_auth_profile,
            commands::import_assessment_auth_profile,
            commands::list_assessment_auth_candidates,
            commands::delete_assessment_auth_profile,
            commands::preview_assessment_contract,
            commands::start_assessment,
            commands::cancel_assessment,
            commands::list_assessment_runs,
            commands::get_assessment_detail,
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
