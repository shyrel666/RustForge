//! AI 引导的非破坏式安全评估。
//!
//! 该领域拥有独立的运行契约、端点、检查和验证结果。旧 `tree` 模块仍只表示
//! 文字测试计划，任何 Assessment 执行动作都不能由 `PlannedNode` 派生。

pub mod catalog;
pub mod discovery;
pub mod executor;
pub mod manager;
pub mod model;
pub mod outcome;
pub mod planner;
pub mod policy;
pub mod runner;
pub mod service;
pub mod templates;
pub mod verifier;

pub use manager::{AssessmentManager, AssessmentRunGuard};
