use std::sync::{Arc, Mutex};
use tokio::sync::watch;

#[derive(Debug)]
struct ActiveAssessment {
    project_id: i64,
    run_id: i64,
    cancel: watch::Sender<bool>,
}

/// Process-wide admission and cancellation gate. SQLite additionally owns a
/// unique partial index so two application processes cannot create active runs.
#[derive(Debug, Default)]
pub struct AssessmentManager {
    active: Mutex<Option<ActiveAssessment>>,
}

impl AssessmentManager {
    pub fn claim(&self, project_id: i64, run_id: i64) -> Result<watch::Receiver<bool>, String> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| "评估运行管理器已损坏".to_string())?;
        if let Some(current) = active.as_ref() {
            return Err(format!(
                "[ASSESSMENT_BUSY] 已有评估正在运行（run_id={}）",
                current.run_id
            ));
        }
        let (cancel, receiver) = watch::channel(false);
        *active = Some(ActiveAssessment {
            project_id,
            run_id,
            cancel,
        });
        Ok(receiver)
    }

    pub fn cancel(&self, project_id: i64, run_id: i64) -> Result<(), String> {
        let active = self
            .active
            .lock()
            .map_err(|_| "评估运行管理器已损坏".to_string())?;
        let current = active
            .as_ref()
            .filter(|current| current.project_id == project_id && current.run_id == run_id)
            .ok_or_else(|| "[ASSESSMENT_NOT_ACTIVE] 指定评估当前未运行".to_string())?;
        current
            .cancel
            .send(true)
            .map_err(|_| "[ASSESSMENT_NOT_ACTIVE] 评估任务已经结束".to_string())
    }

    pub fn release(&self, run_id: i64) {
        if let Ok(mut active) = self.active.lock() {
            if active
                .as_ref()
                .is_some_and(|current| current.run_id == run_id)
            {
                *active = None;
            }
        }
    }

    pub fn active_run_for_project(&self, project_id: i64) -> Option<i64> {
        self.active.lock().ok().and_then(|active| {
            active
                .as_ref()
                .filter(|current| current.project_id == project_id)
                .map(|current| current.run_id)
        })
    }
}

/// RAII 释放 guard：后台任务无论正常结束还是 panic unwind，都会释放全局
/// admission 槽，避免一次崩溃让所有后续评估永久卡在 [ASSESSMENT_BUSY]。
pub struct AssessmentRunGuard {
    manager: Arc<AssessmentManager>,
    run_id: i64,
}

impl AssessmentRunGuard {
    pub fn new(manager: Arc<AssessmentManager>, run_id: i64) -> Self {
        Self { manager, run_id }
    }
}

impl Drop for AssessmentRunGuard {
    fn drop(&mut self) {
        self.manager.release(self.run_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_only_one_run_and_cancels_exact_context() {
        let manager = AssessmentManager::default();
        let receiver = manager.claim(1, 10).unwrap();
        assert!(!*receiver.borrow());
        assert!(manager.claim(2, 11).is_err());
        assert!(manager.cancel(2, 10).is_err());
        manager.cancel(1, 10).unwrap();
        assert!(*receiver.borrow());
        manager.release(10);
        assert!(manager.claim(2, 11).is_ok());
    }
}
