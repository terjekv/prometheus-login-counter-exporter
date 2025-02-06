use serde::Deserialize;
use std::process::Command;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Session {
    pub session: String,
    pub uid: u64,
    pub user: String,
    pub seat: String,
    pub tty: String,
    pub state: String,
    pub idle: bool,
    pub since: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct Sessions {
    pub sessions: Vec<Session>,
}

impl From<Vec<Session>> for Sessions {
    fn from(sessions: Vec<Session>) -> Self {
        Sessions { sessions }
    }
}

impl Sessions {
    pub fn count(&self) -> (usize, usize) {
        let seated = self
            .sessions
            .iter()
            .filter(|s| s.state == "active" && !s.seat.trim().is_empty())
            .count();
        let remote = self
            .sessions
            .iter()
            .filter(|s| s.state == "active" && s.seat.trim().is_empty())
            .count();
        (seated, remote)
    }

    pub fn build_metrics_string(&self, prefix: &str) -> String {
        let (seated, remote) = self.count();
        let metric_seated = format!("{}_seated", prefix);
        let metric_remote = format!("{}_remote", prefix);
        format!(
            "# HELP {ms} Number of active login sessions with a seat\n\
             # TYPE {ms} gauge\n\
             {ms} {seated}\n\
             # HELP {mr} Number of active login sessions without a seat\n\
             # TYPE {mr} gauge\n\
             {mr} {remote}\n",
            ms = metric_seated,
            seated = seated,
            mr = metric_remote,
            remote = remote,
        )
    }
}

pub fn run_loginctl() -> Result<Sessions, String> {
    let output = Command::new("loginctl")
        .args(&[
            "list-sessions",
            "--no-pager",
            "--no-legend",
            "--full",
            "--output=json",
        ])
        .output()
        .map_err(|e| format!("Error executing loginctl: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("loginctl returned error: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sessions: Vec<Session> =
        serde_json::from_str(&stdout).map_err(|e| format!("Failed to parse JSON: {}", e))?;
    Ok(sessions.into())
}
