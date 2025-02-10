use std::process::Command;

use serde::Deserialize;
use std::collections::HashSet;
use std::hash::Hash;

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
    /// Generic aggregator that applies a list of filters before mapping sessions.
    ///
    /// - `filters`: a slice of functions that each take a reference to a Session and return a bool.
    ///   A session passes if *all* filters return true.
    /// - `mapper`: a function that maps a session to some value `T` (e.g. the user name).
    /// - `unique`: if true, the mapped values are deduplicated (using a HashSet) before counting.
    ///
    /// The method returns a tuple `(seated_count, remote_count)`, where "seated"
    /// means the session’s `seat` is non‑empty, and "remote" means the session’s `seat` is empty.
    fn aggregate_with_filters<T>(
        &self,
        filters: &[&dyn Fn(&Session) -> bool],
        mapper: impl Fn(&Session) -> T,
        unique: bool,
    ) -> (usize, usize)
    where
        T: Clone + Eq + Hash,
    {
        // A session passes if all filters return true.
        let passes_filters = |s: &Session| filters.iter().all(|f| f(s));

        let seated_iter = self
            .sessions
            .iter()
            .filter(|s| passes_filters(s) && !s.seat.trim().is_empty())
            .map(|s| mapper(s));
        let remote_iter = self
            .sessions
            .iter()
            .filter(|s| passes_filters(s) && s.seat.trim().is_empty())
            .map(|s| mapper(s));

        if unique {
            let seated = seated_iter.collect::<HashSet<_>>().len();
            let remote = remote_iter.collect::<HashSet<_>>().len();
            (seated, remote)
        } else {
            let seated = seated_iter.count();
            let remote = remote_iter.count();
            (seated, remote)
        }
    }

    /// Count sessions that satisfy a list of filters.
    /// Here we want raw (non‑unique) counts, so we simply ignore mapping (using the unit value).
    pub fn count(&self) -> (usize, usize) {
        // In this example we always filter for active sessions.
        self.aggregate_with_filters(&[&|s: &Session| s.state == "active"], |_| (), false)
    }

    /// Count sessions uniquely by user.
    /// This maps each session to its user name and then counts unique names.
    pub fn count_unique(&self) -> (usize, usize) {
        self.aggregate_with_filters(
            &[&|s: &Session| s.state == "active"],
            |s| s.user.clone(),
            true,
        )
    }

    /// Build the Prometheus metrics string.
    ///
    /// The `allow_duplicates` parameter selects whether to count duplicated sessions per
    /// user or to only count one session per type per user.
    pub fn build_metrics_string(&self, prefix: &str, unique: bool) -> String {
        // Get the counts (either raw or unique, based on the flag)
        let (seated, remote) = if unique {
            self.count_unique()
        } else {
            self.count()
        };
        // Construct the metric name—here we use a single metric named `<prefix>_sessions`
        let metric_name = format!("{}_sessions", prefix);
        format!(
            "# HELP {metric_name} Number of active login sessions\n\
             # TYPE {metric_name} gauge\n\
             {metric_name}{{type=\"seated\"}} {seated}\n\
             {metric_name}{{type=\"remote\"}} {remote}\n",
            metric_name = metric_name,
            seated = seated,
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
