// metrics.rs

use serde::Deserialize;
use std::collections::HashSet;
use std::hash::Hash;
use std::process::Command;

/// An enum that holds the full original data of a session.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SessionSource {
    Loginctl(LoginctlSession),
    Who(WhoSession),
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct LoginctlSession {
    pub session: String,
    pub uid: u64,
    pub user: String,
    pub seat: String,
    pub tty: String,
    pub state: String,
    pub idle: bool,
    pub since: Option<u64>,
}

trait Scrape {
    fn scrape_sessions(users_to_ignore: Vec<String>) -> Result<UnifiedSessions, String>;
}

impl From<LoginctlSession> for UnifiedSession {
    fn from(ls: LoginctlSession) -> Self {
        UnifiedSession {
            user: ls.user.clone(),
            terminal: ls.tty.clone(),
            // If the seat field is empty, assume the session is remote.
            host: if ls.seat.trim().is_empty() {
                Some(String::from("remote"))
            } else {
                None
            },
            source: SessionSource::Loginctl(ls),
        }
    }
}

/// A simplified representation of a session as reported by `who`.
#[derive(Debug, Clone)]
pub struct WhoSession {
    pub user: String,
    pub terminal: String,
    /// If present, this field is parsed from a parenthesized token (e.g. an IP address).
    pub host: Option<String>,
}

impl From<WhoSession> for UnifiedSession {
    fn from(ws: WhoSession) -> Self {
        UnifiedSession {
            user: ws.user.clone(),
            terminal: ws.terminal.clone(),
            host: ws.host.clone(),
            source: SessionSource::Who(ws),
        }
    }
}

impl Scrape for LoginctlSession {
    /// Runs loginctl and converts its JSON output into unified sessions.
    fn scrape_sessions(users_to_ignore: Vec<String>) -> Result<UnifiedSessions, String> {
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
        let sessions: Vec<LoginctlSession> = serde_json::from_str(&stdout)
            .map_err(|e| format!("Failed to parse JSON from loginctl: {}", e))?;
        // Convert each LoginctlSession into a UnifiedSession.

        Ok(sessions
            .into_iter()
            .filter(|s| !users_to_ignore.contains(&s.user))
            .map(Into::into)
            .collect::<Vec<_>>()
            .into())
    }
}

impl Scrape for WhoSession {
    /// Runs `who` and converts its output into unified sessions.
    fn scrape_sessions(users_to_ignore: Vec<String>) -> Result<UnifiedSessions, String> {
        let output = Command::new("who")
            .output()
            .map_err(|e| format!("Error executing who: {}", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("who returned error: {}", stderr));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let sessions: Vec<_> = stdout
            .lines()
            .filter_map(|line| parse_who_line(line))
            .filter(|s| !users_to_ignore.contains(&s.user))
            .map(Into::into)
            .collect();
        Ok(sessions.into())
    }
}

/// Parses one line from `who` output.
/// Expected format (simplistic):
///   user          ttys018      Feb 10 09:51 (192.168.1.100)
/// or:
///   user          console      Feb  5 09:03
fn parse_who_line(line: &str) -> Option<WhoSession> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let user = parts[0].to_string();
    let terminal = parts[1].to_string();
    // Look for a token that starts with '(' and ends with ')'
    let host = parts.iter().find_map(|token| {
        if token.starts_with('(') && token.ends_with(')') {
            Some(token.trim_matches(|c| c == '(' || c == ')').to_string())
        } else {
            None
        }
    });
    Some(WhoSession {
        user,
        terminal,
        host,
    })
}

/// A unified representation of a login session.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UnifiedSession {
    pub user: String,
    /// The terminal (or TTY) associated with the session.
    pub terminal: String,
    /// If present, indicates a remote session (for example, an IP address or hostname).
    pub host: Option<String>,
    /// The full original session data.
    pub source: SessionSource,
}

impl UnifiedSession {
    /// Returns true if the session is considered remote.
    /// For our unified model, if `host` is set then we consider the session remote.
    pub fn is_remote(&self) -> bool {
        self.host.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct UnifiedSessions {
    pub sessions: Vec<UnifiedSession>,
}

impl From<Vec<UnifiedSession>> for UnifiedSessions {
    fn from(sessions: Vec<UnifiedSession>) -> Self {
        UnifiedSessions { sessions }
    }
}

impl UnifiedSessions {
    /// Count all sessions (raw count) from the unified sessions.
    pub fn count_sessions(&self) -> (usize, usize) {
        self.aggregate_unified(|_| (), false)
    }

    /// Count unique sessions by user.
    pub fn count_unique_users(&self) -> (usize, usize) {
        self.aggregate_unified(|s| s.user.clone(), true)
    }

    pub fn build_metrics_string(&self, prefix: &str, allow_duplicates: bool) -> String {
        let (local, remote) = if allow_duplicates {
            self.count_sessions()
        } else {
            self.count_unique_users()
        };
        let metric_name = format!("{}_sessions", prefix);
        format!(
            "# HELP {metric_name} Number of active login sessions\n\
            # TYPE {metric_name} gauge\n\
            {metric_name}{{type=\"local\"}} {local}\n\
            {metric_name}{{type=\"remote\"}} {remote}\n",
            metric_name = metric_name,
            local = local,
            remote = remote,
        )
    }

    /// Generic aggregator that applies a mapper to each unified session and counts local and remote sessions.
    /// If `unique` is true, the mapped values are deduplicated before counting.
    fn aggregate_unified<T>(
        &self,
        mapper: impl Fn(&UnifiedSession) -> T,
        unique: bool,
    ) -> (usize, usize)
    where
        T: Clone + Eq + Hash,
    {
        let local_iter = self
            .sessions
            .iter()
            .filter(|s| !s.is_remote())
            .map(|s| mapper(s));
        let remote_iter = self
            .sessions
            .iter()
            .filter(|s| s.is_remote())
            .map(|s| mapper(s));

        if unique {
            let local = local_iter.collect::<HashSet<T>>().len();
            let remote = remote_iter.collect::<HashSet<T>>().len();
            (local, remote)
        } else {
            let local = local_iter.count();
            let remote = remote_iter.count();
            (local, remote)
        }
    }
}

//
// Public scraper function that dispatches to the correct platform implementation.
//
pub fn scrape_sessions(users_to_ignore: Vec<String>) -> Result<UnifiedSessions, String> {
    #[cfg(target_os = "linux")]
    {
        LoginctlSession::scrape_sessions(users_to_ignore)
    }
    #[cfg(target_os = "macos")]
    {
        WhoSession::scrape_sessions(users_to_ignore)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err("Unsupported platform".to_string())
    }
}
