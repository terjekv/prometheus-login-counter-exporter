use crate::types::UserFilter;

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
    Windows(WindowsSession),
}


trait Scrape {
    fn scrape_sessions(user_filter: &UserFilter) -> Result<UnifiedSessions, String>;
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

#[derive(Debug, Clone)]
pub struct WindowsSession {
    pub user: String,
    pub terminal: String,
    pub host: Option<String>, // If set, indicates a remote session (e.g. from RDP)
}

impl From<WindowsSession> for UnifiedSession {
    fn from(ws: WindowsSession) -> Self {
        UnifiedSession {
            user: ws.user.clone(),
            terminal: ws.terminal.clone(),
            host: ws.host.clone(),
            source: SessionSource::Windows(ws),
        }
    }
}

impl Scrape for LoginctlSession {
    /// Runs loginctl and converts its JSON output into unified sessions.
    fn scrape_sessions(user_filter: &UserFilter) -> Result<UnifiedSessions, String> {
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
            .filter(|s| user_filter.keep(&s.user))
            .map(Into::into)
            .collect::<Vec<_>>()
            .into())
    }
}

impl Scrape for WhoSession {
    /// Runs `who` and converts its output into unified sessions.
    fn scrape_sessions(user_filter: &UserFilter) -> Result<UnifiedSessions, String> {
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
            .filter(|s| user_filter.keep(&s.user))
            .map(Into::into)
            .collect();
        Ok(sessions.into())
    }
}

/// Runs `query user` on Windows, applies a heuristic to detect remote sessions,
/// and converts the output into unified sessions.
impl Scrape for WindowsSession {
    fn scrape_sessions(user_filter: &UserFilter) -> Result<UnifiedSessions, String> {
        let output = Command::new("query")
            .args(&["user"])
            .output()
            .map_err(|e| format!("Error executing query user: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("query user returned error: {}", stderr));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut sessions = Vec::new();
        let mut lines = stdout.lines();

        // Skip the header line (e.g., "USERNAME  SESSIONNAME  ID  STATE  IDLE TIME  LOGON TIME")
        lines.next();

        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            // Split the line by whitespace.
            // Expected columns: USERNAME, SESSIONNAME, ID, STATE, IDLE TIME, LOGON TIME.
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let session = parse_query_user_line(line);
            if let Some(session) = session {
                if user_filter.keep(&session.user) {
                    sessions.push(session);
                } 
            }
        }

        Ok(sessions
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>()
            .into())
    }
}

fn parse_query_user_line(line: &str) -> Option<WindowsSession> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let user = parts[0].to_string();
    let terminal = parts[1].to_string();
    let active = parts[3].to_lowercase();
    if active != "active" {
        return None;
    }
    // If the terminal contains a '#' character, we consider it a remote session. These are usually
    // RDP sessions, where the terminal is in the form "rdp-tcp#5" or vmware-rds#0.
    let host = if terminal.contains("#") {
        Some("remote".to_string())
    } else {
        None
    };
    Some(WindowsSession {
        user,
        terminal,
        host,
    })
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
pub fn scrape_sessions(user_filter: &UserFilter) -> Result<UnifiedSessions, String> {
    #[cfg(target_os = "linux")]
    {
        LoginctlSession::scrape_sessions(&user_filter)
    }
    #[cfg(target_os = "macos")]
    {
        WhoSession::scrape_sessions(&user_filter)
    }
    #[cfg(target_os = "windows")]
    {
        WindowsSession::scrape_sessions(&user_filter)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err("Unsupported platform".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yare::parameterized;
    use serde_json;

    // --- Test for parsing a single line of `who` output ---
    #[parameterized(
        alice_session = { "alice    console    Feb  5 09:03", "alice", "console", None::<&str> },
        alice_remote  = { "alice    tty1       Feb 10 09:51 (test.host.com)", "alice", "tty1", Some("test.host.com") },
        bob_session   = { "bob      tty7       Feb 10 09:51 (192.168.1.100)", "bob", "tty7", Some("192.168.1.100") }
    )]
    fn test_parse_who_line(
        line: &str,
        expected_user: &str,
        expected_terminal: &str,
        expected_host: Option<&str>,
    ) {
        let session = parse_who_line(line).expect("Line should be parsed into WhoSession");
        assert_eq!(session.user, expected_user);
        assert_eq!(session.terminal, expected_terminal);
        match (session.host, expected_host) {
            (Some(host), Some(exp)) => assert_eq!(host, exp),
            (None, None) => {},
            (a, b) => panic!("Mismatched host: got {:?}, expected {:?}", a, b),
        }
    }

    // --- Test for converting Loginctl JSON output to UnifiedSession ---
    #[parameterized(
        session_remote = { 
            r#"[{"session": "1", "uid": 1000, "user": "alice", "seat": "", "tty": "tty1", "state": "active", "idle": false, "since": null}]"#, 
            "alice", 
            Some("remote")
        },
        session_local = { 
            r#"[{"session": "2", "uid": 1001, "user": "bob", "seat": "seat0", "tty": "tty2", "state": "active", "idle": false, "since": null}]"#, 
            "bob", 
            None::<&str>
        }
    )]
    fn test_loginctl_to_unified(json_input: &str, expected_user: &str, expected_host: Option<&str>) {
        let sessions: Vec<LoginctlSession> = serde_json::from_str(json_input)
            .expect("JSON should parse into LoginctlSession vector");
        let unified: Vec<UnifiedSession> = sessions.into_iter().map(Into::into).collect();
        assert_eq!(unified.len(), 1);
        let session = &unified[0];
        assert_eq!(session.user, expected_user);
        match (&session.host, expected_host) {
            (Some(h), Some(exp)) => assert_eq!(h, exp),
            (None, None) => {},
            (a, b) => panic!("Mismatched host: got {:?}, expected {:?}", a, b),
        }
    }

    // --- Test for WindowsSession parsing using the heuristic for remote sessions ---
    #[parameterized(
        remote_session = { "john rdp-tcp#5 2 Active 2:15 9/14/2021 8:00AM", "john", "rdp-tcp#5", Some("remote") },
        remote_vmware_session = { "jane vmware-rds#0 3 Active 0 9/14/2021 7:50AM", "jane", "vmware-rds#0", Some("remote") },
        local_session  = { "jane console 3 Active 0 9/14/2021 7:50AM", "jane", "console", None::<&str> }
    )]
    fn test_windows_session_parsing(
        line: &str,
        expected_user: &str,
        expected_terminal: &str,
        expected_host: Option<&str>,
    ) {
        let session = parse_query_user_line(line).expect("Line should be parsed into WindowsSession");
        assert_eq!(session.user, expected_user);
        assert_eq!(session.terminal, expected_terminal);
        match (&session.host, expected_host) {
            (Some(h), Some(exp)) => assert_eq!(h, &exp.to_string()),
            (None, None) => {},
            (a, b) => panic!("Mismatched host: got {:?}, expected {:?}", a, b),
        }
    }

    // --- Test the aggregation logic in UnifiedSessions ---
    #[test]
    fn test_aggregate_unified_sessions() {
        let sessions = vec![
            UnifiedSession {
                user: "alice".to_string(),
                terminal: "console".to_string(),
                host: None,
                source: SessionSource::Who(WhoSession {
                    user: "alice".to_string(),
                    terminal: "console".to_string(),
                    host: None,
                }),
            },
            UnifiedSession {
                user: "bob".to_string(),
                terminal: "rdp-tcp#1".to_string(),
                host: Some("remote".to_string()),
                source: SessionSource::Windows(WindowsSession {
                    user: "bob".to_string(),
                    terminal: "rdp-tcp#1".to_string(),
                    host: Some("remote".to_string()),
                }),
            },
            // Duplicate user (alice appears twice but with different terminals)
            UnifiedSession {
                user: "alice".to_string(),
                terminal: "console2".to_string(),
                host: None,
                source: SessionSource::Who(WhoSession {
                    user: "alice".to_string(),
                    terminal: "console2".to_string(),
                    host: None,
                }),
            },
        ];
        let unified_sessions = UnifiedSessions { sessions };

        // Raw count: local should count 2 sessions (alice appears twice), remote 1 session.
        let (local_raw, remote_raw) = unified_sessions.count_sessions();
        assert_eq!(local_raw, 2);
        assert_eq!(remote_raw, 1);

        // Unique user count: local should count 1 unique user (alice), remote 1 unique user (bob).
        let (local_unique, remote_unique) = unified_sessions.count_unique_users();
        assert_eq!(local_unique, 1);
        assert_eq!(remote_unique, 1);
    }
}
