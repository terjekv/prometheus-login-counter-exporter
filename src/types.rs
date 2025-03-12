use regex::Regex;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct UserFilter {
    fixed: Vec<String>,
    regex: Vec<Regex>,
}

impl UserFilter {
    pub fn new(fixed: Vec<String>, regex: Vec<Regex>) -> Self {
        UserFilter { fixed, regex }
    }

    pub fn ignore(&self, user: &str) -> bool {
        if self.fixed.contains(&user.to_string()) {
            debug!(
                "Ignoring user '{}', explicit ignore from '{:?}.",
                user, self.fixed
            );
            return true;
        } else if self.regex.iter().any(|re| re.is_match(user)) {
            debug!(
                "Ignoring user '{}', matched regex '{:?}'.",
                user, self.regex
            );
            return true;
        } else {
            return false;
        }
    }

    pub fn keep(&self, user: &str) -> bool {
        !self.ignore(user)
    }
}

#[cfg(test)]

mod test {
    use super::*;
    use yare::parameterized;

    #[parameterized(
        root_ok = { "root", true },
        gdm_ok = { "gdm", true },
        adm_false = { "adm", false },
        rootadm_false = { "rootadm", false },
        rootdashadm_false = { "root-adm", true },
    )]
    fn test_user_filter(user: &str, ok: bool) {
        let fixed = vec!["root".to_string(), "gdm".to_string()];
        let regex = vec![Regex::new(r"-adm$").unwrap()];
        let filter = UserFilter::new(fixed, regex);

        assert_eq!(filter.ignore(user), ok);
    }
}
