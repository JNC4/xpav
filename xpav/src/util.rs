//! Common utility functions shared across modules.

/// Parse a field from /proc/[pid]/status content.
///
/// The status file contains lines like "PPid:\t123" or "Uid:\t1000\t1000\t1000\t1000".
/// This function extracts the first numeric value after the field name.
pub fn parse_status_field(status: &str, field: &str) -> Option<u32> {
    for line in status.lines() {
        if line.starts_with(field) {
            return line.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_status_field_ppid() {
        let status = "Name:\ttest\nPPid:\t1234\nUid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_status_field(status, "PPid:"), Some(1234));
    }

    #[test]
    fn test_parse_status_field_uid() {
        let status = "Name:\ttest\nPPid:\t1234\nUid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_status_field(status, "Uid:"), Some(1000));
    }

    #[test]
    fn test_parse_status_field_missing() {
        let status = "Name:\ttest\nPPid:\t1234\n";
        assert_eq!(parse_status_field(status, "Uid:"), None);
    }

    #[test]
    fn test_parse_status_field_empty() {
        assert_eq!(parse_status_field("", "PPid:"), None);
    }
}
