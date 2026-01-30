//! Unit tests for webshell scanner.

use xpav::scanner::webshell::{WebshellScanner, WebshellLanguage, ThreatLevel};
use std::path::Path;

fn scanner() -> WebshellScanner {
    WebshellScanner::new(50)
}

// PHP Tests
#[test]
fn test_php_clean_code() {
    let s = scanner();
    let result = s.scan(r#"<?php echo "Hello, World!"; ?>"#);
    assert_eq!(result.threat_level, ThreatLevel::Clean);
    assert!(!result.is_malicious);
}

#[test]
fn test_php_eval_get() {
    let s = scanner();
    let result = s.scan(r#"<?php eval($_GET['cmd']); ?>"#);
    assert!(result.is_malicious);
    assert_eq!(result.threat_level, ThreatLevel::Malicious);
}

#[test]
fn test_php_system_post() {
    let s = scanner();
    let result = s.scan(r#"<?php system($_POST['cmd']); ?>"#);
    assert!(result.is_malicious);
}

#[test]
fn test_php_base64_eval() {
    let s = scanner();
    let result = s.scan(r#"<?php eval(base64_decode('ZWNobyAiaGVsbG8iOw==')); ?>"#);
    assert!(result.is_malicious);
}

// JSP Tests
#[test]
fn test_jsp_clean_code() {
    let s = scanner();
    let result = s.scan_jsp(r#"<% out.println("Hello World"); %>"#);
    assert_eq!(result.threat_level, ThreatLevel::Clean);
    assert!(!result.is_malicious);
}

#[test]
fn test_jsp_runtime_exec() {
    let s = scanner();
    let result = s.scan_jsp(r#"<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>"#);
    assert!(result.is_malicious);
}

// ASP.NET Tests
#[test]
fn test_asp_clean_code() {
    let s = scanner();
    let result = s.scan_asp(r#"<% Response.Write("Hello"); %>"#);
    assert_eq!(result.threat_level, ThreatLevel::Clean);
    assert!(!result.is_malicious);
}

#[test]
fn test_asp_process_start() {
    let s = scanner();
    let result = s.scan_asp(r#"<% Process.Start(Request["cmd"]); %>"#);
    assert!(result.is_malicious);
}

// Python Tests
#[test]
fn test_python_clean_code() {
    let s = scanner();
    let result = s.scan_python(r#"print("Hello World")"#);
    assert_eq!(result.threat_level, ThreatLevel::Clean);
    assert!(!result.is_malicious);
}

#[test]
fn test_python_os_system() {
    let s = scanner();
    let result = s.scan_python(r#"os.system(request.form['cmd'])"#);
    assert!(result.is_malicious);
}

#[test]
fn test_python_subprocess() {
    let s = scanner();
    let result = s.scan_python(r#"subprocess.call(request.args['cmd'], shell=True)"#);
    assert!(result.is_malicious);
}

// Language Detection Tests
#[test]
fn test_language_detection() {
    assert_eq!(
        WebshellScanner::should_scan_language(Path::new("test.php")),
        Some(WebshellLanguage::Php)
    );
    assert_eq!(
        WebshellScanner::should_scan_language(Path::new("test.phtml")),
        Some(WebshellLanguage::Php)
    );
    assert_eq!(
        WebshellScanner::should_scan_language(Path::new("test.jsp")),
        Some(WebshellLanguage::Jsp)
    );
    assert_eq!(
        WebshellScanner::should_scan_language(Path::new("test.jspx")),
        Some(WebshellLanguage::Jsp)
    );
    assert_eq!(
        WebshellScanner::should_scan_language(Path::new("test.aspx")),
        Some(WebshellLanguage::AspNet)
    );
    assert_eq!(
        WebshellScanner::should_scan_language(Path::new("test.ashx")),
        Some(WebshellLanguage::AspNet)
    );
    assert_eq!(
        WebshellScanner::should_scan_language(Path::new("test.py")),
        Some(WebshellLanguage::Python)
    );
    assert_eq!(
        WebshellScanner::should_scan_language(Path::new("test.txt")),
        None
    );
}

#[test]
fn test_should_scan_backwards_compat() {
    assert!(WebshellScanner::should_scan(Path::new("test.php")));
    assert!(WebshellScanner::should_scan(Path::new("test.jsp")));
    assert!(WebshellScanner::should_scan(Path::new("test.aspx")));
    assert!(WebshellScanner::should_scan(Path::new("test.py")));
    assert!(!WebshellScanner::should_scan(Path::new("test.txt")));
}
