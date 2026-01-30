//! Detects PHP webshells via pattern matching and obfuscation scoring.

use regex::Regex;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct WebshellScanResult {
    pub is_malicious: bool,
    pub threat_level: ThreatLevel,
    pub detections: Vec<Detection>,
    pub obfuscation_score: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatLevel {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub category: DetectionCategory,
    pub pattern: String,
    pub description: String,
    pub line_number: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionCategory {
    InputEvalChain,
    DecodeChain,
    KnownSignature,
    Obfuscation,
    SuspiciousFunction,
    DynamicExecution,
}

pub struct WebshellScanner {
    input_eval_patterns: Vec<CompiledPattern>,
    decode_chain_patterns: Vec<CompiledPattern>,
    known_signatures: Vec<CompiledPattern>,
    suspicious_functions: Vec<CompiledPattern>,
    dynamic_execution_patterns: Vec<CompiledPattern>,
    obfuscation_threshold: u32,
    hex_pattern: Regex,
    chr_chain: Regex,
    base64_like: Regex,
    concat_abuse: Regex,
    var_var: Regex,
}

struct CompiledPattern {
    regex: Regex,
    description: String,
    category: DetectionCategory,
}

impl Default for WebshellScanner {
    fn default() -> Self {
        Self::new(50) // Default obfuscation threshold
    }
}

impl WebshellScanner {
    pub fn new(obfuscation_threshold: u32) -> Self {
        Self {
            input_eval_patterns: compile_input_eval_patterns(),
            decode_chain_patterns: compile_decode_chain_patterns(),
            known_signatures: compile_known_signatures(),
            suspicious_functions: compile_suspicious_functions(),
            dynamic_execution_patterns: compile_dynamic_execution_patterns(),
            obfuscation_threshold,
            hex_pattern: Regex::new(r"(?:\\x[0-9a-fA-F]{2}){4,}").unwrap(),
            chr_chain: Regex::new(r"chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)").unwrap(),
            base64_like: Regex::new(r#"['"][A-Za-z0-9+/=]{50,}['"]"#).unwrap(),
            concat_abuse: Regex::new(r#"\.\s*['"][^'"]{1,3}['"]\s*\."#).unwrap(),
            var_var: Regex::new(r"\$\$[a-zA-Z_]").unwrap(),
        }
    }

    pub fn should_scan(path: &Path) -> bool {
        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        matches!(
            extension.to_lowercase().as_str(),
            "php" | "phtml" | "php3" | "php4" | "php5" | "php7" | "phps" | "phar" | "inc"
        )
    }

    fn strip_inline_comments(content: &str) -> String {
        let comment_re = Regex::new(r"/\*.*?\*/").unwrap();
        comment_re.replace_all(content, "").to_string()
    }

    pub fn scan(&self, content: &str) -> WebshellScanResult {
        let mut detections = Vec::new();
        let mut obfuscation_score = 0;

        // Strip /* comments */ to catch evasion like ev/**/al()
        let stripped = if content.contains("/*") {
            Some(Self::strip_inline_comments(content))
        } else {
            None
        };

        let match_any = |pattern: &CompiledPattern| -> Option<(String, Option<usize>)> {
            if let Some(captures) = pattern.regex.captures(content) {
                let matched = captures.get(0).map(|m| m.as_str().to_string()).unwrap_or_default();
                let line = find_line_number(content, captures.get(0).map(|m| m.start()));
                return Some((matched, line));
            }
            if let Some(ref stripped) = stripped {
                if let Some(captures) = pattern.regex.captures(stripped) {
                    let matched = captures.get(0).map(|m| m.as_str().to_string()).unwrap_or_default();
                    let line = find_line_number(stripped, captures.get(0).map(|m| m.start()));
                    return Some((matched, line));
                }
            }
            None
        };

        for pattern in &self.input_eval_patterns {
            if let Some((matched, line)) = match_any(pattern) {
                detections.push(Detection {
                    category: pattern.category,
                    pattern: matched,
                    description: pattern.description.clone(),
                    line_number: line,
                });
            }
        }

        for pattern in &self.decode_chain_patterns {
            if let Some((matched, line)) = match_any(pattern) {
                detections.push(Detection {
                    category: pattern.category,
                    pattern: matched,
                    description: pattern.description.clone(),
                    line_number: line,
                });
            }
        }

        for pattern in &self.known_signatures {
            if let Some((matched, line)) = match_any(pattern) {
                detections.push(Detection {
                    category: pattern.category,
                    pattern: matched,
                    description: pattern.description.clone(),
                    line_number: line,
                });
            }
        }

        for pattern in &self.suspicious_functions {
            let mut found_in_original = false;
            for captures in pattern.regex.captures_iter(content) {
                found_in_original = true;
                detections.push(Detection {
                    category: pattern.category,
                    pattern: captures.get(0).map(|m| m.as_str().to_string()).unwrap_or_default(),
                    description: pattern.description.clone(),
                    line_number: find_line_number(content, captures.get(0).map(|m| m.start())),
                });
            }
            if !found_in_original {
                if let Some(ref stripped) = stripped {
                    for captures in pattern.regex.captures_iter(stripped) {
                        detections.push(Detection {
                            category: pattern.category,
                            pattern: captures.get(0).map(|m| m.as_str().to_string()).unwrap_or_default(),
                            description: pattern.description.clone(),
                            line_number: find_line_number(stripped, captures.get(0).map(|m| m.start())),
                        });
                    }
                }
            }
        }

        for pattern in &self.dynamic_execution_patterns {
            if let Some((matched, line)) = match_any(pattern) {
                detections.push(Detection {
                    category: pattern.category,
                    pattern: matched,
                    description: pattern.description.clone(),
                    line_number: line,
                });
            }
        }

        obfuscation_score += self.calculate_obfuscation_score(content);

        let threat_level = self.determine_threat_level(&detections, obfuscation_score);
        let is_malicious = threat_level == ThreatLevel::Malicious
            || (threat_level == ThreatLevel::Suspicious && obfuscation_score >= self.obfuscation_threshold);

        WebshellScanResult {
            is_malicious,
            threat_level,
            detections,
            obfuscation_score,
        }
    }

    fn calculate_obfuscation_score(&self, content: &str) -> u32 {
        let mut score = 0u32;

        score += self.hex_pattern.find_iter(content).count() as u32 * 10;
        score += self.chr_chain.find_iter(content).count() as u32 * 15;
        score += self.base64_like.find_iter(content).count() as u32 * 5;
        score += self.var_var.find_iter(content).count() as u32 * 5;

        let concat_count = self.concat_abuse.find_iter(content).count();
        if concat_count > 10 {
            score += (concat_count as u32 - 10) * 2;
        }

        for line in content.lines() {
            if line.len() > 5000 { score += 20; }
            else if line.len() > 1000 { score += 10; }
            else if line.len() > 500 { score += 5; }
        }

        if content.contains("eval(gzinflate(") || content.contains("eval(gzuncompress(") {
            score += 30;
        }

        if content.contains("str_rot13") && content.contains("base64_decode") {
            score += 25;
        }

        score
    }

    fn determine_threat_level(&self, detections: &[Detection], obfuscation_score: u32) -> ThreatLevel {
        if detections.iter().any(|d| d.category == DetectionCategory::KnownSignature) {
            return ThreatLevel::Malicious;
        }

        if detections.iter().any(|d| d.category == DetectionCategory::InputEvalChain) {
            return ThreatLevel::Malicious;
        }

        if detections.iter().any(|d| d.category == DetectionCategory::DecodeChain) {
            return ThreatLevel::Malicious;
        }

        if detections.iter().any(|d| d.category == DetectionCategory::DynamicExecution) {
            return ThreatLevel::Malicious;
        }

        if obfuscation_score >= self.obfuscation_threshold {
            if detections.iter().any(|d| d.category == DetectionCategory::SuspiciousFunction) {
                return ThreatLevel::Suspicious;
            }
        }

        let suspicious_count = detections
            .iter()
            .filter(|d| d.category == DetectionCategory::SuspiciousFunction)
            .count();
        if suspicious_count >= 3 {
            return ThreatLevel::Suspicious;
        }

        if obfuscation_score >= self.obfuscation_threshold * 2 {
            return ThreatLevel::Suspicious;
        }

        ThreatLevel::Clean
    }
}

fn find_line_number(content: &str, offset: Option<usize>) -> Option<usize> {
    let offset = offset?;
    Some(content[..offset].lines().count() + 1)
}

fn compile_input_eval_patterns() -> Vec<CompiledPattern> {
    vec![
        // $_GET/$_POST/$_REQUEST → eval/system/exec/shell_exec/passthru
        CompiledPattern {
            regex: Regex::new(r#"(?i)\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\].*?(eval|system|exec|shell_exec|passthru|popen|proc_open)\s*\("#).unwrap(),
            description: "User input directly passed to code execution function".to_string(),
            category: DetectionCategory::InputEvalChain,
        },
        // eval($_GET/POST/REQUEST) - eval/assert with direct user input
        CompiledPattern {
            regex: Regex::new(r#"(?i)(eval|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"#).unwrap(),
            description: "Direct eval of user input".to_string(),
            category: DetectionCategory::InputEvalChain,
        },
        // system/exec/shell_exec/passthru($_GET/POST/REQUEST) - shell functions with user input
        CompiledPattern {
            regex: Regex::new(r#"(?i)(system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"#).unwrap(),
            description: "Shell command execution with user input".to_string(),
            category: DetectionCategory::InputEvalChain,
        },
        // preg_replace with /e modifier - fixed to match actual pattern
        // Matches: preg_replace('/.*/e', $_GET['x'], '')
        CompiledPattern {
            regex: Regex::new(r#"(?i)preg_replace\s*\(\s*['"/][^'"]*e[^'"]*['"],\s*\$_(GET|POST|REQUEST|COOKIE)"#).unwrap(),
            description: "preg_replace with /e modifier using user input".to_string(),
            category: DetectionCategory::InputEvalChain,
        },
        // preg_replace with /e and any user input in arguments
        CompiledPattern {
            regex: Regex::new(r#"(?i)preg_replace\s*\(\s*['"/][^'"]*e[imsxeADSUXJu]*['"][^)]*\$_(GET|POST|REQUEST|COOKIE)"#).unwrap(),
            description: "preg_replace /e with user input in replacement".to_string(),
            category: DetectionCategory::InputEvalChain,
        },
        // create_function with user input
        CompiledPattern {
            regex: Regex::new(r#"(?i)create_function\s*\([^)]*\$_(GET|POST|REQUEST)"#).unwrap(),
            description: "create_function with user input".to_string(),
            category: DetectionCategory::InputEvalChain,
        },
        // call_user_func with user-controlled function
        CompiledPattern {
            regex: Regex::new(r#"(?i)call_user_func(_array)?\s*\(\s*\$_(GET|POST|REQUEST)"#).unwrap(),
            description: "call_user_func with user-controlled function name".to_string(),
            category: DetectionCategory::InputEvalChain,
        },
        // Dynamic function call: $var() with user input
        CompiledPattern {
            regex: Regex::new(r#"(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*\$_(GET|POST|REQUEST).*?\$[a-zA-Z_][a-zA-Z0-9_]*\s*\("#).unwrap(),
            description: "Dynamic function call from user input".to_string(),
            category: DetectionCategory::InputEvalChain,
        },
        // Variable function call $var() when file contains user input
        // This catches: $a = 'eval'; $a($_GET['x']);
        CompiledPattern {
            regex: Regex::new(r#"(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"#).unwrap(),
            description: "Variable function call with user input".to_string(),
            category: DetectionCategory::InputEvalChain,
        },
    ]
}

fn compile_decode_chain_patterns() -> Vec<CompiledPattern> {
    vec![
        // base64_decode → eval
        CompiledPattern {
            regex: Regex::new(r#"(?i)(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\("#).unwrap(),
            description: "Encoded payload with code execution".to_string(),
            category: DetectionCategory::DecodeChain,
        },
        // Nested decode chains
        CompiledPattern {
            regex: Regex::new(r#"(?i)(eval|assert)\s*\([^;]*?(base64_decode|gzinflate|gzuncompress)[^;]*(base64_decode|gzinflate|gzuncompress)"#).unwrap(),
            description: "Multiple decode layers before code execution".to_string(),
            category: DetectionCategory::DecodeChain,
        },
        // eval(gzinflate(base64_decode(...)))
        CompiledPattern {
            regex: Regex::new(r#"(?i)eval\s*\(\s*gzinflate\s*\(\s*base64_decode"#).unwrap(),
            description: "Classic packed webshell pattern".to_string(),
            category: DetectionCategory::DecodeChain,
        },
        // str_rot13(base64_decode(...)) chain
        CompiledPattern {
            regex: Regex::new(r#"(?i)(eval|assert)\s*\([^;]*str_rot13\s*\([^;]*base64_decode"#).unwrap(),
            description: "ROT13 + Base64 obfuscation chain".to_string(),
            category: DetectionCategory::DecodeChain,
        },
    ]
}

fn compile_known_signatures() -> Vec<CompiledPattern> {
    vec![
        // c99 shell
        CompiledPattern {
            regex: Regex::new(r#"(?i)(c99shell|c99_buff_prepare|c99ftpbrutecheck|c99gensort|c99sh_)"#).unwrap(),
            description: "c99 webshell signature".to_string(),
            category: DetectionCategory::KnownSignature,
        },
        // r57 shell
        CompiledPattern {
            regex: Regex::new(r#"(?i)(r57shell|r57_|r57genpass|r57teleport)"#).unwrap(),
            description: "r57 webshell signature".to_string(),
            category: DetectionCategory::KnownSignature,
        },
        // b374k shell
        CompiledPattern {
            regex: Regex::new(r#"(?i)(b374k|b374k_)"#).unwrap(),
            description: "b374k webshell signature".to_string(),
            category: DetectionCategory::KnownSignature,
        },
        // WSO shell
        CompiledPattern {
            regex: Regex::new(r#"(?i)(WSO\s+\d|wso_version|FilesMan)"#).unwrap(),
            description: "WSO webshell signature".to_string(),
            category: DetectionCategory::KnownSignature,
        },
        // China Chopper
        CompiledPattern {
            regex: Regex::new(r#"(?i)@?eval\s*\(\s*\$_(POST|GET|REQUEST)\s*\[\s*['"]\w{1,4}['"]\s*\]\s*\)"#).unwrap(),
            description: "China Chopper webshell pattern".to_string(),
            category: DetectionCategory::KnownSignature,
        },
        // Weevely shell
        CompiledPattern {
            regex: Regex::new(r#"(?i)\$\w=\$\w\(\$\w,\$\w\(\$\w\)\);\$\w\(\);"#).unwrap(),
            description: "Weevely webshell signature".to_string(),
            category: DetectionCategory::KnownSignature,
        },
        // Backdoor/c99/r57 common strings
        CompiledPattern {
            regex: Regex::new(r#"(?i)(Safe\s*mode|FilesMan|Perl\s*script|phpinfo\(\)|self\s*remove|sql\s*manager)"#).unwrap(),
            description: "Common webshell feature string".to_string(),
            category: DetectionCategory::KnownSignature,
        },
        // Known webshell MD5/SHA hashes in code (detection evasion attempt)
        CompiledPattern {
            regex: Regex::new(r#"(?i)md5\s*\(\s*['"](pass|password|pwd|auth)['"]\s*\)"#).unwrap(),
            description: "Webshell authentication pattern".to_string(),
            category: DetectionCategory::KnownSignature,
        },
    ]
}

fn compile_suspicious_functions() -> Vec<CompiledPattern> {
    vec![
        CompiledPattern {
            regex: Regex::new(r#"(?i)\b(eval|assert)\s*\("#).unwrap(),
            description: "Code execution function".to_string(),
            category: DetectionCategory::SuspiciousFunction,
        },
        CompiledPattern {
            regex: Regex::new(r#"(?i)\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\("#).unwrap(),
            description: "Shell command execution function".to_string(),
            category: DetectionCategory::SuspiciousFunction,
        },
        CompiledPattern {
            regex: Regex::new(r#"(?i)\bpcntl_(exec|fork)\s*\("#).unwrap(),
            description: "Process control function".to_string(),
            category: DetectionCategory::SuspiciousFunction,
        },
        CompiledPattern {
            regex: Regex::new(r#"(?i)\b(include|require)(_once)?\s*\(\s*\$"#).unwrap(),
            description: "Dynamic file inclusion".to_string(),
            category: DetectionCategory::SuspiciousFunction,
        },
        CompiledPattern {
            regex: Regex::new(r#"(?i)\bpreg_replace\s*\([^)]*['"]/[^'"]*e[^'"]*['"]\s*,"#).unwrap(),
            description: "preg_replace with /e modifier".to_string(),
            category: DetectionCategory::SuspiciousFunction,
        },
        CompiledPattern {
            regex: Regex::new(r#"(?i)\bcreate_function\s*\("#).unwrap(),
            description: "Dynamic function creation".to_string(),
            category: DetectionCategory::SuspiciousFunction,
        },
        CompiledPattern {
            regex: Regex::new(r#"(?i)\b(file_get_contents|file_put_contents|fwrite)\s*\([^)]*https?://"#).unwrap(),
            description: "Remote file operation".to_string(),
            category: DetectionCategory::SuspiciousFunction,
        },
        CompiledPattern {
            regex: Regex::new(r#"(?i)\bmove_uploaded_file\s*\("#).unwrap(),
            description: "File upload handling".to_string(),
            category: DetectionCategory::SuspiciousFunction,
        },
    ]
}

/// Patterns for detecting obfuscation-based dynamic code execution
/// These catch evasion techniques like string concatenation to build function names
fn compile_dynamic_execution_patterns() -> Vec<CompiledPattern> {
    vec![
        // String concatenation to build function name, then call with user input
        // Catches: $a='ev'.'al'; $a($_GET['c']);
        CompiledPattern {
            regex: Regex::new(r#"(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*['"][a-z]{2,4}['"]\s*\.\s*['"][a-z]{2,6}['"].*?\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"#).unwrap(),
            description: "String concatenation to build function name with user input".to_string(),
            category: DetectionCategory::DynamicExecution,
        },
        // Variable variable execution with user input
        // Catches: ${$_GET['f']}() or ${$var}($_GET['x'])
        CompiledPattern {
            regex: Regex::new(r#"(?i)\$\{\s*\$[^}]+\}\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"#).unwrap(),
            description: "Variable variable function call with user input".to_string(),
            category: DetectionCategory::DynamicExecution,
        },
        // Variable variable with user input in the variable name
        // Catches: ${$_GET['a']}
        CompiledPattern {
            regex: Regex::new(r#"(?i)\$\{\s*\$_(GET|POST|REQUEST|COOKIE)"#).unwrap(),
            description: "Variable variable from user input".to_string(),
            category: DetectionCategory::DynamicExecution,
        },
        // Array-based function construction then call
        // Catches: $a=['ev','al']; ($a[0].$a[1])($_GET['c']);
        CompiledPattern {
            regex: Regex::new(r#"(?i)\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\[\s*\d+\s*\]\s*\.\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\[\s*\d+\s*\]\s*\)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"#).unwrap(),
            description: "Array-concatenated function call with user input".to_string(),
            category: DetectionCategory::DynamicExecution,
        },
        // strrev() to hide function name then call with user input
        // Catches: $f=strrev('metsys'); $f($_GET['c']);
        CompiledPattern {
            regex: Regex::new(r#"(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*strrev\s*\(\s*['"][^'"]+['"]\s*\).*?\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"#).unwrap(),
            description: "Reversed string function call with user input".to_string(),
            category: DetectionCategory::DynamicExecution,
        },
        // chr() chain to build function name then call
        // Catches: $f=chr(101).chr(118)...; $f($_GET['c']);
        CompiledPattern {
            regex: Regex::new(r#"(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*chr\s*\(\s*\d+\s*\)(\s*\.\s*chr\s*\(\s*\d+\s*\))+.*?\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"#).unwrap(),
            description: "chr() chain function call with user input".to_string(),
            category: DetectionCategory::DynamicExecution,
        },
        // Hex-encoded string to function call
        // Catches: $f="\x65\x76\x61\x6c"; $f($_GET['c']);
        CompiledPattern {
            regex: Regex::new(r#"(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["']\\x[0-9a-f]{2}(\\x[0-9a-f]{2})+["'].*?\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"#).unwrap(),
            description: "Hex-encoded function call with user input".to_string(),
            category: DetectionCategory::DynamicExecution,
        },
        // Generic: variable assigned string, then used as function with user input
        // Catches: $a='anything'; $a($_GET['c']); when file contains user input
        // This is broader but catches more evasion
        CompiledPattern {
            regex: Regex::new(r#"(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*['"][a-z_]+['"];\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"#).unwrap(),
            description: "Variable function with user input argument".to_string(),
            category: DetectionCategory::DynamicExecution,
        },
        // call_user_func with obfuscated function name
        // Catches: call_user_func($obfuscated, $_GET['x'])
        CompiledPattern {
            regex: Regex::new(r#"(?i)call_user_func\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*,[^)]*\$_(GET|POST|REQUEST|COOKIE)"#).unwrap(),
            description: "call_user_func with variable function and user input".to_string(),
            category: DetectionCategory::DynamicExecution,
        },
        // Superglobal used directly as function name
        // Catches: $_GET['f']($_GET['c'])
        CompiledPattern {
            regex: Regex::new(r#"(?i)\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"#).unwrap(),
            description: "User input as function name and argument".to_string(),
            category: DetectionCategory::DynamicExecution,
        },
        // Concatenation inside variable variable to build superglobal name
        // Catches: ${'_'.'G'.'E'.'T'}['f']($x) or ${str}['f']()
        CompiledPattern {
            regex: Regex::new(r#"(?i)\$\{\s*['"][^'"]*['"]\s*\.\s*['"][^'"]*['"]"#).unwrap(),
            description: "String concatenation inside variable variable (superglobal construction)".to_string(),
            category: DetectionCategory::DynamicExecution,
        },
        // compact/extract abuse - extract() on user input creates variables
        CompiledPattern {
            regex: Regex::new(r#"(?i)extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"#).unwrap(),
            description: "extract() on user input (variable injection)".to_string(),
            category: DetectionCategory::DynamicExecution,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> WebshellScanner {
        WebshellScanner::new(50)
    }

    #[test]
    fn test_clean_php() {
        let s = scanner();
        let result = s.scan(r#"<?php echo "Hello, World!"; ?>"#);
        assert_eq!(result.threat_level, ThreatLevel::Clean);
        assert!(!result.is_malicious);
    }

    #[test]
    fn test_simple_webshell() {
        let s = scanner();
        let result = s.scan(r#"<?php eval($_GET['cmd']); ?>"#);
        assert_eq!(result.threat_level, ThreatLevel::Malicious);
        assert!(result.is_malicious);
        assert!(result.detections.iter().any(|d| d.category == DetectionCategory::InputEvalChain));
    }

    #[test]
    fn test_system_webshell() {
        let s = scanner();
        let result = s.scan(r#"<?php system($_POST['cmd']); ?>"#);
        assert_eq!(result.threat_level, ThreatLevel::Malicious);
        assert!(result.is_malicious);
    }

    #[test]
    fn test_base64_decode_chain() {
        let s = scanner();
        let result = s.scan(r#"<?php eval(base64_decode('ZWNobyAiSGVsbG8iOw==')); ?>"#);
        assert_eq!(result.threat_level, ThreatLevel::Malicious);
        assert!(result.is_malicious);
        assert!(result.detections.iter().any(|d| d.category == DetectionCategory::DecodeChain));
    }

    #[test]
    fn test_gzinflate_chain() {
        let s = scanner();
        let result = s.scan(r#"<?php eval(gzinflate(base64_decode('payload'))); ?>"#);
        assert_eq!(result.threat_level, ThreatLevel::Malicious);
        assert!(result.is_malicious);
    }

    #[test]
    fn test_c99_signature() {
        let s = scanner();
        let result = s.scan(r#"<?php $c99shell_version = '1.0'; ?>"#);
        assert_eq!(result.threat_level, ThreatLevel::Malicious);
        assert!(result.is_malicious);
        assert!(result.detections.iter().any(|d| d.category == DetectionCategory::KnownSignature));
    }

    #[test]
    fn test_r57_signature() {
        let s = scanner();
        let result = s.scan(r#"<?php $r57shell = true; ?>"#);
        assert_eq!(result.threat_level, ThreatLevel::Malicious);
        assert!(result.is_malicious);
    }

    #[test]
    fn test_china_chopper() {
        let s = scanner();
        let result = s.scan(r#"<?php @eval($_POST['x']); ?>"#);
        assert_eq!(result.threat_level, ThreatLevel::Malicious);
        assert!(result.is_malicious);
    }

    #[test]
    fn test_obfuscation_score() {
        let s = scanner();

        // Heavy hex encoding
        let result = s.scan(r#"<?php $a = "\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64"; ?>"#);
        assert!(result.obfuscation_score > 0);

        // chr() chains
        let result = s.scan(r#"<?php $a = chr(72).chr(101).chr(108).chr(108).chr(111); ?>"#);
        assert!(result.obfuscation_score > 0);
    }

    #[test]
    fn test_should_scan() {
        assert!(WebshellScanner::should_scan(Path::new("test.php")));
        assert!(WebshellScanner::should_scan(Path::new("test.phtml")));
        assert!(WebshellScanner::should_scan(Path::new("test.PHP")));
        assert!(!WebshellScanner::should_scan(Path::new("test.txt")));
        assert!(!WebshellScanner::should_scan(Path::new("test.js")));
    }

    #[test]
    fn test_dynamic_function_call() {
        let s = scanner();
        let result = s.scan(r#"<?php $func = $_GET['f']; $func(); ?>"#);
        assert_eq!(result.threat_level, ThreatLevel::Malicious);
        assert!(result.is_malicious);
    }

    #[test]
    fn test_passthru() {
        let s = scanner();
        let result = s.scan(r#"<?php passthru($_REQUEST['cmd']); ?>"#);
        assert_eq!(result.threat_level, ThreatLevel::Malicious);
        assert!(result.is_malicious);
    }
}
