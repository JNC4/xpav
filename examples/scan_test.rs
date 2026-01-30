//! Test the webshell scanner against sample files
use std::fs;
use xpav::scanner::webshell::WebshellScanner;

fn main() {
    let scanner = WebshellScanner::new(50);

    let test_cases = [
        ("<?php eval($_GET['cmd']); ?>", true, "Simple webshell"),
        ("<?php $a='ev'.'al'; $a($_POST['x']); ?>", true, "Concat evasion"),
        ("<?php echo 'Hello World'; ?>", false, "Legitimate PHP"),
        ("<?php $c99shell_version = '1.0'; ?>", true, "c99 signature"),
        ("<?php eval(base64_decode('ZWNobyAiaGFja2VkIjs=')); ?>", true, "Decode chain"),
        ("<?php system($_REQUEST['cmd']); ?>", true, "System shell"),
        ("<?php @eval($_POST['x']); ?>", true, "China Chopper"),
        ("<?php $f = strrev('metsys'); $f($_GET['c']); ?>", true, "strrev evasion"),
        ("<?php ${$_GET['f']}($_GET['x']); ?>", true, "Variable variable"),
        ("<?php include 'header.php'; echo $content; ?>", false, "Normal include"),
    ];

    println!("\n=== Webshell Scanner Test Results ===\n");

    let mut passed = 0;
    let mut failed = 0;

    for (content, should_detect, desc) in &test_cases {
        let result = scanner.scan(content);
        let detected = result.is_malicious;
        let correct = detected == *should_detect;

        if correct {
            passed += 1;
            print!("\x1b[32m[PASS]\x1b[0m ");
        } else {
            failed += 1;
            print!("\x1b[31m[FAIL]\x1b[0m ");
        }
        println!("{}", desc);

        if !result.detections.is_empty() {
            for d in &result.detections {
                println!("       {:?}: {}", d.category, d.description);
            }
        }
        if result.obfuscation_score > 0 {
            println!("       Obfuscation score: {}", result.obfuscation_score);
        }
        println!();
    }

    println!("=== Summary: {}/{} passed ===\n", passed, passed + failed);

    if failed > 0 {
        std::process::exit(1);
    }
}
