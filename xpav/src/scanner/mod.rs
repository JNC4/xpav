//! Scanner modules
//!
//! Stateless content scanners for various threat types.

pub mod entropy;
pub mod framework;
pub mod webshell;

#[cfg(feature = "yara")]
pub mod yara;

pub use entropy::{calculate_entropy, calculate_file_entropy, EntropyClassification, EntropyResult};
pub use framework::{Framework, FrameworkDetector};
pub use webshell::{is_likely_minified, ScanContext, WebshellScanner};

#[cfg(feature = "yara")]
pub use yara::YaraScanner;
