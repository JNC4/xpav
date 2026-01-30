//! Scanner modules
//!
//! Stateless content scanners for various threat types.

pub mod entropy;
pub mod webshell;

#[cfg(feature = "yara")]
pub mod yara;

pub use entropy::{calculate_entropy, calculate_file_entropy, EntropyClassification, EntropyResult};
pub use webshell::WebshellScanner;

#[cfg(feature = "yara")]
pub use yara::YaraScanner;
