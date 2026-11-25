//! qalaa-scan: Qalaa's static file scanner.
//!
//! Runs as a separate, capped child process per batch of files, so a parser
//! bug triggered by a hostile file can't take the daemon with it. It parses
//! executables with goblin, matches YARA-X rules, extracts EMBER-style
//! features and evaluates a local tree model. Rules and model come only from
//! a signed bundle (see `bundle`). Nothing leaves the machine.

pub mod bundle;
pub mod features;
pub mod limits;
pub mod model;
pub mod scan;
