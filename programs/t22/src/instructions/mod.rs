// Every file names its entry point `handler`; lib.rs calls each by full path.
#![allow(ambiguous_glob_reexports)]

pub mod confidential;
pub mod remittance;

pub use confidential::*;
pub use remittance::*;
