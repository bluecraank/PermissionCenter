//! Gemeinsames Datenmodell von PermissionCenter-Client und -Server.
//!
//! Der [`model::ScanReport`] ist der Vertrag zwischen beiden Seiten. Änderungen
//! am Format erhöhen [`model::REPORT_SCHEMA_VERSION`].

pub mod adacl;
pub mod gpo;
pub mod model;
pub mod release;
pub mod rights;
pub mod sid;
pub mod weakness;
pub mod wellknown;

pub use model::*;
