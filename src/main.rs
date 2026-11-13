#![windows_subsystem = "windows"]

pub mod ai;
pub mod app;
pub mod bootkit;
pub mod crypto;
pub mod db;
pub mod models;
pub mod network;
pub mod quarantine;
pub mod report;
pub mod scanner;
pub mod terminal;
pub mod tools;
pub mod ui;
pub mod vuln;

fn main() {
    app::run_app();
}
