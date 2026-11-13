fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/logo.ico");
        res.set("ProductName", "Fikrado Security");
        res.set("FileDescription", "Enterprise Windows Threat Defense Platform");
        res.set("CompanyName", "Fikrado Security");
        res.set("LegalCopyright", "Copyright © 2026 Fikrado Security");
        let _ = res.compile();
    }
}
