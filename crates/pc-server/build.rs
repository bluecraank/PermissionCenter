//! Stellt sicher, dass `web/dist` existiert, damit das Einbetten der
//! Web-Oberfläche auch ohne vorherigen Frontend-Build kompiliert.

use std::path::PathBuf;

fn main() {
    let dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../web/dist");
    if !dist.join("index.html").exists() {
        let _ = std::fs::create_dir_all(&dist);
        let _ = std::fs::write(
            dist.join("index.html"),
            "<!doctype html><meta charset=utf-8><title>PermissionCenter</title>\
             <p>Web-Oberfläche nicht gebaut. Im Ordner <code>web/</code> <code>npm ci &amp;&amp; npm run build</code> ausführen \
             und den Server neu bauen.</p>",
        );
    }
    println!("cargo:rerun-if-changed=../../web/dist");
}
