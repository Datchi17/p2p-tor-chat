const COMMANDS: &[&str] = &[
    "app_state",
    "create_vault",
    "unlock",
    "verify_passphrase",
    "lock",
    "change_passphrase",
    "panic_wipe",
    "my_code",
    "add_contact",
    "contacts",
    "safety_number",
    "verify_contact",
    "unverify_contact",
    "rename_contact",
    "delete_contact",
    "messages",
    "send_text",
    "send_file",
    "save_file",
    "mark_read",
    "set_disappearing",
    "get_settings",
    "set_settings",
    "tor_log",
    "request_attention",
    "build_age_days",
];

fn main() {
    // Declaring the app manifest makes every command deny-by-default: the UI may only call
    // commands granted in capabilities/default.json.
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to run tauri-build");
}
