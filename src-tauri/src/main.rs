//! Desktop shell: exposes the core to the UI through a fixed list of commands and forwards
//! core events to the window. Contains no crypto or networking of its own.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

use p2p_core::{AppState, Config, ContactView, Core, MessageView, MyCode, Settings};
use p2p_vault::KdfParams;
use tauri::{Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

struct App(Core);

type CmdResult<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[tauri::command]
fn app_state(app: State<'_, App>) -> AppState {
    app.0.state()
}

#[tauri::command]
async fn create_vault(app: State<'_, App>, name: String, passphrase: String) -> CmdResult<()> {
    app.0.create_vault(&name, Zeroizing::new(passphrase)).await.map_err(err)
}

#[tauri::command]
async fn unlock(app: State<'_, App>, passphrase: String) -> CmdResult<()> {
    app.0.unlock(Zeroizing::new(passphrase)).await.map_err(err)
}

#[tauri::command]
async fn verify_passphrase(app: State<'_, App>, passphrase: String) -> CmdResult<bool> {
    app.0.verify_passphrase(Zeroizing::new(passphrase)).await.map_err(err)
}

#[tauri::command]
async fn lock(app: State<'_, App>) -> CmdResult<()> {
    app.0.lock().await;
    Ok(())
}

#[tauri::command]
async fn change_passphrase(app: State<'_, App>, old_passphrase: String, new_passphrase: String) -> CmdResult<()> {
    app.0.change_passphrase(Zeroizing::new(old_passphrase), Zeroizing::new(new_passphrase)).await.map_err(err)
}

#[tauri::command]
async fn panic_wipe(app: State<'_, App>) -> CmdResult<()> {
    app.0.panic_wipe().await.map_err(err)
}

#[tauri::command]
fn my_code(app: State<'_, App>) -> CmdResult<MyCode> {
    app.0.my_code().map_err(err)
}

#[tauri::command]
async fn add_contact(app: State<'_, App>, code: String, nickname: Option<String>) -> CmdResult<i64> {
    app.0.add_contact(&code, nickname.as_deref()).await.map_err(err)
}

#[tauri::command]
async fn contacts(app: State<'_, App>) -> CmdResult<Vec<ContactView>> {
    app.0.contacts().await.map_err(err)
}

#[tauri::command]
fn safety_number(app: State<'_, App>, contact_id: i64) -> CmdResult<Vec<String>> {
    app.0.safety_number(contact_id).map_err(err)
}

#[tauri::command]
fn verify_contact(app: State<'_, App>, contact_id: i64, proof: Vec<(usize, String)>) -> CmdResult<()> {
    app.0.verify_contact(contact_id, &proof).map_err(err)
}

#[tauri::command]
fn unverify_contact(app: State<'_, App>, contact_id: i64) -> CmdResult<()> {
    app.0.unverify_contact(contact_id).map_err(err)
}

#[tauri::command]
fn rename_contact(app: State<'_, App>, contact_id: i64, name: String) -> CmdResult<()> {
    app.0.rename_contact(contact_id, &name).map_err(err)
}

#[tauri::command]
async fn delete_contact(app: State<'_, App>, contact_id: i64) -> CmdResult<()> {
    app.0.delete_contact(contact_id).await.map_err(err)
}

#[tauri::command]
fn messages(app: State<'_, App>, contact_id: i64, before_ts: Option<i64>) -> CmdResult<Vec<MessageView>> {
    app.0.messages(contact_id, 100, before_ts).map_err(err)
}

#[tauri::command]
async fn send_text(app: State<'_, App>, contact_id: i64, text: String) -> CmdResult<MessageView> {
    app.0.send_text(contact_id, &text).await.map_err(err)
}

/// Lets the user pick a file in the native dialog (the UI never sees the file system), then
/// queues it. Returns `None` if the dialog was cancelled.
#[tauri::command]
async fn send_file(app: State<'_, App>, window: tauri::WebviewWindow, contact_id: i64) -> CmdResult<Option<MessageView>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    window.dialog().file().set_parent(&window).set_title("Send a file").pick_file(move |p| {
        let _ = tx.send(p);
    });
    let Some(path) = rx.await.map_err(err)? else { return Ok(None) };
    let path = path.into_path().map_err(err)?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let data = tauri::async_runtime::spawn_blocking(move || -> CmdResult<Zeroizing<Vec<u8>>> {
        let len = std::fs::metadata(&path).map_err(err)?.len();
        if len == 0 || len > p2p_core::MAX_FILE_BYTES {
            return Err(p2p_core::CoreError::BadFile.to_string());
        }
        Ok(Zeroizing::new(std::fs::read(&path).map_err(err)?))
    })
    .await
    .map_err(err)??;
    app.0.send_file(contact_id, &name, data).await.map(Some).map_err(err)
}

/// Saves a received file where the user chooses in the native dialog. Returns false if
/// cancelled. Received files are never opened automatically.
#[tauri::command]
async fn save_file(app: State<'_, App>, window: tauri::WebviewWindow, message_id: String) -> CmdResult<bool> {
    let (name, data) = app.0.file_data(&message_id).map_err(err)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    window.dialog().file().set_parent(&window).set_title("Save file").set_file_name(&name).save_file(move |p| {
        let _ = tx.send(p);
    });
    let Some(path) = rx.await.map_err(err)? else { return Ok(false) };
    let path = path.into_path().map_err(err)?;
    tauri::async_runtime::spawn_blocking(move || {
        std::fs::write(&path, &data[..]).map_err(err)?;
        // Mark-of-the-Web: Windows then warns before running a received program, as it does
        // for browser downloads. Best effort (needs NTFS).
        if cfg!(windows) {
            let mut ads = path.into_os_string();
            ads.push(":Zone.Identifier");
            let _ = std::fs::write(ads, "[ZoneTransfer]\r\nZoneId=3\r\n");
        }
        Ok::<_, String>(())
    })
    .await
    .map_err(err)??;
    Ok(true)
}

#[tauri::command]
async fn mark_read(app: State<'_, App>, contact_id: i64) -> CmdResult<()> {
    app.0.mark_read(contact_id).await.map_err(err)
}

#[tauri::command]
async fn set_disappearing(app: State<'_, App>, contact_id: i64, secs: u32) -> CmdResult<()> {
    app.0.set_disappearing(contact_id, secs).await.map_err(err)
}

#[tauri::command]
fn get_settings(app: State<'_, App>) -> CmdResult<Settings> {
    app.0.settings().map_err(err)
}

#[tauri::command]
async fn set_settings(app: State<'_, App>, settings: Settings) -> CmdResult<()> {
    app.0.set_settings(settings).await.map_err(err)
}

#[tauri::command]
async fn tor_log(app: State<'_, App>) -> CmdResult<Vec<String>> {
    Ok(app.0.tor_log().await)
}

#[tauri::command]
fn request_attention(window: tauri::WebviewWindow) -> CmdResult<()> {
    window.request_user_attention(Some(tauri::UserAttentionType::Informational)).map_err(err)
}

/// Days since this build's source commit, so the UI can remind you to update without the app
/// ever contacting anything. Release builds take the commit time from `SOURCE_DATE_EPOCH`
/// (set by CI and scripts/repro-build-linux.sh); other builds return `None`.
#[tauri::command]
fn build_age_days() -> Option<u64> {
    let built: u64 = option_env!("SOURCE_DATE_EPOCH")?.parse().ok()?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    Some(now.saturating_sub(built) / 86_400)
}

/// Data directory: `P2PCHAT_DATA_DIR` (to run two instances on one machine for testing),
/// otherwise the per-user app data directory.
fn data_dir(app: &tauri::App) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(d) = std::env::var_os("P2PCHAT_DATA_DIR") {
        return Ok(PathBuf::from(d));
    }
    Ok(app.path().app_data_dir()?)
}

/// Tor: `P2PCHAT_TOR`, then the bundled copy (Windows), then the system one (Linux package
/// dependency) via PATH.
fn tor_binary(app: &tauri::App) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("P2PCHAT_TOR") {
        return Some(PathBuf::from(p));
    }
    let exe = if cfg!(windows) { "tor.exe" } else { "tor" };
    let bundled = app.path().resource_dir().ok()?.join("tor").join(exe);
    bundled.is_file().then_some(bundled)
}

/// Pluggable transport for bridges: `P2PCHAT_PT`, the bundled lyrebird (Windows), or
/// `lyrebird` / `obfs4proxy` from PATH (Linux packages).
fn pt_binary(app: &tauri::App) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("P2PCHAT_PT") {
        return Some(PathBuf::from(p));
    }
    let names: &[&str] = if cfg!(windows) { &["lyrebird.exe"] } else { &["lyrebird", "obfs4proxy"] };
    if let Ok(res) = app.path().resource_dir() {
        let bundled = res.join("tor").join("pluggable_transports").join(names[0]);
        if bundled.is_file() {
            return Some(bundled);
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).flat_map(|d| names.iter().map(move |n| d.join(n))).find(|p| p.is_file())
}

fn main() {
    // Release builds log nothing unless asked to: Linux desktops append an app's error output
    // to ~/.xsession-errors or the journal, and timestamped lines such as "closing connection
    // to contact 3" would become an on-disk record of when you chatted. For troubleshooting,
    // start the app from a terminal with P2PCHAT_LOG=warn (or debug).
    let filter = std::env::var("P2PCHAT_LOG").ok().or_else(|| cfg!(debug_assertions).then(|| "warn".to_string()));
    if let Some(filter) = filter {
        tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).init();
    }

    tauri::Builder::default()
        // Used only from Rust (send_file/save_file); the UI is granted no dialog permissions.
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let core = Core::new(Config {
                data_dir: data_dir(app)?,
                tor_binary: tor_binary(app),
                pt_binary: pt_binary(app),
                kdf: KdfParams::STRONG,
            });
            let mut events = core.subscribe();
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                use tokio::sync::broadcast::error::RecvError;
                loop {
                    match events.recv().await {
                        Ok(e) => {
                            let _ = handle.emit_to("main", "core-event", e);
                        }
                        Err(RecvError::Lagged(_)) => continue,
                        Err(RecvError::Closed) => break,
                    }
                }
            });
            app.manage(App(core));
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                // Stop Tor and wipe keys from memory when the window closes.
                let core = window.state::<App>().0.clone();
                tauri::async_runtime::block_on(core.lock());
            }
        })
        .invoke_handler(tauri::generate_handler![
            app_state,
            create_vault,
            unlock,
            verify_passphrase,
            lock,
            change_passphrase,
            panic_wipe,
            my_code,
            add_contact,
            contacts,
            safety_number,
            verify_contact,
            unverify_contact,
            rename_contact,
            delete_contact,
            messages,
            send_text,
            send_file,
            save_file,
            mark_read,
            set_disappearing,
            get_settings,
            set_settings,
            tor_log,
            request_attention,
            build_age_days,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the app");
}
