pub mod commands;
pub mod detector;
pub mod scrubber;
pub mod workbench;

use std::sync::Mutex;

use tauri::{webview::NewWindowResponse, Url, WebviewWindowBuilder};

fn allows_navigation(url: &Url) -> bool {
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }

    match (url.scheme(), url.host_str(), url.port()) {
        ("tauri", Some("localhost"), None) | ("https", Some("tauri.localhost"), None) => true,
        #[cfg(debug_assertions)]
        ("http", Some("127.0.0.1"), Some(1420)) => true,
        _ => false,
    }
}

pub fn run() -> tauri::Result<()> {
    let builder = tauri::Builder::default();
    #[cfg(target_os = "macos")]
    let builder = builder.manage(std::sync::Arc::new(
        commands::scrubber::ScrubberController::new(commands::scrubber::NativeFileDialogs),
    ));
    builder
        .manage(Mutex::new(workbench::WorkbenchState::default()))
        .setup(|app| {
            let _window = WebviewWindowBuilder::from_config(app, &app.config().app.windows[0])?
                .disable_drag_drop_handler()
                .on_navigation(allows_navigation)
                .on_new_window(|_, _| NewWindowResponse::Deny)
                .build()?;
            #[cfg(target_os = "macos")]
            commands::scrubber::native_drop::install(&_window)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::analyze_draft,
            commands::set_match_action,
            commands::add_manual_redaction,
            commands::remove_manual_redaction,
            commands::clear_draft,
            commands::copy_redacted_text,
            #[cfg(target_os = "macos")]
            commands::scrubber::scrubber_pick_input,
            #[cfg(target_os = "macos")]
            commands::scrubber::scrubber_get_session,
            #[cfg(target_os = "macos")]
            commands::scrubber::scrubber_get_preview_page,
            #[cfg(target_os = "macos")]
            commands::scrubber::scrubber_export_to_picked_destination,
            #[cfg(target_os = "macos")]
            commands::scrubber::scrubber_get_export_status,
            #[cfg(target_os = "macos")]
            commands::scrubber::scrubber_cancel_export,
            #[cfg(target_os = "macos")]
            commands::scrubber::scrubber_clear_session,
        ])
        .run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    use super::{allows_navigation, Url};

    #[test]
    fn allows_only_bundled_and_debug_origins() {
        for url in ["tauri://localhost/", "https://tauri.localhost/"] {
            assert!(allows_navigation(&Url::parse(url).unwrap()));
        }
        for url in [
            "https://example.com/",
            "https://tauri.localhost.example.com/",
            "https://tauri.localhost:8443/",
            "https://user@tauri.localhost/",
            "http://127.0.0.1:1421/",
            "file:///tmp/index.html",
        ] {
            assert!(!allows_navigation(&Url::parse(url).unwrap()));
        }
        let dev_url = Url::parse("http://127.0.0.1:1420/").unwrap();
        assert_eq!(allows_navigation(&dev_url), cfg!(debug_assertions));
    }
}
