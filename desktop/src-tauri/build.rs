fn main() {
    // AppManifest::commands lists every #[tauri::command] this app registers (main.rs's own
    // invoke_handler list) so tauri-build auto-generates an "allow-<command>" ACL permission
    // identifier per command -- without this, none of them exist as referenceable permissions
    // at all, and capabilities/default.json's own "permissions" array (which grants every one of
    // them) would fail to resolve them. Real, confirmed incident this fixes: open_external_url
    // (Codex/Copilot OAuth "Connect" buttons, a Library source's own link, "Get a key" links) and
    // notify_session_done both silently failed with "Command <name> not allowed by ACL" -- bare
    // `tauri_build::build()` never declared these commands to the ACL system at all. Repeated a
    // second time when force_restart_agent was added straight to main.rs's invoke_handler without
    // also adding it here + capabilities/default.json -- same silent "not allowed by ACL" failure,
    // this time surfaced live on the start screen's own Force Restart button. This list and that
    // one's "permissions" array must always grow together, one entry each, for every new command.
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(
            tauri_build::AppManifest::new().commands(&[
                "get_start_config",
                "launch_backend",
                "force_restart_agent",
                "save_env",
                "open_in_browser",
                "open_external_url",
                "notify_session_done",
            ]),
        ),
    )
    .expect("tauri_build failed");
}
