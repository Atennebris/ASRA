// ASRA's native Windows ConPTY bridge -- see Cargo.toml's own description for the full "why".
//
// Launched by agent/tools/terminal_manager.py (via WSL2's own binfmt_misc interop, exactly the
// same way a plain cmd.exe/powershell.exe was launched before this existed) with the REAL target
// shell's path as argv[1] (plus any further args). This process's own stdin/stdout are the Linux
// PTY slave ASRA already created on the WSL2 side -- but instead of handing THAT pty directly to
// the target shell (the old approach, which left interactive line-editing broken -- PSReadLine
// crashed outright on a Tab keypress, cmd.exe's own path completion never worked either), this
// process creates a genuine Win32 ConPTY of its own (via the `portable-pty` crate, the same
// approach real terminal emulators like WezTerm use), spawns the target shell attached to THAT,
// and pumps raw bytes between the two. The target shell gets a 100% real native console -- no WSL
// interop translation involved on that side at all -- so PSReadLine/tab-completion/history work
// exactly as they would in a real Windows Terminal window.
//
// Wire protocol on THIS process's own stdin (distinct from -- one layer beneath -- the browser-
// facing WebSocket protocol main.py/static/js/terminal.js speak; a WebSocket message is already a
// discrete, length-delimited unit, but a plain redirected stdin pipe has no message boundaries of
// its own, so this framing carries an explicit length where the WS-facing one doesn't need one):
//   0x00 + 4-byte big-endian u32 length + that many raw bytes  -> forwarded to the ConPTY's stdin.
//   0x01 + 2-byte big-endian u16 cols + 2-byte big-endian u16 rows -> resizes the ConPTY.
// This process's own stdout is raw ConPTY output, unframed -- exactly one kind of data ever flows
// that direction, matching the outer WS protocol's own asymmetry.
use std::env;
use std::io::{self, Read, Write};
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::thread;

use portable_pty::{native_pty_system, CommandBuilder, PtySize};

fn read_exact_or_exit<R: Read>(r: &mut R, buf: &mut [u8]) -> bool {
    r.read_exact(buf).is_ok()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: asra-pty-bridge <shell-path> <cwd>");
        exit(2);
    }
    // Both real Windows-shaped paths (e.g. "C:\\Windows\\System32\\...\\powershell.exe" /
    // "C:\\Users\\Public") -- agent/tools/terminal_manager.py's own create_terminal() always
    // translates these from their WSL /mnt/c/... form before invoking this binary. Passing
    // either one as a Linux-side path here is a real, confirmed bug: CreateProcessW simply can't
    // resolve that path shape at all, and (separately) relying on WSL2 interop's own ambient cwd
    // translation for the exec'd bridge process itself was confirmed live to land somewhere OTHER
    // than the caller actually asked for -- an explicit cwd argument removes that guesswork.
    let shell_path = args[1].clone();
    let cwd = args[2].clone();

    let pty_system = native_pty_system();
    let pair = match pty_system.openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    }) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("asra-pty-bridge: failed to open a ConPTY: {e}");
            exit(1);
        }
    };

    let mut cmd = CommandBuilder::new(&shell_path);
    cmd.cwd(&cwd);

    let child = match pair.slave.spawn_command(cmd) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("asra-pty-bridge: failed to spawn {shell_path} (cwd {cwd}) in the ConPTY: {e}");
            exit(1);
        }
    };
    // The slave side is only needed to spawn the child attached to it -- dropping our own handle
    // to it now matches how every real ConPTY consumer (including portable-pty's own examples)
    // does this, and avoids holding a handle open that could keep the pty "alive" past when the
    // real child using it actually exits.
    drop(pair.slave);

    let master = Arc::new(Mutex::new(pair.master));
    let writer = match master.lock().unwrap().take_writer() {
        Ok(w) => Arc::new(Mutex::new(w)),
        Err(e) => {
            eprintln!("asra-pty-bridge: failed to take the ConPTY writer: {e}");
            exit(1);
        }
    };
    let mut reader = match master.lock().unwrap().try_clone_reader() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("asra-pty-bridge: failed to clone the ConPTY reader: {e}");
            exit(1);
        }
    };

    // ConPTY output -> this process's own stdout, raw and unframed. Runs on its own thread so a
    // slow/blocked stdout write (the WSL2 interop pipe on the other end) never stalls us reading
    // more output than we can currently forward, and vice versa for the main thread's own input
    // loop below.
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        let mut stdout = io::stdout();
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if stdout.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = stdout.flush();
                }
                Err(_) => break,
            }
        }
    });

    // Exits this whole bridge process the moment the real shell exits -- there is nothing useful
    // left for the bridge to do once its one real job (hosting that shell's ConPTY) is done, and
    // exiting here is also what lets ASRA's own PTY-master reader on the Linux side see EOF and
    // correctly mark the terminal session as exited (agent/tools/terminal_manager.py's own
    // TerminalSession._handle_exit).
    let waiter_child_ref = Arc::new(Mutex::new(child));
    let waiter_child = Arc::clone(&waiter_child_ref);
    thread::spawn(move || {
        let status = waiter_child.lock().unwrap().wait();
        let code = status.map(|s| s.exit_code() as i32).unwrap_or(1);
        exit(code);
    });

    // This process's own stdin -> the framed protocol described at the top of this file.
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    loop {
        let mut tag = [0u8; 1];
        if !read_exact_or_exit(&mut stdin, &mut tag) {
            break; // EOF or a read error -- ASRA closed its own side, nothing more to do.
        }
        match tag[0] {
            0x00 => {
                let mut len_bytes = [0u8; 4];
                if !read_exact_or_exit(&mut stdin, &mut len_bytes) {
                    break;
                }
                let len = u32::from_be_bytes(len_bytes) as usize;
                let mut payload = vec![0u8; len];
                if !read_exact_or_exit(&mut stdin, &mut payload) {
                    break;
                }
                let mut w = writer.lock().unwrap();
                if w.write_all(&payload).is_err() {
                    break;
                }
                let _ = w.flush();
            }
            0x01 => {
                let mut dims = [0u8; 4];
                if !read_exact_or_exit(&mut stdin, &mut dims) {
                    break;
                }
                let cols = u16::from_be_bytes([dims[0], dims[1]]);
                let rows = u16::from_be_bytes([dims[2], dims[3]]);
                let _ = master.lock().unwrap().resize(PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                });
            }
            _ => break, // an unrecognized tag means the framing itself is desynced -- stop rather
                        // than guess, so a bug shows up as a closed session, not silent corruption.
        }
    }

    // Our own stdin hit EOF (ASRA tore down its side, e.g. the operator closed the tab) -- make
    // sure the real shell doesn't outlive us as an orphan before this process itself exits.
    let _ = waiter_child_ref.lock().unwrap().kill();
    exit(0);
}
