//! 启动留痕：把关键步骤和 panic 写进数据目录的 `boot.log`。
//!
//! 不给用户看，只在拿不到 logcat 的时候能翻出来定位闪退。
//! 数据目录在 setup 之后才知道，之前发生的记录先缓冲在内存里，
//! 等 `set_dir` 时一并落盘。

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

static START: Mutex<Option<Instant>> = Mutex::new(None);
static DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
static BUF: Mutex<Vec<String>> = Mutex::new(Vec::new());

const MAX_BUF: usize = 200;
const LOG_NAME: &str = "boot.log";

fn elapsed_ms() -> u128 {
    let mut guard = match START.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let start = guard.get_or_insert_with(Instant::now);
    start.elapsed().as_millis()
}

fn append_line(path: &PathBuf, line: &str) {
    // 超过 64KB 就重来，避免无限增长。
    if let Ok(meta) = fs::metadata(path) {
        if meta.len() > 64 * 1024 {
            let _ = fs::remove_file(path);
        }
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}

/// 追加一条启动记录。
pub fn trace(msg: &str) {
    let line = format!("[{:>6}ms] {msg}", elapsed_ms());
    let dir = match DIR.lock() {
        Ok(g) => g.clone(),
        Err(p) => p.into_inner().clone(),
    };
    match dir {
        Some(dir) => append_line(&dir.join(LOG_NAME), &line),
        None => {
            let mut buf = match BUF.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            buf.push(line);
            if buf.len() > MAX_BUF {
                let drop = buf.len() - MAX_BUF;
                buf.drain(0..drop);
            }
        }
    }
}

/// 数据目录确定后调用：把内存里缓冲的记录落到 `boot.log`。
pub fn set_dir(dir: PathBuf) {
    {
        let mut guard = match DIR.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *guard = Some(dir.clone());
    }
    let log = dir.join(LOG_NAME);
    let buffered: Vec<String> = {
        let mut buf = match BUF.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        std::mem::take(&mut *buf)
    };
    for line in buffered {
        append_line(&log, &line);
    }
    trace("diag ready");
}

/// 装上 panic hook：进程死前的最后一条记录（panic 信息）靠它落盘。
pub fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        trace(&format!("PANIC {info}"));
        default_hook(info);
    }));
}
