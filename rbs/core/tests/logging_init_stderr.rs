/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Integration test: `init_logging` without `file_path` writes log lines to stderr.

use rbs_core::{init_logging, LoggingConfig};

#[cfg(unix)]
mod unix {
    use std::fs::File;
    use std::io::Read;
    use std::os::unix::io::FromRawFd;

    use super::*;

    struct RestoreStderr(libc::c_int);

    impl Drop for RestoreStderr {
        fn drop(&mut self) {
            unsafe {
                let _ = libc::dup2(self.0, libc::STDERR_FILENO);
                let _ = libc::close(self.0);
            }
        }
    }

    /// Redirect stderr to a pipe while `f` runs, then restore stderr and return captured bytes.
    fn capture_stderr_while(f: impl FnOnce()) -> Vec<u8> {
        let mut fds: [libc::c_int; 2] = [0, 0];
        assert_eq!(
            unsafe { libc::pipe(fds.as_mut_ptr()) },
            0,
            "pipe() for stderr capture"
        );
        let read_fd = fds[0];
        let write_fd = fds[1];

        let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
        assert!(saved_stderr >= 0, "dup(STDERR_FILENO)");

        assert_eq!(
            unsafe { libc::dup2(write_fd, libc::STDERR_FILENO) },
            libc::STDERR_FILENO,
            "dup2(pipe, STDERR)"
        );
        unsafe {
            libc::close(write_fd);
        }

        {
            let _restore = RestoreStderr(saved_stderr);
            f();
        }

        let mut pipe_read = unsafe { File::from_raw_fd(read_fd) };
        let mut buf = Vec::new();
        pipe_read
            .read_to_end(&mut buf)
            .expect("read captured stderr");
        buf
    }

    #[test]
    fn init_logging_stderr_contains_log_message() {
        const MARKER: &str = "logging_stderr_test_marker_xyz";

        let captured = capture_stderr_while(|| {
            let config = LoggingConfig::default();
            init_logging(&config).expect("init_logging to stderr should succeed");
            log::info!("{MARKER}");
            log::logger().flush();
        });

        let text = String::from_utf8_lossy(&captured);
        assert!(
            text.contains(MARKER),
            "stderr must contain the log line; got: {text:?}"
        );
    }
}

#[cfg(not(unix))]
#[test]
fn init_logging_stderr_succeeds_without_file_path() {
    let config = LoggingConfig::default();
    init_logging(&config).expect("init_logging without file_path should succeed");
    log::info!("logging_stderr_test message");
    log::logger().flush();
}
