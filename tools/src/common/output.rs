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

use std::fs;

use crate::config::{GlobalOptions, OutputFormat};
use crate::error::CliError;

/// Renders command output for the selected format and writes it to configured sinks.
pub fn write_formatted_output<F>(global: &GlobalOptions, render: F) -> std::result::Result<(), CliError>
where
    F: FnOnce(OutputFormat) -> std::result::Result<String, CliError>,
{
    let output = render(global.format.clone())?;
    write_output(global, &output)
}

/// Writes an already-rendered output string to the configured targets.
pub fn write_output(global: &GlobalOptions, output: &str) -> std::result::Result<(), CliError> {
    if let Some(output_file) = &global.output_file {
        write_private_file(output_file, output)?;
    }
    if !global.noout {
        println!("{output}");
    }
    Ok(())
}

/// Write `contents` to `path` with owner-only permissions.
///
/// CLI output can carry sensitive material (tokens, decrypted resource
/// content), so new files are created with mode 0o600 and pre-existing files
/// are tightened to 0o600 as well — reusing an output path must not keep a
/// wider mode from an earlier creation. The process umask can only remove
/// permission bits, never widen them.
pub fn write_private_file(path: &str, contents: &str) -> std::result::Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents.as_bytes())?;

        // `mode()` only applies at creation; tighten pre-existing files.
        let perms = fs::metadata(path)?.permissions();
        if perms.mode() & 0o777 != 0o600 {
            fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_formatted_output_writes_rendered_content_to_file() {
        let path = std::env::temp_dir().join(format!("tools-common-output-{}.txt", std::process::id()));
        let global = GlobalOptions { output_file: Some(path.to_string_lossy().into_owned()), noout: true, ..Default::default() };

        write_formatted_output(&global, |format| {
            assert_eq!(format, OutputFormat::Text);
            Ok("payload".to_string())
        })
        .expect("write formatted output");

        let written = std::fs::read_to_string(&path).expect("read output");
        assert_eq!(written, "payload");
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_file_creates_new_file_with_0600() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!("tools-private-write-new-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&path);

        write_private_file(path.to_str().unwrap(), "secret-token").expect("write private file");

        let mode = std::fs::metadata(&path).expect("stat output").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "new output file must be owner-only");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "secret-token");
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_file_tightens_preexisting_wide_file() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!("tools-private-write-wide-{}.txt", std::process::id()));
        std::fs::write(&path, "old").expect("seed wide file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("widen permissions");

        write_private_file(path.to_str().unwrap(), "new-secret").expect("rewrite private file");

        let mode = std::fs::metadata(&path).expect("stat output").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "pre-existing output file must be tightened");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new-secret");
        let _ = std::fs::remove_file(&path);
    }
}
