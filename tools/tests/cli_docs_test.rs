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

//! The generated reference must include every visible command and long option.

use clap::{Command, CommandFactory};

fn assert_reference_covers_command(command: &Command, path: &str, markdown: &str) {
    assert!(markdown.contains(&format!("## `{path}`")), "missing command {path}");
    for argument in command.get_arguments().filter(|argument| !argument.is_hide_set()) {
        if let Some(long) = argument.get_long() {
            if long != "help" && long != "version" {
                assert!(markdown.contains(&format!("--{long}")), "missing {path} --{long}");
            }
        }
    }
    for child in command.get_subcommands().filter(|child| !child.is_hide_set()) {
        assert_reference_covers_command(child, &format!("{path} {}", child.get_name()), markdown);
    }
}

#[test]
fn generated_references_cover_both_real_command_trees() {
    for command in [rbc::cli::Cli::command(), rbs_cli::config::Cli::command()] {
        command.clone().debug_assert();
        let markdown = clap_markdown::help_markdown_command(&command);
        assert_reference_covers_command(&command, command.get_name(), &markdown);
        assert!(markdown.contains("--agent-config"));
        assert!(markdown.contains("--attest-token"));
        assert!(markdown.contains("--private-key-file"));
    }
}
