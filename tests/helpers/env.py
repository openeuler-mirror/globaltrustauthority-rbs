# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

"""Shared e2e environment constants.

Default HTTP and HTTPS ports are fixed so shared RBS processes can bind predictably.
Override per job when CI runs multiple e2e workers on one host; pytest-xdist (-n) is
not supported for the rbs suite unless each worker sets distinct E2E_PORT_* values.
"""

from __future__ import annotations

import os
import socket


def _parse_int_env(name: str, default: str, *, min_value: int, max_value: int) -> int:
    raw = os.environ.get(name, default)
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(
            f"{name} must be an integer (got {raw!r}); unset it or fix the environment"
        ) from exc
    if value < min_value or value > max_value:
        raise ValueError(f"{name} must be between {min_value} and {max_value} (got {value})")
    return value

def get_free_port(start_port: int = 20000, end_port: int = 65535) -> int:
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("0.0.0.0", port))
                return port
            except OSError:
                # port is binded
                continue

    raise RuntimeError(
        f"No available port found between {start_port} and {end_port}"
    )


E2E_PORT_HTTP = _parse_int_env("E2E_PORT_HTTP", "47666", min_value=1, max_value=65535)
E2E_PORT_HTTPS = _parse_int_env("E2E_PORT_HTTPS", "47667", min_value=1, max_value=65535)
E2E_WAIT_SECS = _parse_int_env("E2E_WAIT_SECS", "15", min_value=1, max_value=600)
E2E_LOCAL_ADDR = "127.0.0.1"
E2E_OPENBAO_PORT = get_free_port()
