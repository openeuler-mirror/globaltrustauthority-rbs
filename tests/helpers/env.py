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

Default HTTP/HTTPS ports are fixed so a single RBS process can bind predictably.
Override per job when CI runs multiple e2e workers on one host; pytest-xdist (-n) is
not supported for the rbs suite unless each worker sets distinct E2E_PORT_* values.
"""

from __future__ import annotations

import os


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


E2E_PORT_HTTP = _parse_int_env("E2E_PORT_HTTP", "47666", min_value=1, max_value=65535)
E2E_PORT_HTTPS = _parse_int_env("E2E_PORT_HTTPS", "47667", min_value=1, max_value=65535)
E2E_WAIT_SECS = _parse_int_env("E2E_WAIT_SECS", "15", min_value=1, max_value=600)
