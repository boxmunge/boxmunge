# SPDX-License-Identifier: Apache-2.0
"""The boxmunge action API: one registry of platform actions for every frontend.

Every response the API daemon sends carries API_VERSION. Within a major
version, changes are additive only.
"""

API_VERSION = "1.0"
