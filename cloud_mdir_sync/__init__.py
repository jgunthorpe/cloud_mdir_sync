# SPDX-License-Identifier: GPL-2.0+
import asyncio

# Python 3.6 compatibility
if "create_task" not in dir(asyncio):
    asyncio.create_task = asyncio.ensure_future
