# SPDX-License-Identifier: GPL-2.0+
import asyncio
import contextlib
import functools
import inspect
import json
import logging
import time

from . import config


@contextlib.contextmanager
def log_progress_ctx(level, start_msg, end_msg, *args):
    if inspect.isfunction(start_msg):
        start_msg = start_msg(*args)
    if end_msg is None:
        end_msg = " "

    config.logger.log(level, f"Starting {start_msg}")
    st = time.perf_counter()
    try:
        yield
        et = time.perf_counter()
    except Exception as e:
        if inspect.isfunction(end_msg):
            end_msg = end_msg(*args)
        config.logger.warning(f"FAILED({e!r}): {start_msg}")
        raise

    if inspect.isfunction(end_msg):
        end_msg = end_msg(*args)
    if end_msg.startswith("-"):
        start_msg = ""
    config.logger.info(
        f"Completed {start_msg}{end_msg} (took {et-st:.4f} secs)")


def log_progress(start_msg, end_msg=None, level=logging.INFO):
    """Decorator to log the start/end and duration of a method"""
    def inner(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            with log_progress_ctx(level, start_msg, end_msg, self):
                res = func(self, *args, **kwargs)
            return res

        @functools.wraps(func)
        async def async_wrapper(self, *args, **kwargs):
            with log_progress_ctx(level, start_msg, end_msg, self):
                res = await func(self, *args, **kwargs)
            return res

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return inner


# https://stackoverflow.com/questions/1094841/reusable-library-to-get-human-readable-version-of-file-size
def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


def pj(json_dict):
    print(json.dumps(json_dict, indent=4, sort_keys=True))


async def asyncio_complete(*awo_list):
    """This is like asyncio.gather but it always ensures that the list of
    awaitable objects is completed upon return. For instance if an exception
    is thrown then all the awaitables are canceled"""
    g = asyncio.gather(*awo_list)
    try:
        return await g
    finally:
        g.cancel()
        await asyncio.gather(*awo_list, return_exceptions=True)
