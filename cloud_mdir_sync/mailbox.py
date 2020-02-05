# SPDX-License-Identifier: GPL-2.0+
import asyncio
import functools
import inspect
from abc import abstractmethod
from typing import TYPE_CHECKING, Dict

if TYPE_CHECKING:
    from . import config
    from messages import MessageDB
    from messages import CHMsgDict_Type
    from messages import CHMsgMappingDict_Type


def update_on_failure(func):
    """Decorator for mailbox class methods that cause the mailbox to need a full
    update if the method throws an exception."""
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except:
            self.need_update = True
            Mailbox.changed_event.set()
            raise

    @functools.wraps(func)
    async def async_wrapper(self, *args, **kwargs):
        try:
            return await func(self, *args, **kwargs)
        except:
            self.need_update = True
            Mailbox.changed_event.set()
            raise

    if inspect.iscoroutinefunction(func):
        return async_wrapper
    return wrapper


class Mailbox(object):
    messages: "CHMsgDict_Type" = {}
    changed_event = asyncio.Event()
    need_update = True
    cfg: "config.Config"

    def __init__(self, cfg: "config.Config"):
        self.cfg = cfg

    @abstractmethod
    async def setup_mbox(self) -> None:
        pass

    @abstractmethod
    def force_content(self, msgdb: "MessageDB",
                      msgs: "CHMsgDict_Type") -> None:
        pass

    @abstractmethod
    async def merge_content(self, msgs: "CHMsgMappingDict_Type") -> None:
        pass

    def same_messages(self,
                      mdict: "CHMsgMappingDict_Type",
                      tuple_form=False) -> bool:
        """Return true if mdict is the same as the local messages"""
        if len(self.messages) != len(mdict):
            return False

        for ch, mmsg in self.messages.items():
            omsg = mdict.get(ch)
            if omsg is None:
                return False

            # update_cloud_from_local use a different dict format
            if tuple_form:
                omsg = omsg[0]  # Check the local mbox
                if omsg is None:
                    return False

            if (mmsg.content_hash != omsg.content_hash
                    or mmsg.flags != omsg.flags):
                return False
        return True
