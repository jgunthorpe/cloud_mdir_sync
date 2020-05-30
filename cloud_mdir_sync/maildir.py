# SPDX-License-Identifier: GPL-2.0+
import logging
import os
import pickle
import re
import time

import pyinotify

from . import config, mailbox, messages, util


def unfold_header(s):
    # Hrm, I wonder if this is the right way to normalize a header?
    return re.sub(r"\n[ \t]+", " ", s)


class MailDirMailbox(mailbox.Mailbox):
    """Local MailDir mail directory"""
    storage_kind = "maildir"
    supported_flags = (messages.Message.FLAG_REPLIED
                       | messages.Message.FLAG_READ
                       | messages.Message.FLAG_FLAGGED
                       | messages.Message.FLAG_DELETED)
    cfg: config.Config

    def __init__(self, cfg: config.Config, directory: str):
        super().__init__(cfg)
        self.dfn = os.path.expanduser(directory)
        for sub in ["tmp", "cur", "new"]:
            os.makedirs(os.path.join(self.dfn, sub), mode=0o700, exist_ok=True)

    async def setup_mbox(self):
        self.cfg.watch_manager.add_watch(
            path=[
                os.path.join(self.dfn, "cur"),
                os.path.join(self.dfn, "new")
            ],
            proc_fun=self._dir_changed,
            mask=(pyinotify.IN_ATTRIB | pyinotify.IN_MOVED_FROM
                  | pyinotify.IN_MOVED_TO
                  | pyinotify.IN_CREATE | pyinotify.IN_DELETE
                  | pyinotify.IN_ONLYDIR),
            quiet=False)

    def _dir_changed(self, notifier):
        self.need_update = True
        self.changed_event.set()

    def _msg_to_flags(self, flags: int):
        """Return the desired maildir flags from a message"""
        # See https://cr.yp.to/proto/maildir.html
        res = set()
        if flags & messages.Message.FLAG_REPLIED:
            res.add("R")
        if flags & messages.Message.FLAG_READ:
            res.add("S")
        if flags & messages.Message.FLAG_FLAGGED:
            res.add("F")
        if flags & messages.Message.FLAG_DELETED:
            res.add("T")
        return res

    def _decode_msg_filename(self, fn):
        """Return the base maildir filename, message flags, and maildir flag
        letters"""
        fn = os.path.basename(fn)
        if ":2," not in fn:
            return (fn, set(), 0)
        fn, _, flags = fn.partition(":2,")
        flags = set(flags)
        mflags = 0
        if "R" in flags:
            mflags |= messages.Message.FLAG_REPLIED
        if "S" in flags:
            mflags |= messages.Message.FLAG_READ
        if "F" in flags:
            mflags |= messages.Message.FLAG_FLAGGED
        if "T" in flags:
            mflags |= messages.Message.FLAG_DELETED
        assert ":2," not in fn
        return (fn, flags, mflags)

    def _load_message(self, fn, ffn):
        sid, _, mflags = self._decode_msg_filename(fn)
        msg = messages.Message(mailbox=self, storage_id=sid)
        msg.flags = mflags
        self.msgdb.msg_from_file(msg, ffn)
        return msg

    def _update_message_dir(self, res, dfn):
        for fn in os.listdir(dfn):
            if fn.startswith("."):
                continue
            msg = self._load_message(fn, os.path.join(dfn, fn))
            res[msg.content_hash] = msg

    @util.log_progress(lambda self: f"Updating Message List for {self.dfn}",
                       lambda self: f", {len(self.messages)} msgs",
                       level=logging.DEBUG)
    @mailbox.update_on_failure
    async def update_message_list(self):
        """Read the message list from the maildir and compute the content hashes"""
        res: messages.CHMsgDict_Type = {}
        st = {}
        for sd in ["cur", "new"]:
            st[sd] = os.stat(os.path.join(self.dfn, sd))
        for sd in ["cur", "new"]:
            self._update_message_dir(res, os.path.join(self.dfn, sd))
        for sd in ["cur", "new"]:
            fn = os.path.join(self.dfn, sd)
            # Retry if the dirs changed while trying to read them
            if os.stat(fn).st_mtime != st[sd].st_mtime:
                raise IOError(f"Maildir {fn} changed during listing")

        self.messages = res
        self.need_update = False
        if self.cfg.trace_file is not None:
            pickle.dump(["update_message_list", self.dfn, self.messages],
                        self.cfg.trace_file)

    def _new_maildir_id(self, msg: messages.Message):
        """Return a unique maildir filename for the given message"""
        tm = time.clock_gettime(time.CLOCK_REALTIME)
        base = f"{int(tm)}.M{int((tm%1)*1000*1000)}-{msg.content_hash}"
        flags = self._msg_to_flags(msg.flags)
        if flags:
            fn = os.path.join(self.dfn, "cur",
                              base + ":2," + "".join(sorted(flags)))
        else:
            fn = os.path.join(self.dfn, "new", base)
        return base, fn

    def _store_msg(self, cloudmsg: messages.Message):
        """Apply a delta from the cloud: New message from cloud"""
        sid, fn = self._new_maildir_id(cloudmsg)
        msg = messages.Message(mailbox=self,
                               storage_id=sid,
                               email_id=cloudmsg.email_id)
        msg.flags = cloudmsg.flags
        msg.content_hash = cloudmsg.content_hash
        assert msg.content_hash is not None
        msg.fn = fn

        self.msgdb.write_content(cloudmsg.content_hash, msg.fn)

        # It isn't clear if we need to do this, but make the local timestamps
        # match when the message would have been received if the local MTA
        # delivered it.
        if cloudmsg.received_time is not None:
            os.utime(fn, (time.time(), cloudmsg.received_time.timestamp()))
        self.msgdb.update_inode_cache(msg)
        self.messages[msg.content_hash] = msg

    def _set_flags(self, mymsg: messages.Message, cloudmsg: messages.Message):
        """Apply a delta from the cloud: Same message in cloud, synchronize flags"""
        if mymsg.flags == cloudmsg.flags:
            return

        # Preserve flags in the local maildir that are not supported on the
        # cloud For instance if the cloud can't store replied then we store it
        # here.
        unsupported_on_cloud_flags = self.supported_flags & (
            messages.Message.ALL_FLAGS ^ cloudmsg.mailbox.supported_flags)
        cloud_flags = ((cloudmsg.flags & cloudmsg.mailbox.supported_flags) |
                       (mymsg.flags & unsupported_on_cloud_flags))
        if mymsg.flags == cloudmsg.flags:
            return

        cloud_flags = self._msg_to_flags(cloud_flags)
        base, mflags, _ = self._decode_msg_filename(mymsg.fn)
        nflags = (mflags - set(("R", "S", "F", "T"))) | cloud_flags
        if mflags == nflags:
            return
        if nflags:
            nfn = os.path.join(self.dfn, "cur",
                               base + ":2," + "".join(sorted(nflags)))
        else:
            nfn = os.path.join(self.dfn, "new", base)
        os.rename(mymsg.fn, nfn)
        mymsg.fn = nfn
        mymsg.flags = cloudmsg.flags

    def _remove_msg(self, mymsg: messages.Message):
        """Apply a delta from the cloud: Message deleted in cloud"""
        assert mymsg.content_hash is not None
        os.unlink(mymsg.fn)
        del self.messages[mymsg.content_hash]

    @util.log_progress(
        lambda self: f"Applying cloud changes for {self.dfn}", lambda self:
        f", {self.last_force_new} added, {self.last_force_rm} removed, {self.last_force_kept} same"
    )
    @mailbox.update_on_failure
    def force_content(self, msgs: messages.CHMsgDict_Type):
        """Force this mailbox to contain the message list msgs (from cloud), including
        all the flags and state"""
        self.last_force_kept = 0
        self.last_force_new = 0
        self.last_force_rm = 0

        have = set(self.messages.keys())
        want = set(msgs.keys())

        for content_hash in want.intersection(have):
            self.last_force_kept += 1
            self._set_flags(self.messages[content_hash], msgs[content_hash])

        for content_hash in want - have:
            self.last_force_new += 1
            self._store_msg(msgs[content_hash])

        for content_hash in have - want:
            self.last_force_rm += 1
            self._remove_msg(self.messages[content_hash])

        if self.cfg.trace_file is not None:
            pickle.dump(["force_content", self.dfn, self.messages, msgs],
                        self.cfg.trace_file)

    async def merge_content(self, msgs):
        raise RuntimeError("Cannot merge local changes into a local mailbox")
