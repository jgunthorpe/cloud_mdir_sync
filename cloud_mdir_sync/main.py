# SPDX-License-Identifier: GPL-2.0+
import argparse
import asyncio
import contextlib
import os
import subprocess
from typing import Dict, Optional, Tuple

import aiohttp
import pyinotify

from . import config, mailbox, messages, oauth
from .util import asyncio_complete


def route_cloud_messages(cfg: config.Config) -> messages.MBoxDict_Type:
    """For every cloud message figure out which local mailbox it belongs to"""
    msgs: messages.MBoxDict_Type = {}
    for mbox in cfg.local_mboxes:
        msgs[mbox] = {}
    for mbox in cfg.cloud_mboxes:
        for ch, msg in mbox.messages.items():
            if ch not in cfg.msgdb.file_hashes:
                config.logger.error(
                    f"Bad CH in route_cloud_messages {ch}, {mbox!r} {msg!r}")
            dest = cfg.direct_message(msg)
            msgs[dest][ch] = msg
    return msgs


def force_local_to_cloud(cfg: config.Config, msgs: messages.MBoxDict_Type):
    """Make all the local mailboxes match their cloud content, overwriting any
    local changes."""
    for mbox, msgdict in msgs.items():
        if not mbox.same_messages(msgdict):
            mbox.force_content(msgdict)
    return msgs


async def update_cloud_from_local(cfg: config.Config,
                                  msgs_by_local: messages.MBoxDict_Type,
                                  offline_mode=False):
    """Detect differences made by the local mailboxes and upload them to the
    cloud."""
    msgs_by_cloud: Dict[mailbox.Mailbox, messages.CHMsgMappingDict_Type] = {}
    for mbox in cfg.cloud_mboxes:
        msgs_by_cloud[mbox] = {}
    for local_mbox, msgdict in msgs_by_local.items():
        for ch, cloud_msg in msgdict.items():
            lmsg = local_mbox.messages.get(ch)
            # When doing the first sweep in offline mode ignore missing local
            # messages, only synchronize message flags.
            if lmsg is None and offline_mode:
                continue
            msgs_by_cloud[cloud_msg.mailbox][ch] = (lmsg, cloud_msg)
    await asyncio_complete(*(
        mbox.merge_content(msgdict) for mbox, msgdict in msgs_by_cloud.items()
        if not mbox.same_messages(msgdict, tuple_form=True)))


async def synchronize_mail(cfg: config.Config):
    """Main synchronizing loop"""
    cfg.web_app = oauth.WebServer()
    cfg.async_tasks.append(cfg.web_app)
    try:
        await asyncio_complete(*(I.go() for I in cfg.async_tasks))
        await asyncio_complete(*(mbox.setup_mbox()
                                 for mbox in cfg.all_mboxes()))

        msgs = None
        while True:
            try:
                await asyncio_complete(*(mbox.update_message_list()
                                         for mbox in cfg.all_mboxes()
                                         if mbox.need_update))

                if msgs is not None:
                    await update_cloud_from_local(cfg, msgs)
                    nmsgs = route_cloud_messages(cfg)
                else:
                    nmsgs = route_cloud_messages(cfg)
                    if cfg.args.OFFLINE:
                        await update_cloud_from_local(cfg,
                                                      nmsgs,
                                                      offline_mode=True)

                force_local_to_cloud(cfg, nmsgs)
                msgs = nmsgs
            except (FileNotFoundError, asyncio.TimeoutError,
                    aiohttp.client_exceptions.ClientError, IOError,
                    RuntimeError, subprocess.CalledProcessError):
                cfg.logger.exception(
                    "Failed update cycle, sleeping then retrying")
                await asyncio.sleep(10)
                continue

            await mailbox.Mailbox.changed_event.wait()
            mailbox.Mailbox.changed_event.clear()
            cfg.msgdb.cleanup_msgs(msgs)
            cfg.logger.debug("Changed event, looping")
    finally:
        for I in cfg.async_tasks:
            await I.close()


def main():
    parser = argparse.ArgumentParser(
        description=
        """Cloud MailDir Sync is able to download email messages from a cloud
        provider and store them in a local maildir. It uses the REST interface
        from the cloud provider rather than IMAP and uses OAUTH to
        authenticate. Once downloaded the tool tracks changes in the local
        mail dir and uploads them back to the cloud.""")
    parser.add_argument("-c",
                        dest="CFG",
                        default="cms.cfg",
                        help="Configuration file to use")
    parser.add_argument(
        "--offline",
        dest="OFFLINE",
        default=False,
        action="store_true",
        help=
        "Enable offline mode, local changes to message flags will be considered authoritative."
    )
    args = parser.parse_args()

    cfg = config.Config()
    cfg.args = args
    cfg.load_config(args.CFG)
    cfg.loop = asyncio.get_event_loop()
    with contextlib.closing(pyinotify.WatchManager()) as wm, \
            contextlib.closing(messages.MessageDB(cfg)) as msgdb:
        pyinotify.AsyncioNotifier(wm, cfg.loop)
        cfg.watch_manager = wm
        cfg.msgdb = msgdb
        cfg.loop.run_until_complete(synchronize_mail(cfg))

    cfg.loop.run_until_complete(cfg.loop.shutdown_asyncgens())
    cfg.loop.close()


if __name__ == "__main__":
    main()
