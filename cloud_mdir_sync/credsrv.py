# SPDX-License-Identifier: GPL-2.0+
import asyncio
import contextlib
import os
import re
from typing import List

from . import config, oauth


class CredentialServer(object):
    """Serve XOAUTH2 bearer tokens over a unix domain socket. The client
    writes the user to obtain a token for and the server responds with the
    token. protocols can be IMAP or SMTP"""
    def __init__(self, cfg: config.Config, path: str,
                 accounts: List[oauth.Account], umask, protocols):
        self.cfg = cfg
        self.path = os.path.abspath(os.path.expanduser(path))
        self.umask = umask
        self.accounts = {}
        for I in accounts:
            I.protocols.update(protocols)
            self.accounts[I.user] = I

    async def go(self):
        old_umask = os.umask(self.umask)
        try:
            self.server = await asyncio.start_unix_server(
                self.handle_client, self.path)
        finally:
            os.umask(old_umask)
        os.chmod(self.path, self.umask)

    async def close(self):
        pass

    async def handle_client(self, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> None:
        with contextlib.closing(writer):
            req = await reader.read()
            g = re.match(r"([^ ,]+)(?:,(\S+))? (\S+@\S+)", req.decode())
            if g is None:
                self.cfg.logger.error(f"Invalid credential request {req!r}")
                return
            proto, opts_str, user = g.groups()
            if opts_str:
                opts = opts_str.split(',')
            else:
                opts = []

            self.cfg.logger.debug(
                f"Credential request {proto!r} {opts} {user!r}")

            account = self.accounts.get(user)
            if account is None or proto not in account.protocols:
                return

            xoauth2 = await account.get_xoauth2_bytes(proto)
            if xoauth2 is None:
                return
            writer.write(xoauth2)
            await writer.drain()
