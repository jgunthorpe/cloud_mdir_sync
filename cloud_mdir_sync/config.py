# SPDX-License-Identifier: GPL-2.0+
import asyncio
import itertools
import logging
import os
from typing import TYPE_CHECKING, Any, Dict, List

import pyinotify

if TYPE_CHECKING:
    from . import messages, mailbox, oauth

logger: logging.Logger


class Config(object):
    """Program configuration and general global state"""
    message_db_dir = "~/mail/.cms/"
    trace_file: Any = None
    web_app: "oauth.WebServer"
    logger: logging.Logger
    loop: asyncio.AbstractEventLoop
    watch_manager: pyinotify.WatchManager
    msgdb: "messages.MessageDB"
    cloud_mboxes: "List[mailbox.Mailbox]"
    local_mboxes: "List[mailbox.Mailbox]"

    def _create_logger(self):
        global logger
        logger = logging.getLogger('cloud-mdir-sync')
        logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setFormatter(
            logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s',
                              datefmt='%m-%d %H:%M:%S'))
        ch.setLevel(logging.DEBUG)
        logger.addHandler(ch)
        self.logger = logger

    def __init__(self):
        self._create_logger()
        self.cloud_mboxes = []
        self.local_mboxes = []
        self.async_tasks = []
        self.message_db_dir = os.path.expanduser(self.message_db_dir)
        self.direct_message = self._direct_message

    def load_config(self, fn):
        """The configuration file is a python script that we execute with
        capitalized functions of this class injected into it"""
        fn = os.path.expanduser(fn)
        with open(fn, "r") as F:
            pyc = compile(source=F.read(), filename=fn, mode="exec")

        g = {"cfg": self}
        for k in dir(self):
            if k[0].isupper():
                g[k] = getattr(self, k)
        eval(pyc, g)

    @property
    def storage_key(self):
        """The storage key is used with fernet to manage the authentication
        data, which is stored to disk using symmetric encryption. The
        decryption key is keld by the system keyring in some secure storage.
        On Linux desktop systems this is likely to be something like
        gnome-keyring."""
        import keyring
        from cryptography.fernet import Fernet

        ring = keyring.get_keyring()
        try:
            res = ring.get_password("cloud_mdir_sync", "storage")
        except keyring.errors.NoKeyringError:
            return Fernet.generate_key()

        if res is None:
            res = Fernet.generate_key()
            ring.set_password("cloud_mdir_sync", "storage", res)
        return res

    def all_mboxes(self):
        return itertools.chain(self.local_mboxes, self.cloud_mboxes)

    def Office365_Account(self, user=None, tenant="common", client_id="122f4826-adf9-465d-8e84-e9d00bc9f234"):
        """Define an Office365 account credential. If user is left as None
        then the browser will prompt for the user and the choice will be
        cached. To lock the account to a single tenant specify the Azure
        Directory name, ie 'contoso.onmicrosoft.com', or the GUID."""
        from .office365 import GraphAPI
        self.async_tasks.append(GraphAPI(self, user, tenant, client_id))
        return self.async_tasks[-1]

    def Office365(self, mailbox, account):
        """Create a cloud mailbox for Office365. Mailbox is the name of O365
        mailbox to use, account should be the result of Office365_Account"""
        from .office365 import O365Mailbox
        self.cloud_mboxes.append(
            O365Mailbox(self, mailbox, account))
        return self.cloud_mboxes[-1]

    def GMail_Account(self, user):
        """Define a GMail account credential. The user must be specified as a
        fully qualified Google Account email address. This supports both
        consumer GMail accounts, and accounts linked to a G-Suite account."""
        from .gmail import GmailAPI
        self.async_tasks.append(GmailAPI(self, user))
        return self.async_tasks[-1]

    def GMail(self, label, account):
        """Create a cloud mailbox for Office365. Mailbox is the name of O365
        mailbox to use, account should be the result of Office365_Account"""
        from .gmail import GMailMailbox
        self.cloud_mboxes.append(GMailMailbox(self, label, account))
        return self.cloud_mboxes[-1]

    def MailDir(self, directory):
        """Create a local maildir to hold messages"""
        from .maildir import MailDirMailbox
        self.local_mboxes.append(MailDirMailbox(self, directory))
        return self.local_mboxes[-1]

    def CredentialServer(self,
                         path: str,
                         accounts: List,
                         umask=0o600,
                         protocols=["SMTP"]):
        """Serve XOAUTH2 bearer tokens over a unix domain socket. The client
        writes the user to obtain a token for and the server responds with the
        token. protocols can be IMAP or SMTP. The cms-oauth program interacts
        with this server."""
        from .credsrv import CredentialServer
        self.async_tasks.append(
            CredentialServer(self, path, accounts, umask, protocols))
        return self.async_tasks[-1]

    def _direct_message(self, msg):
        return self.local_mboxes[0]
