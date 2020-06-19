# SPDX-License-Identifier: GPL-2.0+
import asyncio
import base64
import collections
import datetime
import functools
import logging
import secrets
from typing import Dict, List, Optional, Set

import aiohttp
import oauthlib

from . import config, mailbox, messages, oauth, util
from .util import asyncio_complete


def _retry_protect(func):
    @functools.wraps(func)
    async def async_wrapper(self, *args, **kwargs):
        while True:
            while self.headers is None:
                await self.authenticate()

            try:
                return await func(self, *args, **kwargs)
            except aiohttp.ClientResponseError as e:
                self.cfg.logger.debug(
                    f"Got HTTP Error {e.code} in {func} for {e.request_info.url!r}"
                )
                if (e.code == 401 or  # Unauthorized
                        e.code == 403):  # Forbidden
                    await self.authenticate()
                    continue
                if (e.code == 503 or  # Service Unavilable
                        e.code == 400 or  # Bad Request
                        e.code == 509 or  # Bandwidth Limit Exceeded
                        e.code == 429 or  # Too Many Requests
                        e.code == 502 or  # Bad Gateway
                        e.code == 504 or  # Gateway Timeout
                        e.code == 200):  # Success, but error JSON
                    self.cfg.logger.error(f"Gmail returns {e}, delaying")
                    await asyncio.sleep(10)
                    continue
                if (e.code == 400 or  # Bad Request
                        e.code == 405 or  # Method Not Allowed
                        e.code == 406 or  # Not Acceptable
                        e.code == 411 or  # Length Required
                        e.code == 413 or  # Request Entity Too Large
                        e.code == 415 or  # Unsupported Media Type
                        e.code == 422 or  # Unprocessable Entity
                        e.code == 501):  # Not implemented
                    self.cfg.logger.exception(f"Gmail call failed {e.body!r}")
                    raise RuntimeError(f"Gmail call failed {e!r}")

                # Other errors we retry after resetting the mailbox
                raise
            except (asyncio.TimeoutError,
                    aiohttp.client_exceptions.ClientError):
                self.cfg.logger.debug(f"Got non-HTTP Error in {func}")
                await asyncio.sleep(10)
                continue

    return async_wrapper


class GmailAPI(oauth.Account):
    """An OAUTH2 authenticated session to the Google gmail API"""
    # From ziepe.ca
    client_id = "14979213351-bik90v3b8b9f22160ura3oah71u3l113.apps.googleusercontent.com"
    # Google doesn't follow RFC8252 8.5 and does require the client_secret,
    # but it is not secret.
    client_secret = "cLICGg-LVQuMAPTh3VxTC42p"
    authenticator = None
    headers: Optional[Dict[str, str]] = None

    def __init__(self, cfg: config.Config, user: str):
        super().__init__(cfg, user)
        self.domain_id = f"gmail-{user}"
        self.mailboxes = []

    async def go(self):
        cfg = self.cfg

        connector = aiohttp.connector.TCPConnector(limit=20, limit_per_host=5)
        self.session = aiohttp.ClientSession(connector=connector,
                                             raise_for_status=False)

        self.scopes = [
            "https://www.googleapis.com/auth/gmail.modify",
        ]
        if self.oauth_smtp:
            self.scopes.append("https://mail.google.com/")

        self.redirect_url = cfg.web_app.url + "oauth2/gmail"
        self.api_token = cfg.msgdb.get_authenticator(self.domain_id)
        self.oauth = oauth.OAuth2Session(
            client_id=self.client_id,
            client=oauth.NativePublicApplicationClient(self.client_id),
            redirect_uri=self.redirect_url,
            token=self.api_token)

        await self._do_authenticate()
        asyncio.create_task(self._poll_for_changes())

    async def _poll_for_changes(self):
        while True:
            await asyncio.sleep(60)
            profile = await self.get_json("v1","/users/me/profile")
            history_id = int(profile["historyId"])
            for mbox in self.mailboxes:
                if (mbox.history_delta is not None
                        and int(mbox.history_delta[1]) < history_id):
                    mbox.need_update = True
                    mbox.changed_event.set()

    def _set_token(self, api_token):
        # Only store the refresh token, access tokens are more dangerous to
        # keep as they are valid across a password change for their lifetime
        self.cfg.msgdb.set_authenticator(
            self.domain_id,
            {"refresh_token": api_token["refresh_token"]})
        # We expect to only use a Authorization header
        self.headers = {
            "Authorization":
            api_token["token_type"] + " " + api_token["access_token"]
        }
        self.api_token = api_token
        return True

    async def _refresh_authenticate(self):
        if self.api_token is None:
            return False

        try:
            api_token = await self.oauth.refresh_token(
                self.session,
                token_url='https://oauth2.googleapis.com/token',
                client_id=self.client_id,
                client_secret=self.client_secret,
                scopes=self.scopes,
                refresh_token=self.api_token["refresh_token"])
        except oauthlib.oauth2.OAuth2Error:
            self.api_token = None
            return False
        return self._set_token(api_token)

    @util.log_progress(lambda self: f"Google Authentication for {self.user}")
    async def _do_authenticate(self):
        while not await self._refresh_authenticate():
            self.api_token = None

            # This flow follows the directions of
            # https://developers.google.com/identity/protocols/OAuth2InstalledApp
            state = hex(id(self)) + secrets.token_urlsafe(8)
            url = self.oauth.authorization_url(
                'https://accounts.google.com/o/oauth2/v2/auth',
                state=state,
                access_type="offline",
                scopes=self.scopes,
                login_hint=self.user)

            q = await self.cfg.web_app.auth_redir(url, state,
                                                  self.redirect_url)

            api_token = await self.oauth.fetch_token(
                self.session,
                'https://oauth2.googleapis.com/token',
                include_client_id=True,
                client_secret=self.client_secret,
                scopes=self.scopes,
                code=q["code"])
            if self._set_token(api_token):
                return

    async def authenticate(self):
        """Obtain OAUTH bearer tokens for MS services. For users this has to be done
        interactively via the browser. A cache is used for tokens that have
        not expired and they can be refreshed non-interactively into active
        tokens within some limited time period."""
        # Ensure we only ever have one authentication open at once. Other
        # threads will all block here on the single authenticator.
        self.headers = None
        if self.authenticator is None:
            self.authenticator = asyncio.create_task(self._do_authenticate())
        auth = self.authenticator
        await auth
        if self.authenticator is auth:
            self.authenticator = None

    async def _check_op(self, op: aiohttp.ClientResponse):
        if op.status >= 200 and op.status <= 299:
            return
        e = aiohttp.ClientResponseError(op.request_info,
                                        op.history,
                                        code=op.status,
                                        message=op.reason,
                                        headers=op.headers)
        try:
            e.body = await op.json()
        except:
            pass
        raise e

    async def _check_json(self, op: aiohttp.ClientResponse):
        await self._check_op(op)
        return await op.json()

    async def _check_empty(self, op: aiohttp.ClientResponse):
        await self._check_op(op)
        d = await op.text()
        if d:
            e = aiohttp.ClientResponseError(
                op.request_info,
                op.history,
                code=op.status,
                message="POST returned data, not empty",
                headers=op.headers)
            raise e

    @_retry_protect
    async def get_json(self, ver, path, params=None):
        """Return the JSON dictionary from the GET operation"""
        async with self.session.get(
                f"https://www.googleapis.com/gmail/{ver}{path}",
                headers=self.headers,
                params=params) as op:
            return await self._check_json(op)

    @_retry_protect
    async def post_json(self, ver, path, body, params=None):
        """Return the JSON dictionary from the POST operation"""
        async with self.session.post(
                f"https://www.googleapis.com/gmail/{ver}{path}",
                headers=self.headers,
                json=body,
                params=params) as op:
            return await self._check_empty(op)

    async def get_json_paged(self,
                             ver,
                             path,
                             key,
                             params=None,
                             last_json=None):
        """Return an iterator that iterates over every JSON element in a paged
        result. last_json is a list that will contain only the last json dict
        returned"""
        params = dict(params)
        resp = await self.get_json(ver, path, params)
        while True:
            for I in resp.get(key, []):
                yield I
            token = resp.get("nextPageToken")
            if token is None:
                if last_json is not None:
                    last_json[:] = [resp]
                return
            # FIXME: Is this right, or should we drop the other params?
            params["pageToken"] = token
            resp = await self.get_json(ver, path, params=params)

    async def close(self):
        await self.session.close()

    async def get_xoauth2_bytes(self, proto: str) -> bytes:
        """Return the xoauth2 byte string for the given protocol to login to
        this account."""
        while self.api_token is None:
            await self.authenticate()

        if proto == "SMTP":
            res = 'user=%s\1auth=%s %s\1\1' % (self.user,
                                               self.api_token["token_type"],
                                               self.api_token["access_token"])
            return res.encode()
        return None


class GMailMessage(messages.Message):
    gmail_labels: Optional[Set[str]] = None

    def __init__(self, mailbox, gmail_id, gmail_labels=None):
        super().__init__(mailbox=mailbox, storage_id=gmail_id)
        # GMail does not return the email_id, but it does have a stable REST
        # ID, so if we have the REST ID in the database then we can compute
        # the email_id
        self.content_hash = mailbox.msgdb.content_hashes_cloud.get(
            self.cid())
        if self.content_hash:
            self.fill_email_id()
        self.gmail_labels = gmail_labels
        if self.gmail_labels:
            self._labels_to_flags()

    def _labels_to_flags(self):
        assert self.gmail_labels is not None
        flags = 0
        if "UNREAD" not in self.gmail_labels:
            flags |= messages.Message.FLAG_READ
        if "STARRED" in self.gmail_labels:
            flags |= messages.Message.FLAG_FLAGGED
        # Unfortunately other IMAP flags do not seem to be available through
        # the REST interface
        self.flags = flags

    def update_from_json(self, jmsg):
        self.gmail_labels = set(jmsg["labelIds"])
        internal_date = int(jmsg["internalDate"])
        self.received_time = datetime.datetime.fromtimestamp(internal_date /
                                                             1000.0)

        self._labels_to_flags()
        if "payload" in jmsg:
            for hdr in jmsg["payload"]["headers"]:
                if hdr["name"].lower() == "message-id":
                    if self.email_id is None:
                        self.email_id = hdr["value"]
                    else:
                        assert self.email_id == hdr["value"]
                    break


class GMailMailbox(mailbox.Mailbox):
    """Cloud GMail mailbox using the GMail RESET API for data access"""
    storage_kind = "gmail_v1"
    supported_flags = (messages.Message.FLAG_READ
                       | messages.Message.FLAG_FLAGGED
                       | messages.Message.FLAG_DELETED)
    gmail: GmailAPI
    gmail_messages: Dict[str, GMailMessage]
    history_delta = None
    delete_action = "archive" # or delete

    def __init__(self, cfg: config.Config, label: str, gmail: GmailAPI):
        super().__init__(cfg)
        self.label_name = label
        self.gmail = gmail
        self.gmail_messages = {}
        self.max_fetches = asyncio.Semaphore(10)
        gmail.mailboxes.append(self)

    def __repr__(self):
        return f"<GMailMailbox at {id(self):x} for {self.gmail.domain_id} {self.label_name}>"

    async def setup_mbox(self):
        """Setup access to the authenticated API domain for this endpoint"""
        self.name = f"{self.gmail.user}:{self.label_name}"

        # Verify the label exists
        jmsg = await self.gmail.get_json("v1", f"/users/me/labels")
        for I in jmsg["labels"]:
            if I["name"] == self.label_name:
                self.label = I["id"]
                break
        else:
            raise ValueError(f"GMail label {self.label_name!r} not found")

    async def _fetch_metadata(self, msg: GMailMessage):
        params = {"format": "metadata"}
        if msg.email_id is None:
            params["metadataHeaders"] = "message-id"
        jmsg = await self.gmail.get_json(
            "v1", f"/users/me/messages/{msg.storage_id}", params=params)
        msg.update_from_json(jmsg)
        return jmsg["historyId"]

    async def _fetch_message(self, msg: GMailMessage):
        msgdb = self.msgdb
        msg.size = 0
        async with self.max_fetches:
            with util.log_progress_ctx(
                    logging.DEBUG, f"Downloading {msg.storage_id}",
                    lambda msg: f" {util.sizeof_fmt(msg.size)}",
                    msg), msgdb.get_temp() as F:
                jmsg = await self.gmail.get_json(
                    "v1",
                    f"/users/me/messages/{msg.storage_id}",
                    params={
                        "format": "raw",
                    })
                data = base64.urlsafe_b64decode(jmsg["raw"])
                data = data.replace(b"\r\n", b"\n")
                F.write(data)
                msg.size = F.tell()
                msg.update_from_json(jmsg)
                msg.content_hash = msgdb.store_hashed_msg(msg, F)
        return jmsg["historyId"]

    async def _fetch_all_messages(self):
        """Perform a full synchronization of the mailbox"""
        profile = await self.gmail.get_json("v1","/users/me/profile")
        start_history_id = profile["historyId"]

        todo = []
        msgs = []
        async for jmsg in self.gmail.get_json_paged(
                "v1",
                "/users/me/messages",
                key="messages",
                params={"labelIds": self.label}):
            msg = GMailMessage(mailbox=self, gmail_id=jmsg["id"])
            if not self.msgdb.have_content(msg):
                todo.append(
                    asyncio.create_task(self._fetch_message(msg)))
            else:
                todo.append(asyncio.create_task(self._fetch_metadata(msg)))
            msgs.append(msg)
        await asyncio_complete(*todo)

        return (msgs, start_history_id)

    async def _fetch_delta_messages(self, old_msgs: List[GMailMessage],
                                    start_history_id: Optional[str]):
        # Mailbox is empty
        if start_history_id is None:
            assert not old_msgs
            return old_msgs, None

        gmsgs = {msg.storage_id: set(msg.gmail_labels) for msg in old_msgs}

        def add_message(jmsg):
            jmsg = jmsg["message"]
            gmail_id = jmsg["id"]
            if "labelIds" in jmsg:
                gmsgs[gmail_id] = labels = set(jmsg["labelIds"])
            else:
                if gmail_id not in msgs:
                    gmsgs[gmail_id] = labels = set()
                else:
                    labels = gmsgs[gmail_id]
            return gmail_id, labels

        last_history = []
        async for jhistory in self.gmail.get_json_paged(
                "v1",
                "/users/me/history",
                key="history",
                params={
                    "labelId": self.label,
                    "startHistoryId": start_history_id
                },
                last_json=last_history):
            jf = jhistory.get("messagesAdded")
            if jf:
                for jmsg in jf:
                    gmail_id, _ = add_message(jmsg)
            jf = jhistory.get("labelsAdded")
            if jf:
                for jmsg in jf:
                    _, labels = add_message(jmsg)
                    labels.update(jmsg["labelIds"])
            jf = jhistory.get("labelsRemoved")
            if jf:
                for jmsg in jf:
                    _, labels = add_message(jmsg)
                    for I in jmsg["labelIds"]:
                        labels.discard(I)
            # Deleted means permanently deleted
            jf = jhistory.get("messagesDeleted")
            if jf:
                for jmsg in jf:
                    gmail_id, labels = add_message(jmsg)
                    gmsgs.pop(gmail_id, None)

        next_history_id = last_history[0]["historyId"]
        old_msgs_map = {msg.storage_id: msg for msg in old_msgs}
        todo = []
        msgs = []
        for gmail_id, gmail_labels in gmsgs.items():
            if self.label not in gmail_labels:
                continue
            omsg = old_msgs_map.get(gmail_id)
            if omsg is None:
                msg = GMailMessage(mailbox=self,
                                   gmail_id=gmail_id,
                                   gmail_labels=gmail_labels)
                if not self.msgdb.have_content(msg):
                    todo.append(
                        asyncio.create_task(self._fetch_message(msg)))
                else:
                    todo.append(asyncio.create_task(self._fetch_metadata(msg)))
            else:
                msg = GMailMessage(mailbox=self,
                                   gmail_id=gmail_id,
                                   gmail_labels=gmail_labels)
                msg.received_time = omsg.received_time
                assert self.msgdb.have_content(msg)
            msgs.append(msg)
        await asyncio_complete(*todo)
        return (msgs, next_history_id)

    @util.log_progress(lambda self: f"Updating Message List for {self.name}",
                       lambda self: f", {len(self.messages)} msgs")
    @mailbox.update_on_failure
    async def update_message_list(self):
        """Retrieve the list of all messages and store all the message content
        in the content_hash message database"""
        if self.history_delta is None:
            # For whatever reason, there is usually more history than is
            # suggested by the history_id from the messages.list, so always
            # drain it out.
            self.history_delta = await self._fetch_all_messages()

        try:
            self.history_delta = await self._fetch_delta_messages(
                start_history_id=self.history_delta[1],
                old_msgs=self.history_delta[0])
        except:
            # If we fail to read a delta then the history is lost/garbage,
            # start again from full sync.
            self.history_delta = None;
            raise

        self.messages = {
            msg.content_hash: msg
            for msg in self.history_delta[0] if msg.content_hash is not None
        }
        self.need_update = False

    def force_content(self, msgs):
        raise RuntimeError("Cannot move messages into the Cloud")

    def _update_msg_flags(self, cmsg: messages.Message, old_cmsg_flags: int,
                          lmsg: messages.Message, label_edits):
        lflags = lmsg.flags & (messages.Message.ALL_FLAGS
                               ^ messages.Message.FLAG_DELETED)
        if lflags == old_cmsg_flags or lflags == cmsg.flags:
            return None

        cloud_flags = cmsg.flags ^ old_cmsg_flags
        flag_mask = messages.Message.ALL_FLAGS ^ cloud_flags
        nflags = (lflags & flag_mask) | (cmsg.flags & cloud_flags)
        modified_flags = nflags ^ cmsg.flags
        if modified_flags & messages.Message.FLAG_READ:
            label_edits[("-" if nflags & messages.Message.FLAG_READ else "+") +
                        "UNREAD"].add(cmsg.storage_id)
        if modified_flags & messages.Message.FLAG_FLAGGED:
            label_edits[("+" if nflags
                         & messages.Message.FLAG_FLAGGED else "-") +
                        "STARRED"].add(cmsg.storage_id)
        # FLAG_REPLIED is not supported
        cmsg.flags = nflags

    @staticmethod
    def _next_edit(label_edits):
        """Break up the edit list into groups of IDs. The algorithm picks
        groupings of IDs that have matching label changes, and returns every
        ID exactly once."""
        sets = list(label_edits.values())
        while True:
            gmail_ids = functools.reduce(lambda x, y: x & y, sets)
            if gmail_ids:
                if len(gmail_ids) > 50:
                    return set(sorted(gmail_ids)[:50])
                return set(gmail_ids)

            # Pick an arbitary ID and advance its group of labels. The above
            # reduction must return at least todo_gmail_id.
            todo_gmail_id = next(iter(sets[0]))
            sets = [I for I in sets if todo_gmail_id in I]

    @util.log_progress(lambda self: f"Uploading local changes for {self.name}",
                       lambda self: f", {self.last_merge_len} changes ")
    @mailbox.update_on_failure
    async def merge_content(self, msgs: messages.CHMsgMappingDict_Type):
        self.last_merge_len = 0
        label_edits: Dict[str, Set[str]] = collections.defaultdict(set)
        for ch, mpair in msgs.items():
            # lmsg is the message in the local mailbox
            # cmsg is the current cloud message in this class
            # old_cmsg is the original cloud message from the last sync
            lmsg, old_cmsg = mpair
            cmsg = self.messages.get(ch)
            assert old_cmsg is not None

            # Update flags
            if cmsg is not None and old_cmsg is not None and lmsg is not None:
                self._update_msg_flags(cmsg, old_cmsg.flags, lmsg, label_edits)

            if cmsg is not None and (lmsg is None or lmsg.flags
                                     & messages.Message.FLAG_DELETED):
                # To archive skip the +TRASH
                if self.delete_action == "delete":
                    label_edits["+TRASH"].add(cmsg.storage_id)
                label_edits["-" + self.label].add(cmsg.storage_id)
                del self.messages[ch]

        empty: Set[str] = set()
        self.last_merge_len = len(
            functools.reduce(lambda x, y: x | y, label_edits.values(), empty))

        # Group all the label changes for a single ID together and then batch
        # them
        while label_edits:
            gmail_ids = self._next_edit(label_edits)
            labels = []
            for k, v in list(label_edits.items()):
                if gmail_ids.issubset(v):
                    labels.append(k)
                    v.difference_update(gmail_ids)
                if not v:
                    del label_edits[k]

            labels.sort()
            body = {"ids": sorted(gmail_ids)}
            add_labels = [I[1:] for I in labels if I[0] == "+"]
            if add_labels:
                body["addLabelIds"] = add_labels
            remove_labels = [I[1:] for I in labels if I[0] == "-"]
            if remove_labels:
                body["removeLabelIds"] = remove_labels
            await self.gmail.post_json("v1",
                                       f"/users/me/messages/batchModify",
                                       body=body)
