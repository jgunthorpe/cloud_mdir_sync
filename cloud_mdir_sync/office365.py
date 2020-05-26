# SPDX-License-Identifier: GPL-2.0+
import asyncio
import datetime
import functools
import logging
import os
import pickle
import secrets
import webbrowser
from typing import Any, Dict, Optional, Union

import aiohttp
import requests

from . import config, mailbox, messages, util
from .util import asyncio_complete


def _retry_protect(func):
    # Graph can return various error codes, see:
    # https://docs.microsoft.com/en-us/graph/errors
    @functools.wraps(func)
    async def async_wrapper(self, *args, **kwargs):
        while True:
            while (self.graph_token is None or self.owa_token is None):
                await self.authenticate()

            try:
                return await func(self, *args, **kwargs)
            except aiohttp.ClientResponseError as e:
                self.cfg.logger.debug(
                    f"Got HTTP Error {e.code} in {func} for {e.request_info.url!r}"
                )
                if (e.code == 401 or  # Unauthorized
                        e.code == 403):  # Forbidden
                    self.graph_token = None
                    self.owa_token = None
                    await self.authenticate()
                    continue
                if (e.code == 503 or  # Service Unavilable
                        e.code == 509 or  # Bandwidth Limit Exceeded
                        e.code == 429 or  # Too Many Requests
                        e.code == 504 or  # Gateway Timeout
                        e.code == 200):  # Success, but error JSON
                    self.cfg.logger.error(f"Graph returns {e}, delaying")
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
                    self.cfg.logger.exception(f"Graph call failed {e.body!r}")
                    raise RuntimeError(f"Graph call failed {e!r}")

                # Other errors we retry after resetting the mailbox
                raise
            except (asyncio.TimeoutError,
                    aiohttp.client_exceptions.ClientError):
                self.cfg.logger.debug(f"Got non-HTTP Error in {func}")
                await asyncio.sleep(10)
                continue

    return async_wrapper


class GraphAPI(object):
    """An OAUTH2 authenticated session to the Microsoft Graph API"""
    graph_scopes = [
        "https://graph.microsoft.com/User.Read",
        "https://graph.microsoft.com/Mail.ReadWrite"
    ]
    graph_token = None
    owa_scopes = ["https://outlook.office.com/mail.read"]
    owa_token = None
    authenticator = None

    def __init__(self, cfg: config.Config, user: str, tenant: str):
        self.domain_id = f"o365-{user}-{tenant}"
        self.cfg = cfg
        self.user = user
        self.tenant = tenant

        if self.user is not None:
            self.name = f"{self.user}//{tenant}"
        else:
            self.name = f"//{tenant}"

        # Use the new format much more immutable ids, this will work better
        # with our caching scheme. See
        # https://docs.microsoft.com/en-us/graph/outlook-immutable-id
        self.headers= {"Prefer": 'IdType="ImmutableId"'}
        self.owa_headers = {}

    async def go(self):
        import msal
        self.msl_cache = msal.SerializableTokenCache()
        auth = self.cfg.msgdb.get_authenticator(self.domain_id)
        if auth is not None:
            self.msl_cache.deserialize(auth)

        connector = aiohttp.connector.TCPConnector(limit=20, limit_per_host=5)
        self.session = aiohttp.ClientSession(connector=connector,
                                             raise_for_status=False)

        self.msal = msal.PublicClientApplication(
            client_id="122f4826-adf9-465d-8e84-e9d00bc9f234",
            authority=f"https://login.microsoftonline.com/{self.tenant}",
            token_cache=self.msl_cache)

    def _cached_authenticate(self):
        accounts = self.msal.get_accounts(self.user)
        if len(accounts) != 1:
            return False

        try:
            if self.graph_token is None:
                self.graph_token = self.msal.acquire_token_silent(
                    scopes=self.graph_scopes, account=accounts[0])
            if self.graph_token is None or "access_token" not in self.graph_token:
                self.graph_token = None
                return False

            if self.owa_token is None:
                self.owa_token = self.msal.acquire_token_silent(
                    scopes=self.owa_scopes, account=accounts[0])
            if self.owa_token is None or "access_token" not in self.owa_token:
                self.owa_token = None
                return False
        except requests.RequestException as e:
            self.cfg.logger.error(f"msal failed on request {e}")
            self.graph_token = None
            self.owa_token = None
            return False

        self.headers["Authorization"] = self.graph_token[
            "token_type"] + " " + self.graph_token["access_token"]
        self.owa_headers["Authorization"] = self.owa_token[
            "token_type"] + " " + self.owa_token["access_token"]
        self.cfg.msgdb.set_authenticator(self.domain_id,
                                         self.msl_cache.serialize())
        return True

    @util.log_progress(lambda self: f"Azure AD Authentication for {self.name}")
    async def _do_authenticate(self):
        while not self._cached_authenticate():
            self.graph_token = None
            self.owa_token = None

            redirect_url = self.cfg.web_app.url + "oauth2/msal"
            state = hex(id(self)) + secrets.token_urlsafe(8)
            url = self.msal.get_authorization_request_url(
                scopes=self.graph_scopes + self.owa_scopes,
                state=state,
                login_hint=self.user,
                redirect_uri=redirect_url)

            print(
                f"Goto {self.cfg.web_app.url} in a web browser to authenticate"
            )
            webbrowser.open(url)
            q = await self.cfg.web_app.auth_redir(url, state, redirect_url)
            code = q["code"]

            try:
                self.graph_token = self.msal.acquire_token_by_authorization_code(
                    code=code,
                    scopes=self.graph_scopes,
                    redirect_uri=redirect_url)
            except requests.RequestException as e:
                self.cfg.logger.error(f"msal failed on request {e}")
                await asyncio.sleep(10)

    async def authenticate(self):
        """Obtain OAUTH bearer tokens for MS services. For users this has to be done
        interactively via the browser. A cache is used for tokens that have
        not expired and they can be refreshed non-interactively into active
        tokens within some limited time period."""
        # Ensure we only ever have one authentication open at once. Other
        # threads will all block here on the single authenticator.
        if self.authenticator is None:
            self.authenticator = asyncio.create_task(self._do_authenticate())
        auth = self.authenticator
        await auth
        if self.authenticator is auth:
            self.authenticator = None

    async def _check_op(self, op):
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

    async def _check_json(self, op):
        """Check an operation for errors and convert errors to exceptions. Graph can
        return an HTTP failure code, or (rarely) a JSON error message and a 200 success."""
        await self._check_op(op)

        res = await op.json()
        if "error" in res:
            e = aiohttp.ClientResponseError(op.request_info,
                                            op.history,
                                            code=op.status,
                                            message=op.reason,
                                            headers=op.headers)
            e.body = res
            raise e
        return res

    @_retry_protect
    async def get_to_file(self, outf, ver, path, params=None, dos2unix=False):
        """Copy the response of a GET operation into outf"""
        async with self.session.get(f"https://graph.microsoft.com/{ver}{path}",
                                    headers=self.headers,
                                    params=params) as op:
            await self._check_op(op)
            carry = b""
            async for data in op.content.iter_any():
                if dos2unix:
                    if carry:
                        data = carry + data
                    data = data.replace(b"\r\n", b"\n")
                    if data[-1] == b'\r':
                        carry = data[-1:len(data)]
                        data = data[:-1]
                    else:
                        carry = b""
                outf.write(data)
            if dos2unix and carry:
                outf.write(carry)

    @_retry_protect
    async def get_json(self, ver, path, params=None):
        """Return the JSON dictionary from the GET operation"""
        async with self.session.get(f"https://graph.microsoft.com/{ver}{path}",
                                    headers=self.headers,
                                    params=params) as op:
            return await self._check_json(op)

    @_retry_protect
    async def post_json(self, ver, path, body, params=None):
        """Return the JSON dictionary from the POST operation"""
        async with self.session.post(
                f"https://graph.microsoft.com/{ver}{path}",
                headers=self.headers,
                json=body,
                params=params) as op:
            return await self._check_json(op)

    @_retry_protect
    async def patch_json(self, ver, path, body, params=None):
        """Return the JSON dictionary from the PATCH operation"""
        async with self.session.patch(
                f"https://graph.microsoft.com/{ver}{path}",
                headers=self.headers,
                json=body,
                params=params) as op:
            return await self._check_json(op)

    @_retry_protect
    async def delete(self, ver, path):
        """Issue a delete. For Messages delete doesn't put it in the Deleted Items
        folder, it is just deleted."""
        async with self.session.delete(
                f"https://graph.microsoft.com/{ver}{path}",
                headers=self.headers) as op:
            await self._check_op(op)
            async for _ in op.content.iter_any():
                pass

    async def get_json_paged(self, ver, path, params=None):
        """Return an iterator that iterates over every JSON element in a paged
        result"""
        # See https://docs.microsoft.com/en-us/graph/paging
        resp = await self.get_json(ver, path, params)
        while True:
            for I in resp["value"]:
                yield I
            uri = resp.get("@odata.nextLink")
            if uri is None:
                break
            async with self.session.get(uri, headers=self.headers) as op:
                resp = await self._check_json(op)

    @_retry_protect
    async def owa_subscribe(self, resource, changetype):
        """Graph does not support streaming subscriptions, so we use the OWA interface
        instead. See

        https://docs.microsoft.com/en-us/previous-versions/office/office-365-api/api/beta/notify-streaming-rest-operations"""
        body = {
            "@odata.type": "#Microsoft.OutlookServices.StreamingSubscription",
            "Resource": resource,
            "ChangeType": changetype
        }

        async with self.session.post(
                f"https://outlook.office.com/api/beta/me/subscriptions",
                headers=self.owa_headers,
                json=body) as op:
            return await self._check_json(op)

    async def owa_get_notifications(self, subscription_id):
        """Return the notifications as an async iterator"""
        body = {
            "ConnectionTimeoutInMinutes": 2,
            "KeepAliveNotificationIntervalInSeconds": 10,
            "SubscriptionIds": [subscription_id]
        }
        timeout = aiohttp.ClientTimeout(sock_read=20)
        # FIXME: fine tune timeouts https://docs.aiohttp.org/en/stable/client_quickstart.html#timeouts
        # FIXME: retry protect for this
        async with self.session.post(
            f"https://outlook.office.com/api/beta/Me/GetNotifications",
            headers=self.owa_headers,
            json=body,
            timeout=timeout) as op:
            await self._check_op(op)

            # There seems to be no relation to http chunks and json fragments,
            # other than the last chunk before sleeping terminates all the
            # jsons. I guess this is supposed to be parsed using a fancy
            # parser. FIXME: We do need to parse this to exclude the keep alives
            first = True
            buf = b""
            async for data, chunk_end in op.content.iter_chunks():
                buf += data
                if not chunk_end:
                    continue

                # Last, but probably not reliably so
                if buf == b']}':
                    return

                if not first:
                    yield buf
                else:
                    first = False
                buf = b""

    async def close(self):
        await self.session.close()


class O365Mailbox(mailbox.Mailbox):
    """Cloud Office365 mailbox using the Microsoft Graph RESET API for data access"""
    storage_kind = "o365_v0"
    supported_flags = (messages.Message.FLAG_REPLIED
                       | messages.Message.FLAG_READ
                       | messages.Message.FLAG_FLAGGED
                       | messages.Message.FLAG_DELETED)
    loop: asyncio.AbstractEventLoop
    timer = None
    use_owa_subscribe = True
    graph: GraphAPI
    delete_action = "archive" # or delete

    def __init__(self,
                 cfg: config.Config,
                 mailbox: str,
                 graph: GraphAPI):
        super().__init__(cfg)
        self.mailbox = mailbox
        self.graph = graph

    async def setup_mbox(self):
        """Setup access to the authenticated API domain for this endpoint"""
        cfg = self.cfg
        self.loop = cfg.loop
        self.name = f"{self.graph.name}:{self.mailbox}"

        json = await self.graph.get_json(
            "v1.0",
            f"/me/mailFolders",
            params={"$filter": f"displayName eq '{self.mailbox}'"})
        if len(json["value"]) != 1:
            raise ValueError(f"Invalid mailbox name {self.mailbox!r}")
        self.json = json["value"][0]

        self.mailbox_id = self.json["id"]
        if self.use_owa_subscribe:
            asyncio.create_task(self._monitor_changes())

    @mailbox.update_on_failure
    async def _fetch_message(self, msg: messages.Message):
        msgdb = self.msgdb
        msg.size = 0
        with util.log_progress_ctx(logging.DEBUG,
                                   f"Downloading {msg.email_id}",
                                   lambda msg: f" {util.sizeof_fmt(msg.size)}",
                                   msg), msgdb.get_temp() as F:
            # For some reason this returns a message with dos line
            # endings. Really weird.
            await self.graph.get_to_file(
                F,
                "v1.0",
                f"/me/messages/{msg.storage_id}/$value",
                dos2unix=True)
            msg.size = F.tell()
            msg.content_hash = msgdb.store_hashed_msg(msg, F)

    def _json_to_flags(self, jmsg):
        """This is was remarkably difficult to find out, and seems completely
        undocumented."""
        flags = 0
        # First class properties are easy
        if bool(jmsg["isRead"]):
            flags |= messages.Message.FLAG_READ
        if jmsg["flag"]["flagStatus"] == "flagged":
            flags |= messages.Message.FLAG_FLAGGED

        # 'Replied' is not a concept in MAPI, at least not a consistent concept.
        for prop in jmsg.get("singleValueExtendedProperties", []):
            if prop["id"] == "Integer 0x1080":
                # Closely matches OWA and the Outlook App
                # PidTagIconIndex
                # https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/eeca3a02-14e7-419b-8918-986275a2fac0
                val = int(prop["value"])
                if (val == 0x105 or  # Replied mail
                        val == 0x106):  # Forwarded mail
                    flags |= messages.Message.FLAG_REPLIED
            elif prop["id"] == "Integer 0x1081":
                # Sort of matches OWA and the Outlook App
                # PidTagLastVerbExecuted
                # https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/4ec55eac-14b3-4dfa-adf3-340c0dcccd44
                val = int(prop["value"])
                if (val == 102 or  # NOTEIVERB_REPLYTOSENDER
                        val == 103 or  # NOTEIVERB_REPLYTOALL
                        val == 104):  # NOTEIVERB_FORWARD
                    flags |= messages.Message.FLAG_REPLIED
            elif prop["id"] == "Integer 0xe17":
                # This is what IMAP uses but we can't set it
                # PidTagMessageStatus
                # https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/5d00fe2b-9548-4953-97ba-89b1aa0ba5ac
                if int(prop["value"]) & 0x200:  # MSGSTATUS_ANSWERED
                    flags |= messages.Message.FLAG_REPLIED
            else:
                util.pj(prop)
        return flags

    @util.log_progress(lambda self: f"Updating Message List for {self.name}",
                       lambda self: f", {len(self.messages)} msgs")
    @mailbox.update_on_failure
    async def update_message_list(self):
        """Retrieve the list of all messages and store all the message content in the
        content_hash message database"""
        todo = []
        msgs = []

        async for jmsg in self.graph.get_json_paged(
                "v1.0",
                f"/me/mailFolders/{self.mailbox_id}/messages",
                params=
            {
                "$select":
                "internetMessageId,isRead,Flag,receivedDateTime,singleValueExtendedProperties",
                "$expand":
                "SingleValueExtendedProperties($filter=(id eq 'Integer 0xe17') or"
                " (id eq 'Integer 0x1080'))",
            }):
            msg = messages.Message(mailbox=self,
                                   storage_id=jmsg["id"],
                                   email_id=jmsg["internetMessageId"])
            msg.received_time = datetime.datetime.strptime(
                jmsg["receivedDateTime"], '%Y-%m-%dT%H:%M:%SZ')
            msg.flags = self._json_to_flags(jmsg)

            if not self.msgdb.have_content(msg):
                todo.append(
                    asyncio.create_task(self._fetch_message(msg)))

            msgs.append(msg)
        await asyncio_complete(*todo)

        res = {}
        for msg in msgs:
            # Something went wrong?
            if msg.content_hash is not None:
                res[msg.content_hash] = msg
        self.messages = res
        self.need_update = False
        if not self.use_owa_subscribe:
            if self.timer:
                self.timer.cancel()
                self.timer = None
            self.timer = self.loop.call_later(60, self._timer)
        if self.cfg.trace_file is not None:
            pickle.dump(["0365_update_message_list", self.name, self.messages],
                        self.cfg.trace_file)

    async def _monitor_changes(self):
        """Keep a persistent PUT that returns data when there are changes."""
        r = None
        while True:
            if r is None:
                self.need_update = True
                self.changed_event.set()
                r = await self.graph.owa_subscribe(
                    f"https://outlook.office.com/api/beta/me/mailfolders('{self.mailbox_id}')/Messages",
                    "Created,Updated,Deleted")
            try:
                # This should use a single notification channel per graph,
                # however until we can parse the incremental json it can't be
                # done.
                async for data in self.graph.owa_get_notifications(r["Id"]):
                    # hacky hacky
                    if (data ==
                            b'{"@odata.type":"#Microsoft.OutlookServices.KeepAliveNotification","Status":"Ok"}'
                            or data ==
                            b',{"@odata.type":"#Microsoft.OutlookServices.KeepAliveNotification","Status":"Ok"}'
                        ):
                        continue
                    self.need_update = True
                    self.changed_event.set()
            except (asyncio.TimeoutError,
                    aiohttp.client_exceptions.ClientError):
                r = None
                continue

    def _timer(self):
        self.need_update = True
        self.changed_event.set()

    def force_content(self, msgs):
        raise RuntimeError("Cannot move messages into the Cloud")

    def _update_msg_flags(self, cmsg: messages.Message,
                          old_cmsg_flags: int, lmsg: messages.Message):
        lflags = lmsg.flags & (messages.Message.ALL_FLAGS
                               ^ messages.Message.FLAG_DELETED)
        if lflags == old_cmsg_flags or lflags == cmsg.flags:
            return None

        cloud_flags = cmsg.flags ^ old_cmsg_flags
        flag_mask = messages.Message.ALL_FLAGS ^ cloud_flags
        nflags = (lflags & flag_mask) | (cmsg.flags & cloud_flags)
        modified_flags = nflags ^ cmsg.flags

        # FIXME: https://docs.microsoft.com/en-us/graph/best-practices-concept#getting-minimal-responses
        # FIXME: Does the ID change?
        patch: Dict[str, Any] = {}
        if modified_flags & messages.Message.FLAG_READ:
            patch["isRead"] = bool(nflags & messages.Message.FLAG_READ)
        if modified_flags & messages.Message.FLAG_FLAGGED:
            patch["flag"] = {
                "flagStatus":
                "flagged" if nflags
                & messages.Message.FLAG_FLAGGED else "notFlagged"
            }
        if modified_flags & messages.Message.FLAG_REPLIED:
            # This can only be described as an undocumented disaster.
            # Different clients set different things. The Icon shows up in
            # OWS and the Mobile app. The MessageStatus shows up in
            # IMAP. IMAP sets the MessageStatus but otherwise does not
            # interact with the other two. We can't seem to set
            # MessageStatus over REST because it needs RopSetMessageStatus.
            if nflags & messages.Message.FLAG_REPLIED:
                now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                patch["singleValueExtendedProperties"] = [
                    # PidTagLastVerbExecuted
                    {
                        "id": "Integer 0x1081",
                        "value": "103"
                    },
                    # PidTagLastVerbExecutionTime
                    {
                        "id": "SystemTime 0x1082",
                        "value": now
                    },
                    # PidTagIconIndex
                    {
                        "id": "Integer 0x1080",
                        "value": "261"
                    },
                ]
            else:
                # Rarely does anything undo a replied flag, but it is
                # useful for testing.
                patch["singleValueExtendedProperties"] = [
                    {
                        "id":
                        "Integer 0x1080",  # PidTagIconIndex
                        "value":
                        "256" if nflags
                        & messages.Message.FLAG_READ else "-1"
                    },
                ]
        if not patch:
            return None
        cmsg.flags = nflags
        return self.graph.patch_json(
            "v1.0",
            f"/me/mailFolders/{self.mailbox}/messages/{cmsg.storage_id}",
            body=patch)

    @util.log_progress(lambda self: f"Uploading local changes for {self.name}",
                       lambda self: f", {self.last_merge_len} changes ")
    @mailbox.update_on_failure
    async def merge_content(self, msgs: messages.CHMsgMappingDict_Type):
        # There is a batching API for this kind of stuff as well:
        # https://docs.microsoft.com/en-us/graph/json-batching
        self.last_merge_len = 0
        todo_flags = []
        todo_del = []
        if self.cfg.trace_file is not None:
            pickle.dump(["merge_content", self.name, self.messages, msgs],
                        self.cfg.trace_file)
        for ch, mpair in msgs.items():
            # lmsg is the message in the local mailbox
            # cmsg is the current cloud message in this class
            # old_cmsg is the original cloud message from the last sync
            lmsg, old_cmsg = mpair
            cmsg = self.messages.get(ch)
            assert old_cmsg is not None

            # Update flags
            if cmsg is not None and old_cmsg is not None and lmsg is not None:
                patch = self._update_msg_flags(cmsg, old_cmsg.flags, lmsg)
                if patch:
                    todo_flags.append(patch)

            # Debugging that the message really is to be deleted
            if cmsg is not None and lmsg is None:
                assert os.stat(os.path.join(self.msgdb.hashes_dir,
                                            ch)).st_nlink == 1

            if cmsg is not None and (lmsg is None or lmsg.flags
                                     & messages.Message.FLAG_DELETED):
                # Delete cloud message
                todo_del.append(
                    self.graph.post_json(
                        "v1.0",
                        f"/me/mailFolders/{self.mailbox}/messages/{cmsg.storage_id}/move",
                        body={
                            "destinationId":
                            "deleteditems"
                            if self.delete_action == "delete" else "archive"
                        }))
                del self.messages[ch]

        await asyncio_complete(*todo_flags)
        # Delete must be temporally after move as move will change the mailbox
        # id.
        await asyncio_complete(*todo_del)
        self.last_merge_len = len(todo_flags) + len(todo_del)
