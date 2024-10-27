# SPDX-License-Identifier: GPL-2.0+
import asyncio
import datetime
import functools
import json
import logging
import os
import pickle
import secrets
import time
from json import dumps as jdumps
from typing import Any, Dict, List, Optional, Union

import aiohttp
import oauthlib

from . import config, mailbox, messages, oauth, util
from .util import asyncio_complete

MAX_CONCURRENT_OPERATIONS = 5
# Graph is completely crazy, it can only accept 20 requests in a batch,
# and more than some concurrent modify requests seems to hit 429 retry.
# So run modifies 3 at a time sequentially. Bleck.
MAX_BATCH_SIZE = 3

def _retry_protect(func):
    # Graph can return various error codes, see:
    # https://docs.microsoft.com/en-us/graph/errors
    @functools.wraps(func)
    async def async_wrapper(self, *args, **kwargs):
        while True:
            while ("Authorization" not in self.headers
                   or "Authorization" not in self.owa_headers):
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
                if e.code == 429: # Too Many Requests
                    delay = int(e.headers.get("Retry-After", 10))
                    self.cfg.logger.error(
                        f"Graph returns {e} Too Many Requests, {e.headers.get('Rate-Limit-Reason')}, delaying {delay}"
                    )
                    await asyncio.sleep(delay)
                    continue
                if (e.code == 503 or  # Service Unavilable
                        e.code == 509 or  # Bandwidth Limit Exceeded
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
                    aiohttp.client_exceptions.ClientError) as e:
                self.cfg.logger.debug(f"Got non-HTTP Error in {func} {e!r}")
                await asyncio.sleep(10)
                continue

    return async_wrapper


class GraphAPI(oauth.Account):
    """An OAUTH2 authenticated session to the Microsoft Graph API"""
    graph_token: Optional[Dict[str,str]] = None
    owa_token: Optional[Dict[str,str]] = None
    authenticator = None

    def __init__(self, cfg: config.Config, user: str, tenant: str, client_id: str):
        super().__init__(cfg, user)
        self.domain_id = f"o365-{user}-{tenant}"
        self.tenant = tenant
        self.client_id = client_id

        if self.user is not None:
            self.name = f"{self.user}//{tenant}"
        else:
            self.name = f"//{tenant}"

        # Use the new format much more immutable ids, this will work better
        # with our caching scheme. See
        # https://docs.microsoft.com/en-us/graph/outlook-immutable-id
        self.headers= {"Prefer": 'IdType="ImmutableId"'}
        self.owa_headers: Dict[str, str] = {}

    async def go(self):
        auth = self.cfg.msgdb.get_authenticator(self.domain_id)
        if isinstance(auth, dict):
            self.owa_token = auth
            # the msal version used a string here

        connector = aiohttp.connector.TCPConnector(
            limit=MAX_CONCURRENT_OPERATIONS,
            limit_per_host=MAX_CONCURRENT_OPERATIONS)
        self.session = aiohttp.ClientSession(connector=connector,
                                             raise_for_status=False)

        self.graph_scopes = []
        self.owa_scopes = []
        if "_CMS_" in self.protocols:
            self.graph_scopes.extend([
                "https://graph.microsoft.com/User.Read",
                "https://graph.microsoft.com/Mail.ReadWrite"
            ])
            self.owa_scopes.append("https://outlook.office.com/mail.read")
        if "SMTP" in self.protocols:
            self.owa_scopes.append("https://outlook.office.com/SMTP.Send")
        if "IMAP" in self.protocols:
            self.owa_scopes.append(
                "https://outlook.office.com/IMAP.AccessAsUser.All")
        if "TODO" in self.protocols:
            self.graph_scopes.append(
                "https://graph.microsoft.com/Tasks.ReadWrite")
        if self.graph_scopes:
            self.graph_scopes.append("offline_access")
        else:
            if not self.owa_scopes:
                self.owa_scopes.append("openid")
            self.owa_scopes.append("offline_access")

        self.redirect_url = self.cfg.web_app.url + "oauth2/msal"
        self.oauth = oauth.OAuth2Session(
            client_id=self.client_id,
            client=oauth.NativePublicApplicationClient(self.client_id),
            redirect_uri=self.redirect_url,
            token=self.graph_token,
            strict_scopes=False)

        await self._do_authenticate()

    def _set_token(self, graph_token, owa_token):
        # Only store the refresh token, access tokens are more dangerous to
        # keep as they are valid across a password change for their lifetime
        self.cfg.msgdb.set_authenticator(
            self.domain_id,
            {"refresh_token": owa_token["refresh_token"]})
        if graph_token:
            self.headers["Authorization"] = graph_token[
                "token_type"] + " " + graph_token["access_token"]
        self.owa_headers["Authorization"] = owa_token[
            "token_type"] + " " + owa_token["access_token"]
        self.graph_token = graph_token
        self.owa_token = owa_token
        return True

    async def _refresh_authenticate(self):
        if self.owa_token is None:
            return False

        try:
            tasks = []
            if self.graph_scopes:
                tasks.append(
                    self.oauth.refresh_token(
                        self.session,
                        f'https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token',
                        client_id=self.client_id,
                        scopes=self.graph_scopes,
                        refresh_token=self.owa_token["refresh_token"]))
            else:
                async def RetNone():
                    return None
                tasks.append(RetNone())

            tasks.append(
                self.oauth.refresh_token(
                    self.session,
                    f'https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token',
                    client_id=self.client_id,
                    scopes=self.owa_scopes,
                    refresh_token=self.owa_token["refresh_token"]))
            graph_token, owa_token = await asyncio_complete(*tasks)
        except (oauthlib.oauth2.OAuth2Error, Warning) :
            self.cfg.logger.exception(
                f"OAUTH initial exchange failed for {self.domain_id}, sleeping for retry"
            )
            self.graph_token = None
            self.owa_token = None
            await asyncio.sleep(1)
            return False
        return self._set_token(graph_token, owa_token)

    @util.log_progress(lambda self: f"Azure AD Authentication for {self.name}")
    async def _do_authenticate(self):
        while not await self._refresh_authenticate():
            self.graph_token = None
            self.owa_token = None

            state = hex(id(self)) + secrets.token_urlsafe(8)
            url = self.oauth.authorization_url(
                f'https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/authorize',
                state=state,
                scopes=self.graph_scopes + self.owa_scopes,
                login_hint=self.user)

            q = await self.cfg.web_app.auth_redir(url, state,
                                                  self.redirect_url)

            try:
                owa_token = await self.oauth.fetch_token(
                    self.session,
                    f'https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token',
                    include_client_id=True,
                    scopes=self.owa_scopes,
                    code=q["code"])

                graph_token = None
                if self.graph_scopes:
                    graph_token = await self.oauth.refresh_token(
                        self.session,
                        f'https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token',
                        client_id=self.client_id,
                        scopes=self.graph_scopes,
                        refresh_token=owa_token["refresh_token"])
            except (oauthlib.oauth2.OAuth2Error, Warning):
                self.cfg.logger.exception(
                    f"OAUTH initial exchange failed for {self.domain_id}, sleeping for retry"
                )
                await asyncio.sleep(1)
                continue

            if self._set_token(graph_token, owa_token):
                return

    async def authenticate(self):
        """Obtain OAUTH bearer tokens for MS services. For users this has to be done
        interactively via the browser. A cache is used for tokens that have
        not expired and they can be refreshed non-interactively into active
        tokens within some limited time period."""
        # Ensure we only ever have one authentication open at once. Other
        # threads will all block here on the single authenticator.
        if "Authorization" in self.headers:
            del self.headers["Authorization"]
        if "Authorization" in self.owa_headers:
            del self.owa_headers["Authorization"]
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
                    if data[-1:] == b'\r':
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

    def batch_post_json(self, batch, ver, path, body):
        """Like post_json but appends the action to a batch. Note the ver of
        all actions in the batch must be the same"""
        assert(ver == "v1.0")
        requests = batch["requests"]
        req = {
            "id": f"{len(requests)}",
            "method": "POST",
            "url": path,
            "body": body,
            "headers": {
                "Content-Type": "application/json"
            },
        }
        requests.append(req)

    @_retry_protect
    async def patch_json(self, ver, path, body, params=None):
        """Return the JSON dictionary from the PATCH operation"""
        async with self.session.patch(
                f"https://graph.microsoft.com/{ver}{path}",
                headers=self.headers,
                json=body,
                params=params) as op:
            return await self._check_json(op)

    def batch_patch_json(self, batch, ver, path, body):
        """Like patch_json but appends the action to a batch. Note the ver of
        all actions in the batch must be the same"""
        assert(ver == "v1.0")
        requests = batch["requests"]
        req = {
            "id": f"{len(requests)}",
            "method": "PATCH",
            "url": path,
            "body": body,
            "headers": {
                "Content-Type": "application/json"
            },
        }
        requests.append(req)

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

    @_retry_protect
    async def __get_json_paged_next(self, uri):
        async with self.session.get(uri, headers=self.headers) as op:
            return await self._check_json(op)

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
            resp = await self.__get_json_paged_next(uri)

    async def _execute_batch(self, batch):
        resp = await self.post_json("v1.0", "/$batch", batch)
        to_retry = set()
        for rep in resp["responses"]:
            status = int(rep["status"])
            if status < 200 or status >= 300 or "error" in rep["body"]:
                to_retry.add(rep["id"])
                self.cfg.logger.debug(f"Batched request failed, retrying: {rep}")
        if not to_retry:
            return

        # Otherwise issue the request natively and let the normal
        # mechanisms sort it out.
        for req in batch["requests"]:
            if req["id"] not in to_retry:
                continue
            to_retry.remove(req["id"])

            if req["method"] == "POST":
                await self.post_json("v1.0", req["url"], req["body"])
            elif req["method"] == "PATCH":
                await self.patch_json("v1.0", req["url"], req["body"])
            else:
                raise ValueError(f"Incorrect batch {req}")
        assert not to_retry

    async def execute_batch(self, batch):
        """Execute a batch sequence created by batch_* functions"""
        # See https://docs.microsoft.com/en-us/graph/json-batching
        all_requests = batch["requests"]
        while all_requests:
            await self._execute_batch({"requests": all_requests[:MAX_BATCH_SIZE]})
            del all_requests[:MAX_BATCH_SIZE]

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

    async def get_xoauth2_bytes(self, proto: str) -> Optional[bytes]:
        """Return the xoauth2 byte string for the given protocol to login to
        this account."""
        while (self.owa_token is None
               or self.owa_token["expires_at"] <= time.time() + 10):
            await self.authenticate()

        if proto == "SMTP" or proto == "IMAP":
            res = 'user=%s\1auth=%s %s\1\1' % (self.user,
                                               self.owa_token["token_type"],
                                               self.owa_token["access_token"])
            return res.encode()
        if proto == "TODO":
            res = 'user=%s\1auth=%s %s\1\1' % (self.user,
                                               self.graph_token["token_type"],
                                               self.graph_token["access_token"])
            return res.encode()
        return None


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
        graph.protocols.add("_CMS_")
        self.max_fetches = asyncio.Semaphore(10)

    def __repr__(self):
        return f"<O365Mailbox at {id(self):x} for {self.graph.domain_id} {self.mailbox}>"

    async def get_mbox(self,
                       path: List[str],
                       parentid: str = None) -> mailbox.Mailbox:
        child_folders = "" if not parentid else f"/{parentid}/childFolders"
        mbox = await self.graph.get_json(
            "v1.0",
            f"/me/mailFolders" + child_folders,
            params={"$filter": f"displayName eq '{path[0]}'"})
        if len(path) == 1:
            return mbox
        return await self.get_mbox(path[1:], mbox['value'][0]["id"])

    async def setup_mbox(self):
        """Setup access to the authenticated API domain for this endpoint"""
        cfg = self.cfg
        self.loop = cfg.loop
        self.name = f"{self.graph.name}:{self.mailbox}"
        json = await self.get_mbox(self.mailbox.split("/"))
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
        async with self.max_fetches:
            with util.log_progress_ctx(
                    logging.DEBUG, f"Downloading {msg.email_id}",
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
                "$top": 500,
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
                assert msg.content_hash in self.msgdb.file_hashes
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

    def _update_msg_flags(self, batch, cmsg: messages.Message,
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
        self.graph.batch_patch_json(
            batch,
            "v1.0",
            f"/me/mailFolders/{self.mailbox_id}/messages/{cmsg.storage_id}",
            body=patch)

    @util.log_progress(lambda self: f"Uploading local changes for {self.name}",
                       lambda self: f", {self.last_merge_len} changes ")
    @mailbox.update_on_failure
    async def merge_content(self, msgs: messages.CHMsgMappingDict_Type):
        # Note that the mutation operations return a full copy of the message,
        # which is wasteful and we don't need. Couldn't find a way to prevent
        # that.
        self.last_merge_len = 0
        todo_flags = {"requests": []}
        todo_del = {"requests": []}
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
                self._update_msg_flags(todo_flags, cmsg, old_cmsg.flags, lmsg)

            if cmsg is not None and (lmsg is None or lmsg.flags
                                     & messages.Message.FLAG_DELETED):
                # Delete cloud message
                self.graph.batch_post_json(
                    todo_del,
                    "v1.0",
                    f"/me/mailFolders/{self.mailbox_id}/messages/{cmsg.storage_id}/move",
                    body={
                        "destinationId":
                        "deleteditems"
                        if self.delete_action == "delete" else "archive"
                    })
                del self.messages[ch]

        ops = len(todo_flags["requests"]) + len(todo_del["requests"])
        await asyncio_complete(self.graph.execute_batch(todo_flags))
        # Delete must be temporally after move as move will change the mailbox
        # id. FIXME: We could do this with batch ordering
        await asyncio_complete(self.graph.execute_batch(todo_del))
        self.last_merge_len = ops
