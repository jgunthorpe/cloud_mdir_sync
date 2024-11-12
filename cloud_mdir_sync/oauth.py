# SPDX-License-Identifier: GPL-2.0+
import asyncio
import base64
import hashlib
import os
import secrets
import webbrowser
from abc import abstractmethod
from typing import TYPE_CHECKING, Dict, List, Optional

import aiohttp
import aiohttp.web
import oauthlib
import oauthlib.oauth2

import urllib.parse

if TYPE_CHECKING:
    from . import config


class Account(object):
    """An OAUTH2 account"""

    def __init__(self, cfg: "config.Config", user: str):
        self.cfg = cfg
        self.user = user
        self.protocols = set()

    @abstractmethod
    async def get_xoauth2_bytes(self, proto: str) -> Optional[bytes]:
        return None

class WebServer(object):
    """A small web server is used to manage oauth requests. The user should point a browser
    window at localhost. The program will generate redirects for the browser to point at
    OAUTH servers when interactive authentication is required."""
    url = "http://127.0.0.1:8080/"
    runner = None

    def __init__(self):
        self.auth_redirs = {}
        self.web_app = aiohttp.web.Application()
        self.web_app.router.add_get("/", self._start)
        self.web_app.router.add_get("/oauth2/msal", self._oauth2_redirect)
        self.web_app.router.add_get("/oauth2/gmail", self._oauth2_redirect)

    async def go(self):
        self.runner = aiohttp.web.AppRunner(self.web_app)
        await self.runner.setup()
        url = urllib.parse.urlparse(self.url)
        site = aiohttp.web.TCPSite(self.runner, url.hostname, url.port)
        await site.start()

    async def close(self):
        if self.runner:
            await self.runner.cleanup()

    async def auth_redir(self, url: str, state: str, redir_url: str):
        """Call as part of an OAUTH flow to hand the URL off to interactive browser
        based authentication.  The flow will resume when the OAUTH server
        redirects back to the localhost server.  The final query paremeters
        will be returned by this function"""
        queue = asyncio.Queue()

        # If this is the first auth to start then automatically launch a
        # browser, otherwise assume the already running browser will take care
        # of things
        if not self.auth_redirs:
            print(
                f"Goto {self.url} in a web browser to authenticate (opening browser)"
            )
            webbrowser.open(url)
        else:
            print(
                f"Goto {self.url} in a web browser to authenticate (reusing browser)"
            )
        self.auth_redirs[state] = (url, queue, redir_url)
        return await queue.get()

    def _start(self, request: aiohttp.web.Request):
        """Feed redirects to the web browser until all authing is done.  FIXME: Some
        fancy java script should be used to fetch new interactive auth
        requests"""
        for I in self.auth_redirs.values():
            raise aiohttp.web.HTTPFound(I[0])
        return aiohttp.web.Response(text="Authentication done")

    def _oauth2_redirect(self, request: aiohttp.web.Request):
        """Use for the Azure AD authentication response redirection"""
        state = request.query.get("state", None)
        if state is None:
            raise aiohttp.web.HTTPBadRequest(text="No state parameter")
        try:
            _, queue, redir_url = self.auth_redirs[state]
            # RFC8252 8.10
            if redir_url != self.url[:-1] + request.path:
                raise aiohttp.web.HTTPBadRequest(
                    text="Invalid redirection path")
            del self.auth_redirs[state]
            queue.put_nowait(request.query)
        except KeyError:
            pass

        for I in self.auth_redirs.values():
            raise aiohttp.web.HTTPFound(I[0])
        raise aiohttp.web.HTTPFound(self.url)


class NativePublicApplicationClient(oauthlib.oauth2.WebApplicationClient):
    """Amazingly oauthlib doesn't include client side PCKE support
    Hack it into the WebApplicationClient"""
    def __init__(self, client_id):
        super().__init__(client_id)

    def _code_challenge_method_s256(self, verifier):
        return base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')

    def prepare_request_uri(self,
                            authority_uri,
                            redirect_uri,
                            scope=None,
                            state=None,
                            **kwargs):
        self.verifier = secrets.token_urlsafe(96)
        return super().prepare_request_uri(
            authority_uri,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=self._code_challenge_method_s256(self.verifier),
            code_challenge_method="S256",
            **kwargs)

    def prepare_request_body(self,
                             code=None,
                             redirect_uri=None,
                             body='',
                             include_client_id=True,
                             **kwargs):
        return super().prepare_request_body(
            code=code,
            redirect_uri=redirect_uri,
            body=body,
            include_client_id=include_client_id,
            code_verifier=self.verifier,
            **kwargs)


class OAuth2Session(object):
    """Helper to execute OAUTH JSON queries using asyncio http"""
    def __init__(self,
                 client_id: str,
                 client: oauthlib.oauth2.rfc6749.clients.base.Client,
                 redirect_uri: str,
                 token: Optional[Dict],
                 strict_scopes=True):
        """strict_scopes can be True if the server always returns only the
        scopes that were requested"""
        self._client = client
        self.redirect_uri = redirect_uri
        self.strict_scopes = strict_scopes

        if token is not None:
            self._client.token = token
            self._client.populate_token_attributes(token)

    def authorization_url(self, url: str, state: str, scopes: List[str], **kwargs) -> str:
        return self._client.prepare_request_uri(url,
                                                redirect_uri=self.redirect_uri,
                                                scope=scopes,
                                                state=state,
                                                **kwargs)

    async def fetch_token(self,
                          session: aiohttp.ClientSession,
                          token_url: str,
                          include_client_id: bool,
                          scopes: List[str],
                          code: str,
                          client_secret: Optional[str] = None) -> Dict:
        """Complete the exchange started with authorization_url"""
        body = self._client.prepare_request_body(
            code=code,
            redirect_uri=self.redirect_uri,
            include_client_id=include_client_id,
            scope=scopes,
            client_secret=client_secret)
        async with session.post(
                token_url,
                data=dict(oauthlib.common.urldecode(body)),
                headers={
                    "Accept": "application/json",
                    "Origin": "http://127.0.0.1:8080/",
                    #"Content-Type":
                    #"application/x-www-form-urlencoded;charset=UTF-8",
                }) as op:
            self.token = self._client.parse_request_body_response(
                await op.text(), scope=scopes if self.strict_scopes else None)
        return self.token

    async def refresh_token(self,
                            session: aiohttp.ClientSession,
                            token_url: str,
                            client_id: str,
                            scopes: List[str],
                            refresh_token: str,
                            client_secret: Optional[str] = None) -> Dict:
        body = self._client.prepare_refresh_body(refresh_token=refresh_token,
                                                 scope=scopes,
                                                 client_id=client_id,
                                                 client_secret=client_secret)
        async with session.post(
                token_url,
                data=dict(oauthlib.common.urldecode(body)),
                headers={
                    "Accept": "application/json",
                    "Origin": "http://127.0.0.1:8080/",
                    #"Content-Type":
                    #"application/x-www-form-urlencoded;charset=UTF-8",
                }) as op:
            self.token = self._client.parse_request_body_response(
                await op.text(), scope=scopes if self.strict_scopes else None)
        if not "refresh_token" in self.token:
            self.token["refresh_token"] = refresh_token
        return self.token
