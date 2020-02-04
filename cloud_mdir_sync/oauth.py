# SPDX-License-Identifier: GPL-2.0+
import asyncio
import os

import aiohttp
import aiohttp.web


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
        site = aiohttp.web.TCPSite(self.runner, '127.0.0.1', 8080)
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
