import asyncio
import hashlib
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from playwright.async_api import Browser, BrowserContext, CDPSession, Page, Playwright, async_playwright

from app.config import settings
from app.models import AccessProfile, Secret, SessionArtifact, WebConnectionProfile
from app.vault import get_vault_backend_for_secret

from .base import ProviderContext
from .events import add_event
from .web_security import NavigationGuard, UnsafeNavigation


@dataclass
class WebRuntime:
    context: BrowserContext
    page: Page
    cdp: CDPSession
    guard: NavigationGuard
    profile_dir: Path
    artifact_dir: Path
    frames: asyncio.Queue[dict[str, Any]] = field(default_factory=lambda: asyncio.Queue(maxsize=2))


class WebAccessProvider:
    def __init__(self):
        self.playwright: Playwright | None = None
        self.browser: Browser | None = None
        self.runtimes: dict[int, WebRuntime] = {}
        self.semaphore = asyncio.Semaphore(settings.pam_browser_concurrency)
        self._lock = asyncio.Lock()

    def _profile(self, context: ProviderContext) -> WebConnectionProfile:
        profile = context.db.query(WebConnectionProfile).filter_by(connection_profile_id=context.connection_profile.id).first()
        if not profile: raise ValueError("Web connection profile is missing")
        return profile

    async def _browser(self) -> Browser:
        async with self._lock:
            if not self.browser or not self.browser.is_connected():
                self.playwright = await async_playwright().start()
                self.browser = await self.playwright.chromium.launch(headless=settings.pam_browser_headless, args=["--no-sandbox", "--disable-dev-shm-usage"])
        return self.browser

    def _secret(self, context: ProviderContext, secret_id: int | None) -> str | None:
        if not secret_id: return None
        secret = context.db.get(Secret, secret_id)
        if not secret: raise ValueError("Configured authentication secret does not exist")
        return get_vault_backend_for_secret(context.db, secret).get_secret_value(secret.id, {
            "resource_id": context.resource.id, "grant_id": context.grant.id if context.grant else None,
            "session_id": context.session.id if context.session else None, "access_context": "web_browser_worker",
        })

    async def validate_configuration(self, context: ProviderContext) -> None:
        profile = self._profile(context)
        if profile.authentication_mode not in {"none", "basic_auth", "form", "http_header", "cookie", "manual"}:
            raise ValueError("Unsupported web authentication mode")
        if profile.authentication_mode == "form" and not all((profile.username_selector, profile.password_selector, profile.submit_selector)):
            raise ValueError("Form authentication selectors are required")
        guard = NavigationGuard((context.resource.allowed_domains or "").split(","), context.resource.allow_private_network,(profile.blocked_domains or "").split(","))
        await guard.validate(profile.initial_url)

    async def _new_runtime(self, context: ProviderContext) -> WebRuntime:
        profile = self._profile(context)
        if not context.session:
            raise ValueError("Session context is required")
        session = context.session
        await self.validate_configuration(context)
        await self.semaphore.acquire()
        root = Path(settings.pam_browser_profile_dir); root.mkdir(parents=True, exist_ok=True)
        artifacts = Path(settings.pam_artifact_dir) / str(session.id); artifacts.mkdir(parents=True, exist_ok=True)
        profile_dir = Path(tempfile.mkdtemp(prefix=f"pam-{session.id}-", dir=root))
        browser = await self._browser()
        options: dict[str, Any] = {
            "viewport": {"width": settings.pam_web_viewport_width, "height": settings.pam_web_viewport_height},
            "accept_downloads": True, "record_video_dir": str(artifacts),
            "record_video_size": {"width": settings.pam_web_viewport_width, "height": settings.pam_web_viewport_height},
        }
        username = self._secret(context, profile.username_secret_id)
        password = self._secret(context, profile.password_secret_id)
        initial=urlsplit(profile.initial_url); initial_origin=f"{initial.scheme}://{initial.netloc}"
        if profile.authentication_mode == "basic_auth": options["http_credentials"] = {"username": username or "", "password": password or "", "origin": initial_origin}
        browser_context = await browser.new_context(**options)
        await browser_context.tracing.start(screenshots=True, snapshots=True, sources=False)
        guard = NavigationGuard((context.resource.allowed_domains or "").split(","), context.resource.allow_private_network,(profile.blocked_domains or "").split(","))
        runtime = WebRuntime(browser_context, await browser_context.new_page(), None, guard, profile_dir, artifacts)  # type: ignore[arg-type]

        header_value=self._secret(context,profile.auth_secret_id) if profile.authentication_mode=="http_header" else None
        async def route_request(route):
            try: await guard.validate(route.request.url)
            except (UnsafeNavigation, OSError):
                add_event(context.db, session, "policy_blocked", "web", {"url": route.request.url, "reason": "unsafe_navigation"})
                context.db.commit()
                await route.abort("blockedbyclient"); return
            request_origin=f"{urlsplit(route.request.url).scheme}://{urlsplit(route.request.url).netloc}"
            if header_value is not None and request_origin==initial_origin:
                await route.continue_(headers={**route.request.headers,profile.header_name or "X-PAM-Authorization":header_value})
            else: await route.continue_()
        await browser_context.route("**/*", route_request)

        if profile.authentication_mode == "cookie":
            await browser_context.add_cookies([{"name": profile.cookie_name or "pam", "value": self._secret(context, profile.auth_secret_id) or "", "url": initial_origin}])

        page = runtime.page
        page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))
        def console_event(msg) -> None:
            if msg.type == "error":
                add_event(context.db, session, "browser_error", "web", {"type": msg.type, "text": msg.text[:500]}); context.db.commit()
        def popup_event(popup) -> None:
            add_event(context.db, session, "tab_opened", "web", {"url": popup.url}); context.db.commit()
        def navigation_event(frame) -> None:
            if frame == page.main_frame:
                add_event(context.db, session, "navigation", "web", {"url": frame.url}); context.db.commit()
        page.on("console", console_event)
        page.on("download", lambda download: asyncio.create_task(self._handle_download(context, download)))
        page.on("filechooser", lambda chooser: asyncio.create_task(chooser.set_files([])))
        page.on("popup", popup_event)
        page.on("framenavigated", navigation_event)
        await page.goto(profile.initial_url, wait_until="domcontentloaded")
        if profile.authentication_mode == "form":
            await page.locator(profile.username_selector or "").fill(username or "")
            await page.locator(profile.password_selector or "").fill(password or "")
            await page.locator(profile.submit_selector or "").click()
            add_event(context.db, session, "form_submit", "web", {"selector": profile.submit_selector, "credentials": "[REDACTED]"}, sensitive=True)
            if profile.success_url_pattern:
                await page.wait_for_url(profile.success_url_pattern)
            if profile.success_dom_selector:
                await page.locator(profile.success_dom_selector).wait_for()

        runtime.cdp = await browser_context.new_cdp_session(page)
        def frame_received(payload: dict[str, Any]) -> None:
            if runtime.frames.full():
                try: runtime.frames.get_nowait()
                except asyncio.QueueEmpty: pass
            runtime.frames.put_nowait({"data": payload["data"], "metadata": payload.get("metadata", {})})
            asyncio.create_task(runtime.cdp.send("Page.screencastFrameAck", {"sessionId": payload["sessionId"]}))
        runtime.cdp.on("Page.screencastFrame", frame_received)
        await runtime.cdp.send("Page.startScreencast", {"format": "jpeg", "quality": 75, "maxWidth": settings.pam_web_viewport_width, "maxHeight": settings.pam_web_viewport_height, "everyNthFrame": 1})
        return runtime

    async def _handle_download(self, context: ProviderContext, download) -> None:
        if not context.grant or not context.session:
            await download.cancel(); return
        policy = context.db.get(AccessProfile, context.grant.access_profile_id)
        add_event(context.db, context.session, "download_started", "web", {"filename": download.suggested_filename})
        if not policy or policy.download_policy == "deny":
            await download.cancel(); context.db.commit(); return
        path = await download.path()
        if not path: return
        source=Path(path)
        if source.stat().st_size>policy.max_download_bytes:
            source.unlink(missing_ok=True)
            add_event(context.db,context.session,"policy_blocked","web",{"reason":"download_size_limit","filename":download.suggested_filename})
        else:
            runtime=self.runtimes.get(context.session.id)
            if runtime:
                target=runtime.artifact_dir/("download-"+Path(download.suggested_filename).name)
                shutil.copy2(source,target); self._record_artifact(context,target,"download","application/octet-stream")
        context.db.commit()

    async def test_connection(self, context: ProviderContext) -> dict[str, Any]:
        await self.validate_configuration(context)
        profile=self._profile(context); guard=NavigationGuard((context.resource.allowed_domains or "").split(","),context.resource.allow_private_network,(profile.blocked_domains or "").split(","))
        await self.semaphore.acquire(); browser_context=None
        try:
            browser_context=await (await self._browser()).new_context()
            async def guarded(route):
                try: await guard.validate(route.request.url); await route.continue_()
                except (UnsafeNavigation,OSError): await route.abort("blockedbyclient")
            await browser_context.route("**/*",guarded); page=await browser_context.new_page()
            response=await page.goto(profile.initial_url,wait_until="domcontentloaded",timeout=15_000)
            if not response: raise ValueError("Web target did not return a response")
            return {"ok":True,"protocol":"web","status_code":response.status,"final_url":page.url}
        finally:
            if browser_context: await browser_context.close()
            self.semaphore.release()

    async def launch_session(self, context: ProviderContext) -> dict[str, Any]:
        if not context.session: raise ValueError("Session context is required")
        runtime = await self._new_runtime(context)
        self.runtimes[context.session.id] = runtime
        add_event(context.db, context.session, "session_started", "web", {"url": self._profile(context).initial_url})
        return {"protocol": "web", "stream_url": f"/api/web-sessions/{context.session.id}/stream"}

    async def handle_input(self, context: ProviderContext, event: dict[str, Any]) -> dict[str, Any]:
        if not context.session: raise ValueError("Session context is required")
        runtime = self.runtimes.get(context.session.id)
        if not runtime: raise ValueError("Browser runtime is unavailable")
        kind = event.get("type")
        if kind == "mouse":
            action = event.get("action", "move"); x, y = float(event.get("x", 0)), float(event.get("y", 0))
            if action == "click": await runtime.page.mouse.click(x, y); add_event(context.db, context.session, "click", "web", {"x": x, "y": y})
            elif action == "down": await runtime.page.mouse.down(button=event.get("button", "left"))
            elif action == "up": await runtime.page.mouse.up(button=event.get("button", "left"))
            else: await runtime.page.mouse.move(x, y)
        elif kind == "key":
            key = str(event.get("key", ""))[:64]
            if event.get("action") == "up": await runtime.page.keyboard.up(key)
            else: await runtime.page.keyboard.down(key)
        elif kind == "text":
            await runtime.page.keyboard.insert_text(str(event.get("text", ""))[:4096])
            add_event(context.db, context.session, "input_changed", "web", {"field_type": "text", "value_changed": True}, sensitive=True)
        elif kind == "wheel": await runtime.page.mouse.wheel(float(event.get("delta_x", 0)), float(event.get("delta_y", 0)))
        elif kind == "clipboard":
            if not context.grant: raise ValueError("Grant context is required")
            policy=context.db.get(AccessProfile,context.grant.access_profile_id); action=event.get("action")
            if not policy or action not in {"read","write"}: raise ValueError("Invalid clipboard request")
            if action=="write" and policy.clipboard_policy not in {"write","read_write"}: raise ValueError("Clipboard write is denied")
            if action=="read" and policy.clipboard_policy not in {"read","read_write"}: raise ValueError("Clipboard read is denied")
            await runtime.context.grant_permissions(["clipboard-read","clipboard-write"],origin=urlsplit(runtime.page.url).scheme+"://"+urlsplit(runtime.page.url).netloc)
            if action=="write": await runtime.page.evaluate("text => navigator.clipboard.writeText(text)",str(event.get("text",""))[:65536]); return {}
            return {"clipboard_text":await runtime.page.evaluate("navigator.clipboard.readText()")}
        elif kind == "upload": raise ValueError("Use the authenticated upload endpoint")
        else: raise ValueError("Unsupported input event")
        return {}

    async def handle_upload(self, context:ProviderContext,selector:str,filename:str,data:bytes)->None:
        if not context.session or not context.grant: raise ValueError("Session and grant context are required")
        runtime=self.runtimes.get(context.session.id); policy=context.db.get(AccessProfile,context.grant.access_profile_id)
        if not runtime or not policy: raise ValueError("Browser runtime is unavailable")
        if policy.upload_policy!="allow": raise ValueError("Uploads are denied by policy")
        if len(data)>policy.max_upload_bytes: raise ValueError("Upload exceeds the policy size limit")
        target=runtime.profile_dir/("upload-"+Path(filename).name)
        try:
            target.write_bytes(data); await runtime.page.locator(selector).set_input_files(str(target))
            add_event(context.db,context.session,"upload_started","web",{"selector":selector,"filename":Path(filename).name,"size_bytes":len(data)})
        finally: target.unlink(missing_ok=True)

    def _record_artifact(self, context: ProviderContext, path: Path, kind: str, mime: str) -> None:
        if not context.session: return
        if not path.exists(): return
        checksum=hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda:stream.read(1024*1024),b""): checksum.update(chunk)
        digest=checksum.hexdigest()
        context.db.add(SessionArtifact(session_id=context.session.id, artifact_type=kind, storage_path=str(path.resolve()), sha256=digest, size_bytes=path.stat().st_size, mime_type=mime))

    async def terminate_session(self, context: ProviderContext, reason: str) -> None:
        if not context.session: return
        runtime = self.runtimes.pop(context.session.id, None)
        if not runtime: return
        try:
            await runtime.cdp.send("Page.stopScreencast")
            trace_path = runtime.artifact_dir / "trace.zip"
            await runtime.context.tracing.stop(path=str(trace_path))
            video = runtime.page.video
            screenshot_path = runtime.artifact_dir / "final.png"
            if settings.pam_web_record_screenshots:
                await runtime.page.screenshot(path=str(screenshot_path))
            await runtime.context.close()
            self._record_artifact(context, trace_path, "trace", "application/zip")
            if settings.pam_web_record_screenshots:
                self._record_artifact(context, screenshot_path, "screenshot", "image/png")
            if video:
                try: self._record_artifact(context, Path(await video.path()), "video", "video/webm")
                except Exception: pass
            add_event(context.db, context.session, "session_finished", "web", {"reason": reason})
        finally:
            shutil.rmtree(runtime.profile_dir, ignore_errors=True)
            self.semaphore.release()

    async def collect_events(self, context: ProviderContext) -> list[dict[str, Any]]: return []
    async def cleanup_session(self, context: ProviderContext) -> None: await self.terminate_session(context, "cleanup")

    async def shutdown(self) -> None:
        for session_id in list(self.runtimes):
            runtime = self.runtimes.pop(session_id)
            await runtime.context.close(); shutil.rmtree(runtime.profile_dir, ignore_errors=True); self.semaphore.release()
        if self.browser: await self.browser.close()
        if self.playwright: await self.playwright.stop()
        self.browser = None; self.playwright = None

    def healthy(self) -> bool:
        return self.browser is None or self.browser.is_connected()


web_provider = WebAccessProvider()
