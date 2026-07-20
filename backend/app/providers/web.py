import asyncio
import hashlib
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.config import settings
from app.models import Secret, SessionArtifact, WebConnectionProfile
from app.vault import get_vault_backend_for_secret

from .base import ProviderContext
from .events import add_event
from .web_security import NavigationGuard, UnsafeNavigation


@dataclass
class WebRuntime:
    context: Any
    page: Any
    cdp: Any
    guard: NavigationGuard
    profile_dir: Path
    artifact_dir: Path
    trace_enabled: bool
    frames: asyncio.Queue[dict[str, Any]] = field(default_factory=lambda: asyncio.Queue(maxsize=2))


class WebAccessProvider:
    def __init__(self):
        self.playwright: Any = None
        self.browser: Any = None
        self.runtimes: dict[int, WebRuntime] = {}
        self.semaphore = asyncio.Semaphore(settings.pam_browser_concurrency)
        self._lock = asyncio.Lock()

    def profile(self, context: ProviderContext) -> WebConnectionProfile:
        value = context.db.query(WebConnectionProfile).filter_by(server_id=context.resource.id).first()
        if not value:
            raise ValueError("Web connection profile is missing")
        return value

    def secret(self, context: ProviderContext, secret_id: int | None) -> str | None:
        if not secret_id:
            return None
        secret = context.db.get(Secret, secret_id)
        if not secret:
            raise ValueError("Configured authentication secret does not exist")
        return get_vault_backend_for_secret(context.db, secret).get_secret_value(secret.id, {
            "server_id": context.resource.id,
            "grant_id": context.grant.id if context.grant else None,
            "session_id": context.session.id if context.session else None,
            "access_context": "web_browser_worker",
        })

    async def _browser(self):
        async with self._lock:
            if not self.browser or not self.browser.is_connected():
                try:
                    from playwright.async_api import async_playwright
                except ImportError as exc:
                    raise RuntimeError("Playwright browser worker is not installed") from exc
                self.playwright = await async_playwright().start()
                self.browser = await self.playwright.chromium.launch(headless=settings.pam_browser_headless, args=["--disable-dev-shm-usage"])
        return self.browser

    def guard(self, context: ProviderContext, profile: WebConnectionProfile) -> NavigationGuard:
        return NavigationGuard((context.resource.allowed_domains or "").split(","), context.resource.allow_private_network, (profile.blocked_domains or "").split(","))

    async def validate_configuration(self, context: ProviderContext) -> None:
        profile = self.profile(context)
        if profile.authentication_mode not in {"none", "basic_auth", "form", "http_header", "cookie", "manual"}:
            raise ValueError("Unsupported web authentication mode")
        if profile.authentication_mode == "form" and not all((profile.username_selector, profile.password_selector, profile.submit_selector)):
            raise ValueError("Form authentication selectors are required")
        await self.guard(context, profile).validate(profile.initial_url)

    async def test_connection(self, context: ProviderContext) -> dict[str, Any]:
        await self.validate_configuration(context)
        profile = self.profile(context)
        guard = self.guard(context, profile)
        await self.semaphore.acquire()
        browser_context = None
        try:
            browser_context = await (await self._browser()).new_context()

            async def guarded(route):
                try:
                    await guard.validate(route.request.url)
                    await route.continue_()
                except (UnsafeNavigation, OSError):
                    await route.abort("blockedbyclient")

            await browser_context.route("**/*", guarded)
            page = await browser_context.new_page()
            response = await page.goto(profile.initial_url, wait_until="domcontentloaded", timeout=15_000)
            if not response:
                raise ValueError("Web target did not return a response")
            return {"ok": True, "protocol": "web", "status_code": response.status}
        finally:
            if browser_context:
                await browser_context.close()
            self.semaphore.release()

    async def launch_session(self, context: ProviderContext) -> dict[str, Any]:
        if not context.session:
            raise ValueError("Session context is required")
        await self.validate_configuration(context)
        profile = self.profile(context)
        await self.semaphore.acquire()
        root = Path(settings.pam_browser_profile_dir)
        root.mkdir(parents=True, exist_ok=True)
        artifact_dir = Path(settings.pam_artifact_dir) / str(context.session.id)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        profile_dir = Path(tempfile.mkdtemp(prefix=f"pam-{context.session.id}-", dir=root))
        runtime = None
        try:
            options: dict[str, Any] = {
                "viewport": {"width": settings.pam_web_viewport_width, "height": settings.pam_web_viewport_height},
                "accept_downloads": True,
                "record_video_dir": str(artifact_dir),
                "record_video_size": {"width": settings.pam_web_viewport_width, "height": settings.pam_web_viewport_height},
            }
            username = self.secret(context, profile.username_secret_id)
            password = self.secret(context, profile.password_secret_id)
            origin_parts = urlsplit(profile.initial_url)
            initial_origin = f"{origin_parts.scheme}://{origin_parts.netloc}"
            if profile.authentication_mode == "basic_auth":
                options["http_credentials"] = {"username": username or "", "password": password or "", "origin": initial_origin}
            browser_context = await (await self._browser()).new_context(**options)
            trace_enabled = profile.authentication_mode in {"none", "manual"}
            if trace_enabled:
                await browser_context.tracing.start(screenshots=True, snapshots=True, sources=False)
            page = await browser_context.new_page()
            guard = self.guard(context, profile)
            cdp = await browser_context.new_cdp_session(page)
            runtime = WebRuntime(browser_context, page, cdp, guard, profile_dir, artifact_dir, trace_enabled)

            header_value = self.secret(context, profile.auth_secret_id) if profile.authentication_mode == "http_header" else None

            async def route_request(route):
                try:
                    await guard.validate(route.request.url)
                except (UnsafeNavigation, OSError) as exc:
                    add_event(context.db, context.session, "policy_blocked", "web", {"url": route.request.url, "reason": type(exc).__name__})
                    context.db.commit()
                    await route.abort("blockedbyclient")
                    return
                request_parts = urlsplit(route.request.url)
                request_origin = f"{request_parts.scheme}://{request_parts.netloc}"
                if header_value is not None and request_origin == initial_origin:
                    await route.continue_(headers={**route.request.headers, profile.header_name or "Authorization": header_value})
                else:
                    await route.continue_()

            await browser_context.route("**/*", route_request)
            if profile.authentication_mode == "cookie":
                await browser_context.add_cookies([{"name": profile.cookie_name or "pam", "value": self.secret(context, profile.auth_secret_id) or "", "url": initial_origin, "httpOnly": True, "secure": origin_parts.scheme == "https"}])

            page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))
            page.on("download", lambda download: asyncio.create_task(self._download(context, profile, runtime, download)))
            page.on("filechooser", lambda chooser: asyncio.create_task(chooser.set_files([])))
            page.on("console", lambda message: self._console(context, message))
            page.on("framenavigated", lambda frame: self._navigation(context, page, frame))

            async def popup(popup_page):
                try:
                    await guard.validate(popup_page.url)
                    if profile.popup_policy == "deny" or (profile.popup_policy == "same_origin" and not popup_page.url.startswith(initial_origin)):
                        raise UnsafeNavigation("Popup denied by policy")
                    add_event(context.db, context.session, "tab_opened", "web", {"url": popup_page.url})
                except UnsafeNavigation:
                    await popup_page.close()
                    add_event(context.db, context.session, "policy_blocked", "web", {"reason": "popup_policy"})
                context.db.commit()

            page.on("popup", lambda popup_page: asyncio.create_task(popup(popup_page)))
            await page.goto(profile.initial_url, wait_until="domcontentloaded")
            if profile.authentication_mode == "form":
                await page.locator(profile.username_selector).fill(username or "")
                await page.locator(profile.password_selector).fill(password or "")
                await page.locator(profile.submit_selector).click()
                add_event(context.db, context.session, "form_submit", "web", {"selector": profile.submit_selector, "value_changed": True}, sensitive=True)
                if profile.success_url_pattern:
                    await page.wait_for_url(profile.success_url_pattern)
                if profile.success_dom_selector:
                    await page.locator(profile.success_dom_selector).wait_for()

            def frame_received(payload):
                if runtime.frames.full():
                    try:
                        runtime.frames.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                runtime.frames.put_nowait({"data": payload["data"], "metadata": payload.get("metadata", {})})
                asyncio.create_task(cdp.send("Page.screencastFrameAck", {"sessionId": payload["sessionId"]}))

            cdp.on("Page.screencastFrame", frame_received)
            await cdp.send("Page.startScreencast", {"format": "jpeg", "quality": 75, "maxWidth": settings.pam_web_viewport_width, "maxHeight": settings.pam_web_viewport_height})
            self.runtimes[context.session.id] = runtime
            add_event(context.db, context.session, "session_started", "web", {"url": profile.initial_url})
            return {"protocol": "web", "stream_url": f"/api/web-sessions/{context.session.id}/stream"}
        except Exception:
            if runtime:
                await runtime.context.close()
            shutil.rmtree(profile_dir, ignore_errors=True)
            self.semaphore.release()
            raise

    def _console(self, context: ProviderContext, message) -> None:
        if message.type == "error" and context.session:
            add_event(context.db, context.session, "browser_error", "web", {"type": "console_error"})
            context.db.commit()

    def _navigation(self, context: ProviderContext, page, frame) -> None:
        if context.session and frame == page.main_frame:
            add_event(context.db, context.session, "navigation", "web", {"url": frame.url})
            context.db.commit()

    async def _download(self, context: ProviderContext, profile: WebConnectionProfile, runtime: WebRuntime, download) -> None:
        if not context.session:
            await download.cancel()
            return
        add_event(context.db, context.session, "download_started", "web", {"filename": Path(download.suggested_filename).name})
        if profile.download_policy != "allow":
            await download.cancel()
            context.db.commit()
            return
        source_path = await download.path()
        if not source_path:
            return
        source = Path(source_path)
        if source.stat().st_size > profile.max_download_bytes:
            await download.cancel()
            add_event(context.db, context.session, "policy_blocked", "web", {"reason": "download_size_limit"})
        else:
            target = runtime.artifact_dir / f"download-{Path(download.suggested_filename).name}"
            shutil.copy2(source, target)
            self.record_artifact(context, target, "download", "application/octet-stream")
        context.db.commit()

    async def handle_input(self, context: ProviderContext, event: dict[str, Any]) -> dict[str, Any]:
        if not context.session or context.session.id not in self.runtimes:
            raise ValueError("Browser runtime is unavailable")
        runtime = self.runtimes[context.session.id]
        kind = event.get("type")
        if kind == "mouse":
            action = event.get("action", "move")
            x, y = float(event.get("x", 0)), float(event.get("y", 0))
            if action == "click":
                await runtime.page.mouse.click(x, y)
                add_event(context.db, context.session, "click", "web", {"x": x, "y": y})
            elif action == "down": await runtime.page.mouse.down(button=event.get("button", "left"))
            elif action == "up": await runtime.page.mouse.up(button=event.get("button", "left"))
            else: await runtime.page.mouse.move(x, y)
        elif kind == "key":
            key = str(event.get("key", ""))[:64]
            if event.get("action") == "up": await runtime.page.keyboard.up(key)
            else: await runtime.page.keyboard.down(key)
        elif kind == "text":
            await runtime.page.keyboard.insert_text(str(event.get("text", ""))[:4096])
            add_event(context.db, context.session, "input_changed", "web", {"selector": event.get("selector"), "field_type": event.get("field_type", "text"), "value_changed": True}, sensitive=True)
        elif kind == "wheel":
            await runtime.page.mouse.wheel(float(event.get("delta_x", 0)), float(event.get("delta_y", 0)))
        else:
            raise ValueError("Unsupported input event")
        return {}

    async def handle_upload(self, context: ProviderContext, selector: str, filename: str, data: bytes) -> None:
        if not context.session or context.session.id not in self.runtimes:
            raise ValueError("Browser runtime is unavailable")
        profile = self.profile(context)
        if profile.upload_policy != "allow" or len(data) > profile.max_upload_bytes:
            raise ValueError("Upload denied by policy")
        runtime = self.runtimes[context.session.id]
        target = runtime.profile_dir / ("upload-" + Path(filename).name)
        try:
            target.write_bytes(data)
            await runtime.page.locator(selector).set_input_files(str(target))
            add_event(context.db, context.session, "upload_started", "web", {"selector": selector, "filename": Path(filename).name, "size_bytes": len(data)})
        finally:
            target.unlink(missing_ok=True)

    def record_artifact(self, context: ProviderContext, path: Path, kind: str, mime: str) -> None:
        if not context.session or not path.is_file():
            return
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        context.db.add(SessionArtifact(session_id=context.session.id, artifact_type=kind, storage_path=str(path.resolve()), sha256=digest.hexdigest(), size_bytes=path.stat().st_size, mime_type=mime))

    async def terminate_session(self, context: ProviderContext, reason: str) -> None:
        if not context.session:
            return
        runtime = self.runtimes.pop(context.session.id, None)
        if not runtime:
            return
        try:
            await runtime.cdp.send("Page.stopScreencast")
            trace_path = runtime.artifact_dir / "trace.zip"
            if runtime.trace_enabled:
                await runtime.context.tracing.stop(path=str(trace_path))
            video = runtime.page.video
            screenshot_path = runtime.artifact_dir / "final.png"
            if settings.pam_web_record_screenshots:
                await runtime.page.screenshot(path=str(screenshot_path))
            await runtime.context.close()
            if runtime.trace_enabled: self.record_artifact(context, trace_path, "trace", "application/zip")
            if settings.pam_web_record_screenshots: self.record_artifact(context, screenshot_path, "screenshot", "image/png")
            if video:
                try: self.record_artifact(context, Path(await video.path()), "video", "video/webm")
                except Exception: pass
            add_event(context.db, context.session, "session_finished", "web", {"reason": reason})
        finally:
            shutil.rmtree(runtime.profile_dir, ignore_errors=True)
            self.semaphore.release()

    async def cleanup_session(self, context: ProviderContext) -> None:
        await self.terminate_session(context, "cleanup")

    async def shutdown(self) -> None:
        for runtime in list(self.runtimes.values()):
            await runtime.context.close()
            shutil.rmtree(runtime.profile_dir, ignore_errors=True)
            self.semaphore.release()
        self.runtimes.clear()
        if self.browser: await self.browser.close()
        if self.playwright: await self.playwright.stop()
        self.browser = self.playwright = None

    def healthy(self) -> bool:
        return self.browser is None or self.browser.is_connected()


web_provider = WebAccessProvider()
