#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io
import os
import re
import secrets
import shutil
import string
from datetime import datetime

import psutil
import pyudev
import pyzipper
import requests
from flask import jsonify, send_file

from app.utils import effective_capture_export, read_config, stop_monitoring
from app.spyguard_logging import LOG_PATH, get_logger

# POST multipart upload; base URL = config frontend.spyguard_server.
REPORT_SEND_PATH = "/report/send"


class Save():

    def __init__(self):
        self.mount_point = ""
        self.log = get_logger()
        return None

    def _copy_session_log_to_capture_assets(self, token: str) -> None:
        """Snapshot /tmp/spyguard.log into the capture assets folder before archiving."""
        cap_assets = os.path.join("/tmp", token, "assets")
        dest = os.path.join(cap_assets, "spyguard.log")
        if not os.path.isdir(cap_assets):
            return
        try:
            if os.path.isfile(LOG_PATH):
                shutil.copy2(LOG_PATH, dest)
            else:
                with open(dest, "w", encoding="utf-8") as f:
                    f.write("")
            self.log.info("session log copied to capture assets token=%s", token)
        except Exception:
            self.log.warning(
                "could not copy session log to capture assets token=%s",
                token,
                exc_info=True,
            )

    def usb_check(self) -> dict:
        """Check if an USB storage is connected or not.

        Returns:
            dict: contains the connection status.
        """
        self.usb_devices = []
        context = pyudev.Context()
        removable = [device for device in context.list_devices(
            subsystem='block', DEVTYPE='disk')]
        for device in removable:
            if "usb" in device.sys_path:
                partitions = [device.device_node for device in context.list_devices(
                    subsystem='block', DEVTYPE='partition', parent=device)]
                for p in psutil.disk_partitions():
                    if p.device in partitions:
                        self.mount_point = p.mountpoint
                        self.log.info("usb_check connected mount_point=%s", self.mount_point)
                        return jsonify({"status": True,
                                        "message": "USB storage connected"})
        self.mount_point = ""
        self.log.info("usb_check not connected")
        return jsonify({"status": False,
                        "message": "USB storage not connected"})

    def save_capture(self, token, method) -> any:
        """Save the capture to the USB device or push a ZIP
        file to download.

        Args:
            token (str): capture token
            method (str): method used to save

        Returns:
            dict: operation status OR Flask answer.
        """
        if re.match(r"[A-F0-9]{8}", token):
            try:
                if method == "usb":
                    cd = datetime.now().strftime("%d%m%Y-%H%M")
                    self.log.info("save_capture usb token=%s mount_point=%s", token, self.mount_point)
                    self._copy_session_log_to_capture_assets(token)
                    if shutil.make_archive("{}/SpyGuard_{}".format(self.mount_point, cd), "zip", "/tmp/{}/".format(token)):
                        shutil.rmtree("/tmp/{}/".format(token))
                        self.log.info("save_capture usb done token=%s", token)
                        return jsonify({"status": True,
                                        "message": "Capture saved on the USB key"})
                elif method == "url":
                    cd = datetime.now().strftime("%d%m%Y-%H%M")
                    self.log.info("save_capture browser zip token=%s", token)
                    if shutil.make_archive("/tmp/SpyGuard_{}".format(cd), "zip", "/tmp/{}/".format(token)):
                        shutil.rmtree("/tmp/{}/".format(token))
                        with open("/tmp/SpyGuard_{}.zip".format(cd), "rb") as f:
                            return send_file(
                                io.BytesIO(f.read()),
                                mimetype="application/octet-stream",
                                as_attachment=True,
                                attachment_filename="SpyGuard_{}.zip".format(cd))
            except Exception:
                self.log.exception("save_capture failed token=%s method=%s", token, method)
                return jsonify({"status": False,
                                "message": "Error while saving capture"})
        else:
            return jsonify({"status": False,
                            "message": "Bad token value"})

    @staticmethod
    def _random_archive_password() -> str:
        # Avoid ambiguous characters (O/0, l/1, o) for easier transcription.
        alphabet = "abcdefghijkmnpqrstuvwxyz23456789"

        def segment():
            return "".join(secrets.choice(alphabet) for _ in range(4))

        return "{}-{}-{}".format(segment(), segment(), segment())

    @staticmethod
    def _write_encrypted_zip(source_dir: str, dest_zip: str, password: str) -> None:
        """ZIP with WinZip AES (pyzipper 0.3.x); contents encrypted, names listed."""
        pwd = password.encode("utf-8")
        base = os.path.abspath(source_dir)
        with pyzipper.AESZipFile(
            dest_zip,
            "w",
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
        ) as zf:
            zf.setpassword(pwd)
            for root, _dirs, files in os.walk(base):
                for name in files:
                    full = os.path.join(root, name)
                    arcname = os.path.relpath(full, base)
                    zf.write(full, arcname)

    @staticmethod
    def _remote_upload_error_payload(resp: requests.Response) -> dict:
        """Map remote HTTP error JSON to a structured payload for the UI."""
        code = resp.status_code
        out = {"status": False, "http_status": code}
        try:
            body = resp.json()
        except ValueError:
            out["error"] = "server_error"
            out["message"] = "Server error: HTTP {}".format(code)
            return out
        if not isinstance(body, dict):
            out["error"] = "server_error"
            out["message"] = "Server error: HTTP {}".format(code)
            return out
        err = body.get("error") or "server_error"
        out["error"] = err
        if body.get("message"):
            out["message"] = body["message"]
        for key in (
            "max_mb",
            "max_bytes",
            "retry_after_seconds",
            "daily_limit",
            "hourly_limit",
            "reason",
            "daily_window_seconds",
            "hourly_window_seconds",
        ):
            if key in body:
                out[key] = body[key]
        for key in ("not_encrypted_files", "missing_files", "extra_files"):
            if key in body:
                out[key] = body[key]
        if err == "bad_zip":
            if body.get("not_encrypted_files"):
                out["error"] = "bad_zip_not_encrypted"
            elif body.get("missing_files") or body.get("extra_files"):
                out["error"] = "bad_zip_structure"
        if "message" not in out:
            out["message"] = "Server error: HTTP {}".format(code)
        return out

    def upload_cloud(self, token) -> any:
        """Build an encrypted ZIP of the capture, upload it to the remote API."""
        if not re.match(r"[A-F0-9]{8}", token):
            return jsonify(
                {"status": False, "error": "bad_token", "message": "Bad token value"}
            )
        cap_dir = "/tmp/{}/".format(token)
        if not os.path.isdir(cap_dir):
            return jsonify(
                {"status": False, "error": "capture_not_found", "message": "Capture not found"}
            )

        if effective_capture_export() != "server":
            return jsonify(
                {
                    "status": False,
                    "error": "export_not_server",
                    "message": "Server export not selected in configuration",
                }
            )

        cd = datetime.now().strftime("%d%m%Y-%H%M")
        zip_path = "/tmp/SpyGuard_cloud_{}.zip".format(cd)
        password = self._random_archive_password()
        resp = None

        try:
            # Release pcap / suricata handles so the archive can read all files.
            stop_monitoring()
            self._copy_session_log_to_capture_assets(token)
            self._write_encrypted_zip(cap_dir, zip_path, password)
            base = read_config(
                ("frontend", "spyguard_server"),
                "http://localhost:5000",
            )
            base = (base or "http://localhost:5000").strip().rstrip("/")
            endpoint = base + REPORT_SEND_PATH
            self.log.info("upload_cloud start token=%s endpoint=%s zip=%s", token, endpoint, zip_path)
            with open(zip_path, "rb") as zf:
                resp = requests.post(
                    endpoint,
                    files={
                        "file": (
                            "SpyGuard_{}.zip".format(cd),
                            zf,
                            "application/zip",
                        )
                    },
                    timeout=120,
                )
        except requests.RequestException as exc:
            self.log.exception("upload_cloud request failed token=%s", token)
            return jsonify(
                {"status": False, "message": "Upload failed: {}".format(exc)}
            )
        except Exception as exc:
            self.log.exception("upload_cloud prepare failed token=%s", token)
            return jsonify(
                {
                    "status": False,
                    "message": "Error while preparing capture: {}".format(exc),
                }
            )
        finally:
            if os.path.isfile(zip_path):
                try:
                    os.remove(zip_path)
                except OSError:
                    pass

        if resp is None:
            return jsonify(
                {
                    "status": False,
                    "error": "no_response",
                    "message": "No response from upload",
                }
            )

        if resp.status_code >= 400:
            self.log.warning(
                "upload_cloud server HTTP error token=%s status=%s body=%s",
                token,
                resp.status_code,
                getattr(resp, "text", "")[:500],
            )
            return jsonify(Save._remote_upload_error_payload(resp))

        try:
            data = resp.json()
        except ValueError:
            return jsonify(
                {
                    "status": False,
                    "error": "invalid_response",
                    "message": "Invalid server response",
                }
            )

        capture_id = data.get("capture_id") or data.get("captureId")
        if capture_id is None:
            return jsonify(
                {
                    "status": False,
                    "error": "missing_capture_id",
                    "message": "Missing capture_id in response",
                }
            )
        capture_id = str(capture_id).strip().lower()
        if not re.match(r"^[0-9a-f]{8}$", capture_id):
            return jsonify(
                {
                    "status": False,
                    "error": "invalid_capture_id",
                    "message": "Invalid capture_id from server",
                }
            )

        try:
            shutil.rmtree(cap_dir)
        except Exception:
            self.log.exception("upload_cloud cleanup failed token=%s", token)
            return jsonify(
                {
                    "status": False,
                    "error": "cleanup_failed",
                    "message": "Uploaded but failed to remove local capture",
                }
            )

        self.log.info("upload_cloud done token=%s capture_id=%s", token, capture_id)
        return jsonify(
            {
                "status": True,
                "capture_id": capture_id,
                "archive_password": password,
                "message": "Capture uploaded",
            }
        )
