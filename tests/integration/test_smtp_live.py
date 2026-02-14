"""Integration tests for SMTP operations against pytest-localserver.

These tests exercise the real EmailClient.send_email() method against a live
SMTP server. Sent messages are captured in smtpserver.outbox for inspection.

Run: make test-integration
"""

from __future__ import annotations

import pytest

from mcp_email_server.emails.classic import test_smtp_connection as check_smtp_connection

from .conftest import TEST_USER

pytestmark = pytest.mark.integration


class TestSmtpConnectionLive:
    """Test SMTP connection against a real server."""

    async def test_connection_success(self, smtp_email_server):
        result = await check_smtp_connection(smtp_email_server, timeout=5)
        assert result.startswith("✅")
        assert "successful" in result


class TestSendEmail:
    """Test send_email against pytest-localserver SMTP."""

    async def test_send_basic_email(self, smtp_client, smtpserver):
        await smtp_client.send_email(
            recipients=["recipient@localhost"],
            subject="Basic Test",
            body="Hello from integration test!",
        )

        assert len(smtpserver.outbox) == 1
        msg = smtpserver.outbox[0]
        assert msg["Subject"] == "Basic Test"
        assert msg["To"] == "recipient@localhost"
        assert msg["From"] == TEST_USER

    async def test_send_email_with_cc(self, smtp_client, smtpserver):
        await smtp_client.send_email(
            recipients=["to@localhost"],
            subject="CC Test",
            body="With CC",
            cc=["cc1@localhost", "cc2@localhost"],
        )

        assert len(smtpserver.outbox) == 1
        msg = smtpserver.outbox[0]
        assert msg["Cc"] == "cc1@localhost, cc2@localhost"

    async def test_send_email_with_bcc(self, smtp_client, smtpserver):
        await smtp_client.send_email(
            recipients=["to@localhost"],
            subject="BCC Test",
            body="With BCC",
            bcc=["secret@localhost"],
        )

        assert len(smtpserver.outbox) == 1
        msg = smtpserver.outbox[0]
        # BCC should NOT appear in headers
        assert msg.get("Bcc") is None

    async def test_send_html_email(self, smtp_client, smtpserver):
        await smtp_client.send_email(
            recipients=["to@localhost"],
            subject="HTML Test",
            body="<h1>Hello</h1>",
            html=True,
        )

        assert len(smtpserver.outbox) == 1
        msg = smtpserver.outbox[0]
        assert msg.get_content_type() == "text/html"

    async def test_send_email_with_attachment(self, smtp_client, smtpserver, tmp_path):
        # Create a temporary attachment file
        attachment = tmp_path / "test.txt"
        attachment.write_text("attachment content")

        await smtp_client.send_email(
            recipients=["to@localhost"],
            subject="Attachment Test",
            body="See attached",
            attachments=[str(attachment)],
        )

        assert len(smtpserver.outbox) == 1
        msg = smtpserver.outbox[0]
        assert msg.is_multipart()

        # Find the attachment part
        parts = list(msg.walk())
        attachment_parts = [
            p for p in parts if p.get("Content-Disposition") and "attachment" in p.get("Content-Disposition", "")
        ]
        assert len(attachment_parts) == 1
        assert "test.txt" in attachment_parts[0].get_filename()

    async def test_send_reply_email(self, smtp_client, smtpserver):
        await smtp_client.send_email(
            recipients=["to@localhost"],
            subject="Re: Original Subject",
            body="My reply",
            in_reply_to="<original-id@localhost>",
            references="<original-id@localhost>",
        )

        assert len(smtpserver.outbox) == 1
        msg = smtpserver.outbox[0]
        assert msg["In-Reply-To"] == "<original-id@localhost>"
        assert msg["References"] == "<original-id@localhost>"

    async def test_send_sets_message_id_and_date(self, smtp_client, smtpserver):
        await smtp_client.send_email(
            recipients=["to@localhost"],
            subject="Headers Test",
            body="Check headers",
        )

        assert len(smtpserver.outbox) == 1
        msg = smtpserver.outbox[0]
        assert msg["Message-Id"] is not None
        assert msg["Date"] is not None

    async def test_send_unicode_subject(self, smtp_client, smtpserver):
        await smtp_client.send_email(
            recipients=["to@localhost"],
            subject="日本語テスト",
            body="Unicode subject test",
        )

        assert len(smtpserver.outbox) == 1

    async def test_send_multiple_recipients(self, smtp_client, smtpserver):
        await smtp_client.send_email(
            recipients=["a@localhost", "b@localhost", "c@localhost"],
            subject="Multi-recipient",
            body="To multiple people",
        )

        assert len(smtpserver.outbox) == 1
        msg = smtpserver.outbox[0]
        assert "a@localhost" in msg["To"]
        assert "b@localhost" in msg["To"]
        assert "c@localhost" in msg["To"]
