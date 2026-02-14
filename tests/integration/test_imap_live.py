"""Integration tests for IMAP operations against MockImapServer.

These tests exercise the real EmailClient methods against a live IMAP server
running in-process. No mocks — every byte goes over a TCP socket.

Note: MockImapServer does NOT support INTERNALDATE or BODY.PEEK[HEADER],
so get_emails_metadata_stream() cannot be tested here. Use GreenMail
Docker tests (Tier 2) for full metadata/roundtrip coverage.

Run: make test-integration
"""

from __future__ import annotations

from email.mime.text import MIMEText

import pytest

from mcp_email_server.config import ConnectionSecurity, EmailServer
from mcp_email_server.emails.classic import test_imap_connection as check_imap_connection

from .conftest import QUOTED_INBOX, TEST_USER, make_multipart_mail, make_test_mail

pytestmark = pytest.mark.integration


class TestImapConnectionLive:
    """Test IMAP connection against a real server."""

    async def test_connection_success(self, imap_server_and_port, imap_email_server):
        result = await check_imap_connection(imap_email_server, timeout=5)
        assert result.startswith("✅")
        assert "successful" in result

    async def test_connection_wrong_port(self):
        server = EmailServer(
            host="127.0.0.1",
            port=1,
            user_name="x",
            password="x",
            security=ConnectionSecurity.NONE,
            verify_ssl=False,
        )
        result = await check_imap_connection(server, timeout=2)
        assert result.startswith("❌")


class TestGetEmailCount:
    """Test get_email_count against MockImapServer."""

    async def test_empty_inbox(self, imap_server_and_port, imap_client):
        count = await imap_client.get_email_count(mailbox="INBOX")
        assert count == 0

    async def test_with_injected_emails(self, imap_server_and_port, imap_client):
        server, _ = imap_server_and_port
        server.receive(make_test_mail(subject="Email 1"), imap_user=TEST_USER, mailbox=QUOTED_INBOX)
        server.receive(make_test_mail(subject="Email 2"), imap_user=TEST_USER, mailbox=QUOTED_INBOX)
        server.receive(make_test_mail(subject="Email 3"), imap_user=TEST_USER, mailbox=QUOTED_INBOX)

        count = await imap_client.get_email_count(mailbox="INBOX")
        assert count == 3


class TestGetEmailBody:
    """Test get_email_body_by_id against MockImapServer."""

    async def test_body_extraction(self, imap_server_and_port, imap_client):
        server, _ = imap_server_and_port
        server.receive(
            make_test_mail(subject="Body Test", body="This is the body content."),
            imap_user=TEST_USER,
            mailbox=QUOTED_INBOX,
        )

        body_result = await imap_client.get_email_body_by_id("1", mailbox="INBOX")
        assert body_result is not None
        assert "body" in body_result


class TestDownloadAttachment:
    """Test download_attachment against MockImapServer."""

    async def test_attachment_download(self, imap_server_and_port, imap_client, tmp_path):
        server, _ = imap_server_and_port
        attachment_content = b"Hello from attachment!"
        server.receive(
            make_multipart_mail(
                subject="Attachment Test",
                attachment_name="notes.txt",
                attachment_content=attachment_content,
            ),
            imap_user=TEST_USER,
            mailbox=QUOTED_INBOX,
        )

        save_path = str(tmp_path / "notes.txt")
        download = await imap_client.download_attachment("1", "notes.txt", save_path, mailbox="INBOX")

        assert download["attachment_name"] == "notes.txt"
        assert download["size"] == len(attachment_content)
        assert (tmp_path / "notes.txt").read_bytes() == attachment_content


class TestDeleteEmails:
    """Test delete_emails against MockImapServer."""

    async def test_delete_and_verify_gone(self, imap_server_and_port, imap_client):
        server, _ = imap_server_and_port
        server.receive(make_test_mail(subject="To Delete"), imap_user=TEST_USER, mailbox=QUOTED_INBOX)

        # Verify exists
        count_before = await imap_client.get_email_count(mailbox="INBOX")
        assert count_before == 1

        # Delete UID 1
        deleted, failed = await imap_client.delete_emails(["1"], mailbox="INBOX")
        assert "1" in deleted
        assert len(failed) == 0

        # Verify gone
        count_after = await imap_client.get_email_count(mailbox="INBOX")
        assert count_after == 0


class TestAppendToSent:
    """Test append_to_sent against MockImapServer."""

    async def test_append_message(self, imap_server_and_port, imap_client, imap_email_server):
        msg = MIMEText("Sent message body", "plain", "utf-8")
        msg["Subject"] = "Sent Test"
        msg["From"] = TEST_USER
        msg["To"] = "recipient@localhost"

        result = await imap_client.append_to_sent(msg, imap_email_server)
        assert result is True
