"""Integration tests for IMAP with different security settings.

Tests exercise EmailClient against MockImapServer in multiple security modes:
- ConnectionSecurity.NONE  (plaintext — covered in test_imap_live.py)
- ConnectionSecurity.TLS   (Implicit TLS via self-signed cert)
- Connection test diagnostics with wrong security settings

MockImapServer does NOT support STARTTLS protocol, so STARTTLS IMAP is
tested only at the Docker tier (GreenMail).

Run: make test-integration
"""

from __future__ import annotations

import pytest

from mcp_email_server.config import ConnectionSecurity, EmailServer
from mcp_email_server.emails.classic import test_imap_connection as check_imap_connection

from .conftest import QUOTED_INBOX, TEST_PASSWORD, TEST_USER, make_test_mail

pytestmark = pytest.mark.integration


class TestImapImplicitTLS:
    """IMAP operations over Implicit TLS (ConnectionSecurity.TLS)."""

    async def test_connection_success(self, imap_tls_server_and_port, imap_tls_email_server):
        """Verify TLS connection + login succeeds with self-signed cert."""
        result = await check_imap_connection(imap_tls_email_server, timeout=5)
        assert result.startswith("✅")
        assert "tls" in result

    async def test_email_count(self, imap_tls_server_and_port, imap_tls_client):
        """Verify email count works over TLS."""
        server, _ = imap_tls_server_and_port
        server.receive(make_test_mail(subject="TLS Email"), imap_user=TEST_USER, mailbox=QUOTED_INBOX)

        count = await imap_tls_client.get_email_count(mailbox="INBOX")
        assert count == 1

    async def test_email_body(self, imap_tls_server_and_port, imap_tls_client):
        """Verify body extraction works over TLS."""
        server, _ = imap_tls_server_and_port
        server.receive(
            make_test_mail(subject="TLS Body", body="Encrypted body content."),
            imap_user=TEST_USER,
            mailbox=QUOTED_INBOX,
        )

        result = await imap_tls_client.get_email_body_by_id("1", mailbox="INBOX")
        assert result is not None
        assert "body" in result

    async def test_delete_over_tls(self, imap_tls_server_and_port, imap_tls_client):
        """Verify delete works over TLS."""
        server, _ = imap_tls_server_and_port
        server.receive(make_test_mail(subject="TLS Delete"), imap_user=TEST_USER, mailbox=QUOTED_INBOX)

        deleted, failed = await imap_tls_client.delete_emails(["1"], mailbox="INBOX")
        assert "1" in deleted
        assert len(failed) == 0


class TestImapSecurityMismatch:
    """Test that wrong security settings produce clear error messages."""

    async def test_tls_on_plaintext_server(self, imap_server_and_port):
        """TLS client against plaintext server should fail with clear error."""
        _, port = imap_server_and_port
        server = EmailServer(
            host="127.0.0.1",
            port=port,
            user_name=TEST_USER,
            password=TEST_PASSWORD,
            security=ConnectionSecurity.TLS,
            verify_ssl=False,
        )
        result = await check_imap_connection(server, timeout=3)
        assert result.startswith("❌")

    async def test_starttls_on_plaintext_server(self, imap_server_and_port):
        """STARTTLS against a server without STARTTLS capability should fail clearly."""
        _, port = imap_server_and_port
        server = EmailServer(
            host="127.0.0.1",
            port=port,
            user_name=TEST_USER,
            password=TEST_PASSWORD,
            security=ConnectionSecurity.STARTTLS,
            verify_ssl=False,
        )
        result = await check_imap_connection(server, timeout=3)
        assert result.startswith("❌")
        assert "STARTTLS" in result


# ---------------------------------------------------------------------------
# Blocked IMAP mismatch tests
# TODO(aioimaplib#128): aioimaplib's internal tasks do not support asyncio
# cancellation. Connecting with the wrong security mode (e.g. plaintext client
# to a TLS server, or verify_ssl=True with a self-signed cert) causes
# test_imap_connection() to hang indefinitely — the internal _client_task
# holds transport references that prevent cleanup.
# See: https://github.com/iroco-co/aioimaplib/issues/128
#
# Uncomment when aioimaplib#128 is resolved upstream.
# ---------------------------------------------------------------------------
#
# class TestImapSecurityMismatchBlocked:
#     """Tests blocked by aioimaplib#128 (connection hangs on security mismatch)."""
#
#     async def test_plaintext_on_tls_server(self, imap_tls_server_and_port):
#         """Plaintext client against TLS server should time out with clear error."""
#         _, port = imap_tls_server_and_port
#         server = EmailServer(
#             host="127.0.0.1",
#             port=port,
#             user_name=TEST_USER,
#             password=TEST_PASSWORD,
#             security=ConnectionSecurity.NONE,
#             verify_ssl=False,
#         )
#         result = await check_imap_connection(server, timeout=3)
#         assert result.startswith("❌")
#
#     async def test_verify_ssl_true_rejects_self_signed(self, imap_tls_server_and_port):
#         """verify_ssl=True should reject our self-signed certificate."""
#         _, port = imap_tls_server_and_port
#         server = EmailServer(
#             host="127.0.0.1",
#             port=port,
#             user_name=TEST_USER,
#             password=TEST_PASSWORD,
#             security=ConnectionSecurity.TLS,
#             verify_ssl=True,
#         )
#         result = await check_imap_connection(server, timeout=3)
#         assert result.startswith("❌")
#         assert "SSL" in result or "certificate" in result.lower() or "timed out" in result.lower()
