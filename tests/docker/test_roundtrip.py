"""Docker integration tests: full SMTP/IMAP roundtrip via GreenMail.

Tests the complete email pipeline end-to-end across security modes:
- NONE:     plaintext SMTP (3025) / IMAP (3143)
- TLS:      SMTPS (3465) / IMAPS (3993)
- STARTTLS: skipped (greenmail#135 — GreenMail does not support STARTTLS)

Run: make test-docker
Requires: Docker (auto-skips if not available)
"""

from __future__ import annotations

import asyncio

import pytest

from mcp_email_server.emails.classic import (
    test_imap_connection as check_imap_connection,
)
from mcp_email_server.emails.classic import (
    test_smtp_connection as check_smtp_connection,
)

from .conftest import GREENMAIL_USER

pytestmark = pytest.mark.docker


async def _get_first_uid(imap_client) -> str:
    """Helper to get the first email UID from INBOX via metadata stream."""
    async for email_data in imap_client.get_emails_metadata_stream(mailbox="INBOX", page=1, page_size=1):
        return email_data.get("email_id") or email_data.get("uid")
    msg = "No emails found in INBOX"
    raise AssertionError(msg)


# ---------------------------------------------------------------------------
# Plaintext (NONE) roundtrip
# ---------------------------------------------------------------------------


class TestRoundtripPlaintext:
    """Send via SMTP, read via IMAP in GreenMail (plaintext)."""

    async def test_send_and_count(self, greenmail_smtp_client, greenmail_imap_client):
        """Send an email and verify the count increases."""
        await greenmail_smtp_client.send_email(
            recipients=[GREENMAIL_USER],
            subject="Roundtrip Count Test",
            body="Hello from Docker integration test!",
        )
        await asyncio.sleep(1)

        count = await greenmail_imap_client.get_email_count(mailbox="INBOX")
        assert count >= 1

    async def test_send_and_read_body(self, greenmail_smtp_client, greenmail_imap_client):
        """Send an email and verify the body content via IMAP."""
        await greenmail_smtp_client.send_email(
            recipients=[GREENMAIL_USER],
            subject="Body Roundtrip",
            body="Expected body content here.",
        )
        await asyncio.sleep(1)

        uid = await _get_first_uid(greenmail_imap_client)
        body_result = await greenmail_imap_client.get_email_body_by_id(uid, mailbox="INBOX")
        assert body_result is not None
        assert "body" in body_result

    async def test_send_and_delete(self, greenmail_smtp_client, greenmail_imap_client):
        """Send, read, delete, and verify the email is gone."""
        await greenmail_smtp_client.send_email(
            recipients=[GREENMAIL_USER],
            subject="Delete Roundtrip",
            body="This will be deleted.",
        )
        await asyncio.sleep(1)

        count_before = await greenmail_imap_client.get_email_count(mailbox="INBOX")
        assert count_before >= 1

        uid = await _get_first_uid(greenmail_imap_client)
        deleted, _failed = await greenmail_imap_client.delete_emails([uid], mailbox="INBOX")
        assert uid in deleted


# ---------------------------------------------------------------------------
# Implicit TLS (SMTPS/IMAPS) roundtrip
# ---------------------------------------------------------------------------


class TestRoundtripTLS:
    """Send via SMTPS, read via IMAPS in GreenMail (Implicit TLS)."""

    async def test_smtp_tls_connection(self, greenmail_smtps_server):
        """Verify SMTPS connection succeeds."""
        result = await check_smtp_connection(greenmail_smtps_server, timeout=10)
        assert result.startswith("\u2705")
        assert "tls" in result

    async def test_imap_tls_connection(self, greenmail_imaps_server):
        """Verify IMAPS connection succeeds."""
        result = await check_imap_connection(greenmail_imaps_server, timeout=10)
        assert result.startswith("\u2705")
        assert "tls" in result

    async def test_send_tls_read_tls(self, greenmail_smtps_client, greenmail_imaps_client):
        """Full TLS roundtrip: send via SMTPS, read via IMAPS."""
        await greenmail_smtps_client.send_email(
            recipients=[GREENMAIL_USER],
            subject="TLS Roundtrip",
            body="Encrypted end-to-end!",
        )
        await asyncio.sleep(1)

        count = await greenmail_imaps_client.get_email_count(mailbox="INBOX")
        assert count >= 1

        uid = await _get_first_uid(greenmail_imaps_client)
        body_result = await greenmail_imaps_client.get_email_body_by_id(uid, mailbox="INBOX")
        assert body_result is not None


# ---------------------------------------------------------------------------
# STARTTLS roundtrip
# TODO(greenmail#135): GreenMail does not advertise STARTTLS on plaintext ports.
# The SMTP EHLO response on port 3025 omits the STARTTLS extension, and the
# IMAP CAPABILITY on port 3143 does not include STARTTLS.
# STARTTLS is tested at Tier 1: SMTP via aiosmtpd, IMAP via unit tests.
# See: https://github.com/greenmail-mail-test/greenmail/issues/135
#
# Uncomment when GreenMail adds STARTTLS support on plaintext ports.
# ---------------------------------------------------------------------------
#
# class TestRoundtripSTARTTLS:
#     """Send via SMTP+STARTTLS, read via IMAP+STARTTLS in GreenMail."""
#
#     async def test_smtp_starttls_connection(self, greenmail_smtp_starttls_server):
#         """Verify SMTP STARTTLS connection succeeds."""
#         result = await check_smtp_connection(greenmail_smtp_starttls_server, timeout=10)
#         assert result.startswith("\u2705")
#         assert "starttls" in result
#
#     async def test_imap_starttls_connection(self, greenmail_imap_starttls_server):
#         """Verify IMAP STARTTLS connection succeeds."""
#         result = await check_imap_connection(greenmail_imap_starttls_server, timeout=10)
#         assert result.startswith("\u2705")
#         assert "starttls" in result
#
#     async def test_send_starttls_read_starttls(
#         self, greenmail_smtp_starttls_client, greenmail_imap_starttls_client
#     ):
#         """Full STARTTLS roundtrip: send + read with STARTTLS on both sides."""
#         await greenmail_smtp_starttls_client.send_email(
#             recipients=[GREENMAIL_USER],
#             subject="STARTTLS Roundtrip",
#             body="Upgraded to TLS on both sides!",
#         )
#         await asyncio.sleep(1)
#
#         count = await greenmail_imap_starttls_client.get_email_count(mailbox="INBOX")
#         assert count >= 1
#
#         uid = await _get_first_uid(greenmail_imap_starttls_client)
#         body_result = await greenmail_imap_starttls_client.get_email_body_by_id(
#             uid, mailbox="INBOX"
#         )
#         assert body_result is not None
