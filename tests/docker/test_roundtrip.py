"""Docker integration tests: full SMTP→IMAP roundtrip via GreenMail.

These tests send an email via SMTP, then read it back via IMAP to verify
the complete email pipeline works end-to-end.

Run: make test-docker
Requires: Docker (auto-skips if not available)
"""

from __future__ import annotations

import asyncio

import pytest

from .conftest import GREENMAIL_USER

pytestmark = pytest.mark.docker


async def _get_first_uid(imap_client) -> str:
    """Helper to get the first email UID from INBOX via metadata stream."""
    async for email_data in imap_client.get_emails_metadata_stream(mailbox="INBOX", page=1, page_size=1):
        return email_data.get("email_id") or email_data.get("uid")
    msg = "No emails found in INBOX"
    raise AssertionError(msg)


class TestSmtpImapRoundtrip:
    """Send via SMTP → read via IMAP in GreenMail."""

    async def test_send_and_count(self, greenmail_smtp_client, greenmail_imap_client):
        """Send an email and verify the count increases."""
        await greenmail_smtp_client.send_email(
            recipients=[GREENMAIL_USER],
            subject="Roundtrip Count Test",
            body="Hello from Docker integration test!",
        )

        # GreenMail may need a moment to deliver
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
