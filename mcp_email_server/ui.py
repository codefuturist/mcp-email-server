import asyncio

import gradio as gr

from mcp_email_server.config import ConnectionSecurity, EmailServer, EmailSettings, get_settings, store_settings
from mcp_email_server.emails.classic import test_imap_connection, test_smtp_connection
from mcp_email_server.tools.installer import install_claude_desktop, is_installed, need_update, uninstall_claude_desktop

PASSWORD_PLACEHOLDER = "********"  # noqa: S105
IMAP_PORT_MAP = {"tls": 993, "starttls": 143, "none": 143}
SMTP_PORT_MAP = {"tls": 465, "starttls": 587, "none": 25}


def _get_form_defaults():
    """Return default values for all form fields."""
    return (
        "",  # account_name
        "",  # full_name
        "",  # email_address
        "",  # user_name
        "",  # password
        "",  # imap_host
        993,  # imap_port
        "tls",  # imap_security
        True,  # imap_verify_ssl
        "",  # imap_user_name
        "",  # imap_password
        "",  # smtp_host
        465,  # smtp_port
        "tls",  # smtp_security
        True,  # smtp_verify_ssl
        "",  # smtp_user_name
        "",  # smtp_password
        True,  # same_security
    )


def create_ui():  # noqa: C901
    with gr.Blocks(title="Email Settings Configuration") as app:
        gr.Markdown("# Email Settings Configuration")

        # Hidden state to track edit mode
        editing_account = gr.State(value=None)

        def get_current_accounts():
            settings = get_settings(reload=True)
            return [email.account_name for email in settings.emails]

        def update_account_list():
            settings = get_settings(reload=True)
            email_accounts = [email.account_name for email in settings.emails]

            if email_accounts:
                accounts_details = []
                for email_cfg in settings.emails:
                    details = [
                        f"**Account Name:** {email_cfg.account_name}",
                        f"**Full Name:** {email_cfg.full_name}",
                        f"**Email Address:** {email_cfg.email_address}",
                    ]
                    if hasattr(email_cfg, "description") and email_cfg.description:
                        details.append(f"**Description:** {email_cfg.description}")
                    if hasattr(email_cfg, "incoming") and hasattr(email_cfg.incoming, "host"):
                        details.append(f"**IMAP Provider:** {email_cfg.incoming.host}")
                    if hasattr(email_cfg, "outgoing") and hasattr(email_cfg.outgoing, "host"):
                        details.append(f"**SMTP Provider:** {email_cfg.outgoing.host}")
                    accounts_details.append("### " + email_cfg.account_name + "\n" + "\n".join(details) + "\n")

                accounts_md = "\n".join(accounts_details)
                return (
                    f"## Configured Accounts\n{accounts_md}",
                    gr.update(choices=email_accounts, value=None),
                    gr.update(visible=True),
                )
            else:
                return (
                    "No email accounts configured yet.",
                    gr.update(choices=[], value=None),
                    gr.update(visible=False),
                )

        # --- Current Email Accounts ---
        with gr.Accordion("Current Email Accounts", open=True):
            accounts_display = gr.Markdown("")
            account_to_delete = gr.Dropdown(choices=[], label="Select Account to Delete", interactive=True)
            delete_status = gr.Markdown("")
            delete_btn = gr.Button("Delete Selected Account")

            def delete_email_account(account_name):
                if not account_name:
                    return "Error: Please select an account to delete.", *update_account_list()
                try:
                    settings = get_settings()
                    settings.delete_email(account_name)
                    store_settings(settings)
                    return f"Success: Email account '{account_name}' has been deleted.", *update_account_list()
                except Exception as e:
                    return f"Error: {e!s}", *update_account_list()

            delete_btn.click(
                fn=delete_email_account,
                inputs=[account_to_delete],
                outputs=[delete_status, accounts_display, account_to_delete, delete_btn],
            )
            app.load(fn=update_account_list, inputs=None, outputs=[accounts_display, account_to_delete, delete_btn])

        # --- Add / Edit Email Account ---
        with gr.Accordion("Add / Edit Email Account", open=True):
            gr.Markdown("### Email Account Settings")

            # Edit existing account dropdown
            edit_account = gr.Dropdown(
                choices=[],
                label="Edit Existing Account",
                interactive=True,
                info="Select an account to edit, or leave empty to create a new one",
            )
            clear_btn = gr.Button("Clear / New Account", size="sm")

            # Basic account information
            account_name = gr.Textbox(label="Account Name", placeholder="e.g. work_email")
            full_name = gr.Textbox(label="Full Name", placeholder="e.g. John Doe")
            email_address = gr.Textbox(label="Email Address", placeholder="e.g. john@example.com")

            # Credentials
            user_name = gr.Textbox(label="Username", placeholder="e.g. john@example.com")
            password = gr.Textbox(label="Password", type="password")

            # IMAP and SMTP settings
            with gr.Row():
                with gr.Column():
                    gr.Markdown("### IMAP Settings (Incoming)")
                    imap_host = gr.Textbox(label="IMAP Host", placeholder="e.g. imap.example.com")
                    imap_port = gr.Number(label="IMAP Port", value=993)
                    imap_security = gr.Dropdown(
                        label="Connection Security",
                        choices=["tls", "starttls", "none"],
                        value="tls",
                        info="TLS (port 993) | STARTTLS (port 143) | None (not recommended)",
                    )
                    imap_verify_ssl = gr.Checkbox(label="Verify SSL Certificate", value=True)
                    imap_user_name = gr.Textbox(
                        label="IMAP Username (optional)", placeholder="Leave empty to use the same as above"
                    )
                    imap_password = gr.Textbox(
                        label="IMAP Password (optional)",
                        type="password",
                        placeholder="Leave empty to use the same as above",
                    )

                with gr.Column():
                    gr.Markdown("### SMTP Settings (Outgoing)")
                    smtp_host = gr.Textbox(label="SMTP Host", placeholder="e.g. smtp.example.com")
                    smtp_port = gr.Number(label="SMTP Port", value=465)
                    same_security = gr.Checkbox(
                        label="Use same security settings as IMAP",
                        value=True,
                        info="When checked, SMTP security mirrors IMAP settings",
                    )
                    smtp_security = gr.Dropdown(
                        label="Connection Security",
                        choices=["tls", "starttls", "none"],
                        value="tls",
                        info="TLS (port 465) | STARTTLS (port 587) | None (not recommended)",
                        interactive=False,
                    )
                    smtp_verify_ssl = gr.Checkbox(label="Verify SSL Certificate", value=True, interactive=False)
                    smtp_user_name = gr.Textbox(
                        label="SMTP Username (optional)", placeholder="Leave empty to use the same as above"
                    )
                    smtp_password = gr.Textbox(
                        label="SMTP Password (optional)",
                        type="password",
                        placeholder="Leave empty to use the same as above",
                    )

            # --- Auto-update port on security change ---
            def update_imap_port(security):
                return IMAP_PORT_MAP.get(security, 993)

            def on_imap_security_change(security, same_sec):
                """Update IMAP port, and mirror to SMTP if same_security is checked."""
                imap_p = IMAP_PORT_MAP.get(security, 993)
                if same_sec:
                    smtp_p = SMTP_PORT_MAP.get(security, 465)
                    return imap_p, security, True, smtp_p
                return imap_p, gr.update(), gr.update(), gr.update()

            imap_security.change(
                fn=on_imap_security_change,
                inputs=[imap_security, same_security],
                outputs=[imap_port, smtp_security, smtp_verify_ssl, smtp_port],
            )

            def on_imap_verify_ssl_change(verify, same_sec):
                if same_sec:
                    return verify
                return gr.update()

            imap_verify_ssl.change(
                fn=on_imap_verify_ssl_change,
                inputs=[imap_verify_ssl, same_security],
                outputs=[smtp_verify_ssl],
            )

            def on_same_security_toggle(same_sec, imap_sec, imap_verify):
                """Toggle SMTP security fields interactive state and sync values."""
                if same_sec:
                    smtp_p = SMTP_PORT_MAP.get(imap_sec, 465)
                    return (
                        gr.update(value=imap_sec, interactive=False),
                        gr.update(value=imap_verify, interactive=False),
                        smtp_p,
                    )
                return (
                    gr.update(interactive=True),
                    gr.update(interactive=True),
                    gr.update(),
                )

            same_security.change(
                fn=on_same_security_toggle,
                inputs=[same_security, imap_security, imap_verify_ssl],
                outputs=[smtp_security, smtp_verify_ssl, smtp_port],
            )

            def update_smtp_port(security):
                return SMTP_PORT_MAP.get(security, 465)

            smtp_security.change(fn=update_smtp_port, inputs=[smtp_security], outputs=[smtp_port])

            # --- Test Connection Buttons ---
            with gr.Row():
                test_imap_btn = gr.Button("🔌 Test IMAP Connection", size="sm")
                test_smtp_btn = gr.Button("🔌 Test SMTP Connection", size="sm")
            test_status = gr.Markdown("")

            def _build_server(host, port, user, pwd, security, verify_ssl):
                return EmailServer(
                    user_name=user,
                    password=pwd,
                    host=host,
                    port=int(port),
                    security=security,
                    verify_ssl=verify_ssl,
                )

            def run_imap_test(
                imap_host,
                imap_port,
                imap_security,
                imap_verify_ssl,
                user_name,
                password,
                imap_user_name,
                imap_password,
            ):
                if not imap_host:
                    return "❌ Please enter an IMAP host."
                effective_user = imap_user_name if imap_user_name else user_name
                effective_pass = imap_password if imap_password else password
                if not effective_user or not effective_pass:
                    return "❌ Please enter username and password."
                try:
                    server = _build_server(
                        imap_host,
                        imap_port,
                        effective_user,
                        effective_pass,
                        imap_security,
                        imap_verify_ssl,
                    )
                    return asyncio.run(test_imap_connection(server))
                except Exception as e:
                    return f"❌ Error: {e}"

            def run_smtp_test(
                smtp_host,
                smtp_port,
                smtp_security,
                smtp_verify_ssl,
                user_name,
                password,
                smtp_user_name,
                smtp_password,
            ):
                if not smtp_host:
                    return "❌ Please enter an SMTP host."
                effective_user = smtp_user_name if smtp_user_name else user_name
                effective_pass = smtp_password if smtp_password else password
                if not effective_user or not effective_pass:
                    return "❌ Please enter username and password."
                try:
                    server = _build_server(
                        smtp_host,
                        smtp_port,
                        effective_user,
                        effective_pass,
                        smtp_security,
                        smtp_verify_ssl,
                    )
                    return asyncio.run(test_smtp_connection(server))
                except Exception as e:
                    return f"❌ Error: {e}"

            test_imap_btn.click(
                fn=run_imap_test,
                inputs=[
                    imap_host,
                    imap_port,
                    imap_security,
                    imap_verify_ssl,
                    user_name,
                    password,
                    imap_user_name,
                    imap_password,
                ],
                outputs=[test_status],
            )
            test_smtp_btn.click(
                fn=run_smtp_test,
                inputs=[
                    smtp_host,
                    smtp_port,
                    smtp_security,
                    smtp_verify_ssl,
                    user_name,
                    password,
                    smtp_user_name,
                    smtp_password,
                ],
                outputs=[test_status],
            )

            # --- Load existing account for editing ---
            all_form_fields = [
                account_name,
                full_name,
                email_address,
                user_name,
                password,
                imap_host,
                imap_port,
                imap_security,
                imap_verify_ssl,
                imap_user_name,
                imap_password,
                smtp_host,
                smtp_port,
                smtp_security,
                smtp_verify_ssl,
                smtp_user_name,
                smtp_password,
                same_security,
            ]

            def load_account(selected_account):
                """Load an existing account's settings into the form."""
                if not selected_account:
                    return (None, *_get_form_defaults())

                settings = get_settings(reload=True)
                for email_cfg in settings.emails:
                    if email_cfg.account_name == selected_account:
                        inc = email_cfg.incoming
                        out = email_cfg.outgoing
                        same_sec = inc.security == out.security and inc.verify_ssl == out.verify_ssl
                        return (
                            selected_account,  # editing_account state
                            email_cfg.account_name,
                            email_cfg.full_name,
                            email_cfg.email_address,
                            inc.user_name,
                            PASSWORD_PLACEHOLDER,
                            inc.host,
                            inc.port,
                            inc.security.value,
                            inc.verify_ssl,
                            "" if inc.user_name == out.user_name else out.user_name,
                            "",
                            out.host,
                            out.port,
                            out.security.value,
                            out.verify_ssl,
                            "" if out.user_name == inc.user_name else out.user_name,
                            "",
                            same_sec,
                        )

                return (None, *_get_form_defaults())

            edit_account.change(
                fn=load_account,
                inputs=[edit_account],
                outputs=[editing_account, *all_form_fields],
            )

            def clear_form():
                return (None, gr.update(value=None), *_get_form_defaults())

            clear_btn.click(
                fn=clear_form,
                inputs=[],
                outputs=[editing_account, edit_account, *all_form_fields],
            )

            # --- Status and Save ---
            status_message = gr.Markdown("")
            save_btn = gr.Button("Save Email Settings", variant="primary")

            def _make_result(msg, form_values):
                account_md, account_choices, btn_visible = update_account_list()
                accounts = get_current_accounts()
                return (
                    msg,
                    account_md,
                    account_choices,
                    btn_visible,
                    gr.update(choices=accounts),
                    *form_values,
                )

            def _resolve_passwords(editing, password, imap_password, smtp_password, settings):
                """Resolve effective passwords, keeping existing ones if placeholder."""
                effective_password = password
                effective_imap_password = imap_password if imap_password else None
                effective_smtp_password = smtp_password if smtp_password else None

                if editing and password == PASSWORD_PLACEHOLDER:
                    for email_cfg in settings.emails:
                        if email_cfg.account_name == editing:
                            effective_password = email_cfg.incoming.password
                            break

                return effective_password, effective_imap_password, effective_smtp_password

            def save_email_settings(
                editing,
                account_name,
                full_name,
                email_address,
                user_name,
                password,
                imap_host,
                imap_port,
                imap_security,
                imap_verify_ssl,
                imap_user_name,
                imap_password,
                smtp_host,
                smtp_port,
                smtp_security,
                smtp_verify_ssl,
                smtp_user_name,
                smtp_password,
                same_security_checked,
            ):
                form_vals = (
                    account_name,
                    full_name,
                    email_address,
                    user_name,
                    password,
                    imap_host,
                    imap_port,
                    imap_security,
                    imap_verify_ssl,
                    imap_user_name,
                    imap_password,
                    smtp_host,
                    smtp_port,
                    smtp_security,
                    smtp_verify_ssl,
                    smtp_user_name,
                    smtp_password,
                    same_security_checked,
                )
                try:
                    if not account_name or not full_name or not email_address or not user_name:
                        return _make_result("Error: Please fill in all required fields.", form_vals)

                    is_editing = editing is not None
                    if not is_editing and not password:
                        return _make_result("Error: Password is required.", form_vals)

                    if not imap_host or not smtp_host:
                        return _make_result("Error: IMAP and SMTP hosts are required.", form_vals)

                    settings = get_settings()

                    if not is_editing:
                        for email_cfg in settings.emails:
                            if email_cfg.account_name == account_name:
                                return _make_result(f"Error: Account name '{account_name}' already exists.", form_vals)

                    effective_password, effective_imap_password, effective_smtp_password = _resolve_passwords(
                        editing, password, imap_password, smtp_password, settings
                    )

                    effective_smtp_security = imap_security if same_security_checked else smtp_security
                    effective_smtp_verify_ssl = imap_verify_ssl if same_security_checked else smtp_verify_ssl

                    email_settings = EmailSettings.init(
                        account_name=account_name,
                        full_name=full_name,
                        email_address=email_address,
                        user_name=user_name,
                        password=effective_password,
                        imap_host=imap_host,
                        smtp_host=smtp_host,
                        imap_port=int(imap_port),
                        imap_security=ConnectionSecurity(imap_security),
                        imap_verify_ssl=imap_verify_ssl,
                        smtp_port=int(smtp_port),
                        smtp_security=ConnectionSecurity(effective_smtp_security),
                        smtp_verify_ssl=effective_smtp_verify_ssl,
                        imap_user_name=imap_user_name if imap_user_name else None,
                        imap_password=effective_imap_password,
                        smtp_user_name=smtp_user_name if smtp_user_name else None,
                        smtp_password=effective_smtp_password,
                    )

                    if is_editing:
                        settings.update_email(email_settings)
                        action = "updated"
                    else:
                        settings.add_email(email_settings)
                        action = "added"

                    store_settings(settings)

                    return _make_result(
                        f"Success: Email account '{account_name}' has been {action}.",
                        _get_form_defaults(),
                    )
                except Exception as e:
                    return _make_result(f"Error: {e!s}", form_vals)

            save_btn.click(
                fn=save_email_settings,
                inputs=[editing_account, *all_form_fields],
                outputs=[
                    status_message,
                    accounts_display,
                    account_to_delete,
                    delete_btn,
                    edit_account,
                    *all_form_fields,
                ],
            )

            # Initialize edit dropdown with current accounts
            def init_edit_dropdown():
                accounts = get_current_accounts()
                return gr.update(choices=accounts)

            app.load(fn=init_edit_dropdown, inputs=None, outputs=[edit_account])

        # Claude Desktop Integration
        with gr.Accordion("Claude Desktop Integration", open=True):
            gr.Markdown("### Claude Desktop Integration")

            # Status display for Claude Desktop integration
            claude_status = gr.Markdown("")

            # Function to check and update Claude Desktop status
            def update_claude_status():
                if is_installed():
                    if need_update():
                        return "Claude Desktop integration is installed but needs to be updated."
                    else:
                        return "Claude Desktop integration is installed and up to date."
                else:
                    return "Claude Desktop integration is not installed."

            # Buttons for Claude Desktop actions
            with gr.Row():
                install_update_btn = gr.Button("Install to Claude Desktop")
                uninstall_btn = gr.Button("Uninstall from Claude Desktop")

            # Functions for Claude Desktop actions
            def install_or_update_claude():
                try:
                    install_claude_desktop()
                    status = update_claude_status()
                    # Update button states based on new status
                    is_inst = is_installed()
                    needs_upd = need_update()

                    button_text = "Update Claude Desktop" if (is_inst and needs_upd) else "Install to Claude Desktop"
                    button_interactive = not (is_inst and not needs_upd)

                    return [
                        status,
                        gr.update(value=button_text, interactive=button_interactive),
                        gr.update(interactive=is_inst),
                    ]
                except Exception as e:
                    return [f"Error installing/updating Claude Desktop: {e!s}", gr.update(), gr.update()]

            def uninstall_from_claude():
                try:
                    uninstall_claude_desktop()
                    status = update_claude_status()
                    # Update button states based on new status
                    is_inst = is_installed()
                    needs_upd = need_update()

                    button_text = "Update Claude Desktop" if (is_inst and needs_upd) else "Install to Claude Desktop"
                    button_interactive = not (is_inst and not needs_upd)

                    return [
                        status,
                        gr.update(value=button_text, interactive=button_interactive),
                        gr.update(interactive=is_inst),
                    ]
                except Exception as e:
                    return [f"Error uninstalling from Claude Desktop: {e!s}", gr.update(), gr.update()]

            # Function to update button states based on installation status
            def update_button_states():
                status = update_claude_status()
                is_inst = is_installed()
                needs_upd = need_update()

                button_text = "Update Claude Desktop" if (is_inst and needs_upd) else "Install to Claude Desktop"
                button_interactive = not (is_inst and not needs_upd)

                return [
                    status,
                    gr.update(value=button_text, interactive=button_interactive),
                    gr.update(interactive=is_inst),
                ]

            # Connect buttons to functions
            install_update_btn.click(
                fn=install_or_update_claude, inputs=[], outputs=[claude_status, install_update_btn, uninstall_btn]
            )
            uninstall_btn.click(
                fn=uninstall_from_claude, inputs=[], outputs=[claude_status, install_update_btn, uninstall_btn]
            )

            # Initialize Claude Desktop status and button states
            app.load(fn=update_button_states, inputs=None, outputs=[claude_status, install_update_btn, uninstall_btn])

    return app


def main():
    app = create_ui()
    app.launch(inbrowser=True)


if __name__ == "__main__":
    main()
