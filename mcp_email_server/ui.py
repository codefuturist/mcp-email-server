import gradio as gr

from mcp_email_server.config import ConnectionSecurity, EmailSettings, get_settings, store_settings
from mcp_email_server.tools.installer import install_claude_desktop, is_installed, need_update, uninstall_claude_desktop


def create_ui():  # noqa: C901
    # Create a Gradio interface
    with gr.Blocks(title="Email Settings Configuration") as app:
        gr.Markdown("# Email Settings Configuration")

        # Function to get current accounts
        def get_current_accounts():
            settings = get_settings(reload=True)
            email_accounts = [email.account_name for email in settings.emails]
            return email_accounts

        # Function to update account list display
        def update_account_list():
            settings = get_settings(reload=True)
            email_accounts = [email.account_name for email in settings.emails]

            if email_accounts:
                # Create a detailed list of accounts with more information
                accounts_details = []
                for email in settings.emails:
                    details = [
                        f"**Account Name:** {email.account_name}",
                        f"**Full Name:** {email.full_name}",
                        f"**Email Address:** {email.email_address}",
                    ]

                    if hasattr(email, "description") and email.description:
                        details.append(f"**Description:** {email.description}")

                    # Add IMAP/SMTP provider info if available
                    if hasattr(email, "incoming") and hasattr(email.incoming, "host"):
                        details.append(f"**IMAP Provider:** {email.incoming.host}")

                    if hasattr(email, "outgoing") and hasattr(email.outgoing, "host"):
                        details.append(f"**SMTP Provider:** {email.outgoing.host}")

                    accounts_details.append("### " + email.account_name + "\n" + "\n".join(details) + "\n")

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

        # Display current email accounts and allow deletion
        with gr.Accordion("Current Email Accounts", open=True):
            # Display the list of accounts
            accounts_display = gr.Markdown("")

            # Create a dropdown to select account to delete
            account_to_delete = gr.Dropdown(choices=[], label="Select Account to Delete", interactive=True)

            # Status message for deletion
            delete_status = gr.Markdown("")

            # Delete button
            delete_btn = gr.Button("Delete Selected Account")

            # Function to delete an account
            def delete_email_account(account_name):
                if not account_name:
                    return "Error: Please select an account to delete.", *update_account_list()

                try:
                    # Get current settings
                    settings = get_settings()

                    # Delete the account
                    settings.delete_email(account_name)

                    # Store settings
                    store_settings(settings)

                    # Return success message and update the UI
                    return f"Success: Email account '{account_name}' has been deleted.", *update_account_list()
                except Exception as e:
                    return f"Error: {e!s}", *update_account_list()

            # Connect the delete button to the delete function
            delete_btn.click(
                fn=delete_email_account,
                inputs=[account_to_delete],
                outputs=[delete_status, accounts_display, account_to_delete, delete_btn],
            )

            # Initialize the account list
            app.load(
                fn=update_account_list,
                inputs=None,
                outputs=[accounts_display, account_to_delete, delete_btn],
            )

        # Form for adding a new email account
        with gr.Accordion("Add New Email Account", open=True):
            gr.Markdown("### Add New Email Account")

            # Basic account information
            account_name = gr.Textbox(label="Account Name", placeholder="e.g. work_email")
            full_name = gr.Textbox(label="Full Name", placeholder="e.g. John Doe")
            email_address = gr.Textbox(label="Email Address", placeholder="e.g. john@example.com")

            # Credentials
            user_name = gr.Textbox(label="Username", placeholder="e.g. john@example.com")
            password = gr.Textbox(label="Password", type="password")

            # IMAP settings
            with gr.Row():
                with gr.Column():
                    gr.Markdown("### IMAP Settings")
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

                    # Auto-update IMAP port when security mode changes
                    def update_imap_port(security):
                        port_map = {"tls": 993, "starttls": 143, "none": 143}
                        return port_map.get(security, 993)

                    imap_security.change(fn=update_imap_port, inputs=[imap_security], outputs=[imap_port])

                # SMTP settings
                with gr.Column():
                    gr.Markdown("### SMTP Settings")
                    smtp_host = gr.Textbox(label="SMTP Host", placeholder="e.g. smtp.example.com")
                    smtp_port = gr.Number(label="SMTP Port", value=465)
                    smtp_security = gr.Dropdown(
                        label="Connection Security",
                        choices=["tls", "starttls", "none"],
                        value="tls",
                        info="TLS (port 465) | STARTTLS (port 587) | None (not recommended)",
                    )
                    smtp_verify_ssl = gr.Checkbox(label="Verify SSL Certificate", value=True)
                    smtp_user_name = gr.Textbox(
                        label="SMTP Username (optional)", placeholder="Leave empty to use the same as above"
                    )
                    smtp_password = gr.Textbox(
                        label="SMTP Password (optional)",
                        type="password",
                        placeholder="Leave empty to use the same as above",
                    )

                    # Auto-update SMTP port when security mode changes
                    def update_smtp_port(security):
                        port_map = {"tls": 465, "starttls": 587, "none": 25}
                        return port_map.get(security, 465)

                    smtp_security.change(fn=update_smtp_port, inputs=[smtp_security], outputs=[smtp_port])

            # Status message
            status_message = gr.Markdown("")

            # Save button
            save_btn = gr.Button("Save Email Settings")

            # Function to save settings
            def save_email_settings(
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
            ):
                try:
                    # Validate required fields
                    if not account_name or not full_name or not email_address or not user_name or not password:
                        # Get account list update
                        account_md, account_choices, btn_visible = update_account_list()
                        return (
                            "Error: Please fill in all required fields.",
                            account_md,
                            account_choices,
                            btn_visible,
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
                        )

                    if not imap_host or not smtp_host:
                        # Get account list update
                        account_md, account_choices, btn_visible = update_account_list()
                        return (
                            "Error: IMAP and SMTP hosts are required.",
                            account_md,
                            account_choices,
                            btn_visible,
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
                        )

                    # Get current settings
                    settings = get_settings()

                    # Check if account name already exists
                    for email in settings.emails:
                        if email.account_name == account_name:
                            # Get account list update
                            account_md, account_choices, btn_visible = update_account_list()
                            return (
                                f"Error: Account name '{account_name}' already exists.",
                                account_md,
                                account_choices,
                                btn_visible,
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
                            )

                    # Create new email settings
                    email_settings = EmailSettings.init(
                        account_name=account_name,
                        full_name=full_name,
                        email_address=email_address,
                        user_name=user_name,
                        password=password,
                        imap_host=imap_host,
                        smtp_host=smtp_host,
                        imap_port=int(imap_port),
                        imap_security=ConnectionSecurity(imap_security),
                        imap_verify_ssl=imap_verify_ssl,
                        smtp_port=int(smtp_port),
                        smtp_security=ConnectionSecurity(smtp_security),
                        smtp_verify_ssl=smtp_verify_ssl,
                        imap_user_name=imap_user_name if imap_user_name else None,
                        imap_password=imap_password if imap_password else None,
                        smtp_user_name=smtp_user_name if smtp_user_name else None,
                        smtp_password=smtp_password if smtp_password else None,
                    )

                    # Add to settings
                    settings.add_email(email_settings)

                    # Store settings
                    store_settings(settings)

                    # Get account list update
                    account_md, account_choices, btn_visible = update_account_list()

                    # Return success message, update the UI, and clear form fields
                    return (
                        f"Success: Email account '{account_name}' has been added.",
                        account_md,
                        account_choices,
                        btn_visible,
                        "",  # Clear account_name
                        "",  # Clear full_name
                        "",  # Clear email_address
                        "",  # Clear user_name
                        "",  # Clear password
                        "",  # Clear imap_host
                        993,  # Reset imap_port
                        "tls",  # Reset imap_security
                        True,  # Reset imap_verify_ssl
                        "",  # Clear imap_user_name
                        "",  # Clear imap_password
                        "",  # Clear smtp_host
                        465,  # Reset smtp_port
                        "tls",  # Reset smtp_security
                        True,  # Reset smtp_verify_ssl
                        "",  # Clear smtp_user_name
                        "",  # Clear smtp_password
                    )
                except Exception as e:
                    # Get account list update
                    account_md, account_choices, btn_visible = update_account_list()
                    return (
                        f"Error: {e!s}",
                        account_md,
                        account_choices,
                        btn_visible,
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
                    )

            # Connect the save button to the save function
            save_btn.click(
                fn=save_email_settings,
                inputs=[
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
                ],
                outputs=[
                    status_message,
                    accounts_display,
                    account_to_delete,
                    delete_btn,
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
                ],
            )

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
