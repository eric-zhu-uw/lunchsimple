import re
import json
import string
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, cast

import keyring
from lunchable import LunchMoney, TransactionInsertObject
from lunchable.exceptions import LunchMoneyHTTPError
import typer
from lunchable.models import AssetsObject
from rich.console import Console
from rich.progress import track
from rich.table import Table

from ws_api import (
    WealthsimpleAPI,
    OTPRequiredException,
    LoginFailedException,
    WSAPISession,
)

APP_NAME = "lunchsimple"

app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)

console = Console()
err_console = Console(stderr=True)

keyring_service_name = APP_NAME


def _get_asset_display_name(lunch_money_asset: AssetsObject):
    """
    Helper method to get the display name of an asset.
    """
    if display_name := lunch_money_asset.display_name:
        display_name = display_name
    else:
        if institution := lunch_money_asset.institution_name:
            display_name = institution + " " + lunch_money_asset.name
        else:
            display_name = lunch_money_asset.name

    return display_name


@dataclass
class Config:
    """
    The primary storage object for this utility.
    """

    access_token: str
    """The API token from Lunch Money"""

    account_map: dict[str, int]
    """A simple dict providing the links between accounts and assets"""


def _get_all_session_emails() -> list[str]:
    """
    Get a list of all emails that have stored sessions.
    
    :return: List of email addresses with stored sessions
    """
    emails_json = keyring.get_password(keyring_service_name, "session_emails")
    if emails_json:
        return json.loads(emails_json)
    return []


def _add_session_email(email: str):
    """
    Add an email to the list of emails with sessions.
    
    :param email: The email address to add
    """
    emails = _get_all_session_emails()
    if email not in emails:
        emails.append(email)
        keyring.set_password(keyring_service_name, "session_emails", json.dumps(emails))


def persist_session(session: str, email: str):
    """
    Helper method to persist the Wealthsimple session to the system keyring.
    
    :param session: The session data to persist
    :param email: The email address associated with this session
    """
    keyring.set_password(keyring_service_name, f"session_{email}", session)
    # Add to list of all session emails
    _add_session_email(email)


def get_session(email: str | None = None) -> WSAPISession:
    """
    Get the JSON session data from the keyring.

    :param email: The email address to retrieve the session for. If None, uses the first available session (for internal use only).
    :return: The persisted session data
    """
    # If no email provided, try to get the first available session
    if email is None:
        emails = _get_all_session_emails()
        if not emails:
            err_console.print(f"Please run [cyan]{APP_NAME} login[/cyan] first.")
            raise typer.Exit(1)
        email = emails[0]
    
    if session_data := keyring.get_password(keyring_service_name, f"session_{email}"):
        return WSAPISession.from_json(session_data)
    else:
        err_console.print(f"Please run [cyan]{APP_NAME} login[/cyan] first.")
        raise typer.Exit(1)


def list_all_sessions() -> dict[str, WSAPISession]:
    """
    Get all stored sessions.
    
    :return: Dictionary mapping email addresses to their sessions
    """
    sessions = {}
    emails = _get_all_session_emails()
    for email in emails:
        if session_data := keyring.get_password(keyring_service_name, f"session_{email}"):
            try:
                sessions[email] = WSAPISession.from_json(session_data)
            except Exception:
                # Skip invalid sessions
                continue
    return sessions


def prompt_session_selection() -> str:
    """
    Display all available sessions and prompt the user to select one.
    
    :return: The selected email address
    """
    all_sessions = list_all_sessions()
    
    if not all_sessions:
        err_console.print("No sessions found. Please run [cyan]lunchsimple login[/cyan] first.")
        raise typer.Exit(1)
    
    # Display sessions table
    console.print("\n[bold]Available Sessions[/bold]")
    sessions_table = Table("", "Email")
    session_emails = list(all_sessions.keys())
    for index, email in enumerate(session_emails):
        sessions_table.add_row(f"[green]{str(index + 1)}[/green]", email)
    console.print(sessions_table)
    
    # Prompt for selection
    while True:
        try:
            choice = typer.prompt(f"\nSelect a session (1-{len(session_emails)})")
            choice_num = int(choice)
            if 1 <= choice_num <= len(session_emails):
                return session_emails[choice_num - 1]
            else:
                err_console.print(f"Please enter a number between 1 and {len(session_emails)}.")
        except ValueError:
            err_console.print("Please enter a valid number.")
        except KeyboardInterrupt:
            raise typer.Exit(1)


def save_config(config: Config, email: str) -> None:
    """
    Save the configuration to a file in the user's home, specific to the email/session.
    
    :param config: The configuration to save
    :param email: The email address associated with this config
    """
    # Get or create config directory
    app_dir = typer.get_app_dir(APP_NAME)
    config_directory = Path(app_dir)

    config_directory.mkdir(parents=True, exist_ok=True)

    # Save config file with email-specific name
    # Sanitize email for filename (replace @ and . with _)
    safe_email = email.replace("@", "_at_").replace(".", "_")
    config_path = Path(app_dir) / f"config_{safe_email}.json"
    with open(config_path, "w") as file:
        json.dump(asdict(config), file)

    console.print(f"Saved config for {email} to {config_path}", style="green")


def load_config(email: str | None = None, print_error: bool = True) -> Config:
    """
    Load the configuration from the filesystem for a specific email/session.
    
    :param email: The email address to load config for. If None, tries to load first available config.
    :param print_error: Whether to print error messages if config not found
    :return: The loaded configuration
    """
    # Get the config directory
    app_dir = typer.get_app_dir(APP_NAME)
    config_directory = Path(app_dir)
    
    # If email is provided, load email-specific config
    if email:
        safe_email = email.replace("@", "_at_").replace(".", "_")
        config_path = Path(app_dir) / f"config_{safe_email}.json"
        
        if config_path.is_file():
            with open(config_path, "r") as file:
                config_dict = cast(dict[str, str | dict[str, int]], json.loads(file.read()))
            return Config(**config_dict)  # pyright:ignore[reportArgumentType]
    
    # If no email provided, try to find any config
    if email is None:
        emails = _get_all_session_emails()
        for session_email in emails:
            safe_email = session_email.replace("@", "_at_").replace(".", "_")
            config_path = Path(app_dir) / f"config_{safe_email}.json"
            if config_path.is_file():
                with open(config_path, "r") as file:
                    config_dict = cast(dict[str, str | dict[str, int]], json.loads(file.read()))
                return Config(**config_dict)  # pyright:ignore[reportArgumentType]
    
    # No config found
    if print_error:
        if email:
            err_console.print(f"Please run [cyan]{APP_NAME} configure --email {email}[/cyan] first.")
        else:
            err_console.print(f"Please run [cyan]{APP_NAME} configure[/cyan] first.")
    raise typer.Exit(1)


def list_all_configs() -> dict[str, Config]:
    """
    Get all stored configs.
    
    :return: Dictionary mapping email addresses to their configs
    """
    configs = {}
    app_dir = typer.get_app_dir(APP_NAME)
    config_directory = Path(app_dir)
    
    if not config_directory.is_dir():
        return configs
    
    # Get all emails with sessions
    emails = _get_all_session_emails()
    
    # Try to load config for each email
    for email in emails:
        safe_email = email.replace("@", "_at_").replace(".", "_")
        config_path = config_directory / f"config_{safe_email}.json"
        if config_path.is_file():
            try:
                with open(config_path, "r") as file:
                    config_dict = cast(dict[str, str | dict[str, int]], json.loads(file.read()))
                configs[email] = Config(**config_dict)  # pyright:ignore[reportArgumentType]
            except Exception:
                # Skip invalid configs
                continue
    
    return configs


@app.command()
def login(
    email: Annotated[
        str, typer.Option(prompt="Wealthsimple Email", help="Your Wealthsimple email.")
    ],
    password: Annotated[
        str,
        typer.Option(
            prompt=True,
            hide_input=True,
            help="Your Wealthsimple password.",
        ),
    ],
    otp_answer: Annotated[
        str, typer.Option(prompt="OTP Answer", help="Your Wealthsimple 2FA/OTP answer.")
    ],
) -> None:
    """
    Log in to Wealthsimple.
    """
    # Create a closure that captures the email
    def persist_session_with_email(session: str):
        persist_session(session, email)
    
    try:
        WealthsimpleAPI.login(
            email,
            password,
            otp_answer,
            persist_session_fct=persist_session_with_email,
        )
        console.print("Success! Saved session to system keyring.", style="green")
    except OTPRequiredException:
        err_console.print("Please supply an OTP code.")
        raise typer.Exit(1)
    except LoginFailedException:
        err_console.print("Login failed, please try again.")
        raise typer.Exit(1)


@app.command()
def configure(
    access_token: Annotated[
        str, typer.Option(help="Your Lunch Money developer access token.")
    ] = "",
    email: Annotated[
        str | None,
        typer.Option(help="Email address to use for the session. If not provided, you will be prompted to select from available sessions."),
    ] = None,
):
    """
    Link each Wealthsimple account with a corresponding Lunch Money asset.
    """
    # If no email provided, prompt user to select a session
    if email is None:
        email = prompt_session_selection()
    
    # Try to load existing config
    existing_config = None
    try:
        existing_config = load_config(email=email, print_error=False)
    except typer.Exit:
        pass
    
    # Get access token - use existing if available, otherwise prompt
    if not access_token:
        if existing_config:
            access_token = existing_config.access_token
        else:
            # Try any available config as fallback
            try:
                fallback_config = load_config(print_error=False)
                access_token = fallback_config.access_token
            except typer.Exit:
                access_token = cast(str, typer.prompt("Access token", type=str))
    
    # Get session
    session = get_session(email)
    # Create a closure that captures the email
    def persist_session_with_email(session: str):
        persist_session(session, email)
    ws = WealthsimpleAPI.from_token(session, persist_session_with_email)

    # Render Wealthsimple Accounts table
    table = Table("", "Wealthsimple Account")
    wealthsimple_accounts = ws.get_accounts()
    for index, wealthsimple_account in enumerate(wealthsimple_accounts):
        wealthsimple_account_name = wealthsimple_account["description"]

        table.add_row(f"[green]{str(index + 1)}[/green]", wealthsimple_account_name)

    console.print(table)

    # Get assets
    lunch = LunchMoney(access_token=access_token)
    lunch_money_assets = lunch.get_assets()

    # Render Lunch Money assets table
    table = Table("", "Lunch Money Asset")
    for index, lunch_money_asset in enumerate(lunch_money_assets):
        table.add_row(
            f"[green]{string.ascii_uppercase[index]}[/green]",
            _get_asset_display_name(lunch_money_asset),
        )

    console.print(table)

    # Create maps for account and asset lookups
    ws_account_map = {
        account["id"]: account["description"]
        for account in wealthsimple_accounts
    }
    lm_asset_map = {
        asset.id: _get_asset_display_name(asset)
        for asset in lunch_money_assets
    }

    # Start with existing account_map if available, otherwise empty dict
    account_map = existing_config.account_map.copy() if existing_config else {}
    
    # Show current mappings if any exist
    if account_map:
        console.print("\n[bold]Current Account Mappings:[/bold]")
        current_table = Table("Wealthsimple Account", "Lunch Money Asset")
        for ws_account_id, lm_asset_id in account_map.items():
            ws_account_name = ws_account_map.get(
                ws_account_id, f"Account ID: {ws_account_id}"
            )
            lm_asset_name = lm_asset_map.get(
                lm_asset_id, f"Asset ID: {lm_asset_id}"
            )
            current_table.add_row(ws_account_name, lm_asset_name)
        console.print(current_table)
        console.print(
            "\n[yellow]You can add new mappings or remove existing ones. Type 'REMOVE <number>' to remove a mapping, or 'CLEAR' to start fresh.[/yellow]"
        )

    console.print(
        "\nLink accounts by choosing the corresponding number and letter (e.g. '1 B' would link Account '1' to Asset 'B')."
    )

    # Associate Wealth Simple accounts with Lunch Money assets
    while True:
        choice: str = cast(
            str,
            typer.prompt("Please provide a number and a letter (type DONE to finish)"),
        )
        choice_upper = choice.upper()
        match choice_upper.split(" "):
            case ["CLEAR"]:
                if typer.confirm("Are you sure you want to clear all existing mappings?"):
                    account_map = {}
                    console.print("[yellow]All mappings cleared. Starting fresh.[/yellow]")
                else:
                    console.print("[green]Cancelled. Keeping existing mappings.[/green]")
            case ["REMOVE", account_number]:
                try:
                    account_idx = int(account_number) - 1
                    if 0 <= account_idx < len(wealthsimple_accounts):
                        ws_account = wealthsimple_accounts[account_idx]
                        ws_account_id = ws_account["id"]
                        if ws_account_id in account_map:
                            removed_asset_id = account_map.pop(ws_account_id)
                            removed_asset_name = lm_asset_map.get(
                                removed_asset_id, f"Asset ID: {removed_asset_id}"
                            )
                            console.print(
                                f"[yellow]Removed mapping: {ws_account['description']} -> {removed_asset_name}[/yellow]"
                            )
                        else:
                            console.print(
                                f"[red]No mapping found for account {ws_account['description']}[/red]"
                            )
                    else:
                        console.print(
                            f"[red]Invalid account number. Please enter a number between 1 and {len(wealthsimple_accounts)}.[/red]"
                        )
                except ValueError:
                    console.print("[red]Please enter a valid number after REMOVE.[/red]")
            case [account_number, asset_letter]:
                try:
                    wealthsimple_account = wealthsimple_accounts[
                        int(account_number) - 1
                    ]
                    lunch_money_asset = lunch_money_assets[
                        string.ascii_uppercase.index(asset_letter)
                    ]
                    account_map[wealthsimple_account["id"]] = lunch_money_asset.id

                    console.print(
                        f"Linked {wealthsimple_account['description']} to {_get_asset_display_name(lunch_money_asset)}",
                        style="green",
                    )
                except (ValueError, IndexError):
                    console.print(
                        "[red]Invalid account number or asset letter. Please try again.[/red]"
                    )
            case ["DONE"] | ["done"]:
                break
            case _:
                console.print(
                    "[red]Please enter a number followed by a space and a letter, 'REMOVE <number>', 'CLEAR', or 'DONE'.[/red]"
                )

    # Save the config for this email
    config = Config(access_token=access_token, account_map=account_map)
    save_config(config, email)


@app.command()
def view() -> None:
    """
    View your current configurations and login status.
    """
    # Get all sessions
    all_sessions = list_all_sessions()
    
    # Check login status
    session_exists = len(all_sessions) > 0

    # Get all configs
    all_configs = list_all_configs()
    config_exists = len(all_configs) > 0

    # Display login status
    console.print("\n[bold]Login Status[/bold]")
    login_table = Table("Status", "Details")
    if session_exists:
        login_table.add_row(
            "[green]✓ Logged in[/green]",
            f"{len(all_sessions)} session(s) found in system keyring"
        )
    else:
        login_table.add_row(
            "[red]✗ Not logged in[/red]",
            "Run [cyan]lunchsimple login[/cyan] to authenticate"
        )
    console.print(login_table)
    
    # Display all sessions
    if session_exists:
        console.print("\n[bold]Stored Sessions[/bold]")
        sessions_table = Table("Email", "Status")
        for email, session in all_sessions.items():
            status = "[green]Available[/green]"
            sessions_table.add_row(email, status)
        console.print(sessions_table)

    # Display config status
    console.print("\n[bold]Configuration Status[/bold]")
    config_table = Table("Email", "Status", "Access Token", "Account Mappings")
    if config_exists:
        for email, config in all_configs.items():
            # Show access token status (masked)
            token_display = (
                f"{config.access_token[:8]}...{config.access_token[-4:]}"
                if len(config.access_token) > 12
                else "***"
            )
            
            # Show account mappings count
            num_mappings = len(config.account_map)
            mappings_display = (
                f"[green]{num_mappings} mapped[/green]"
                if num_mappings > 0
                else "[yellow]Not configured[/yellow]"
            )
            
            status = "[green]✓ Configured[/green]" if num_mappings > 0 else "[yellow]⚠ Partial[/yellow]"
            config_table.add_row(
                email,
                status,
                token_display,
                mappings_display
            )
    else:
        config_table.add_row(
            "N/A",
            "[red]✗ Not configured[/red]",
            "N/A",
            "Run [cyan]lunchsimple configure[/cyan] to set up"
        )
    console.print(config_table)

    # If both session and config exist, show detailed account mappings for each configured session
    if session_exists and config_exists:
        for email, config in all_configs.items():
            if email not in all_sessions:
                continue
                
            if len(config.account_map) == 0:
                continue
                
            try:
                session = get_session(email)
                # Create a closure that captures the email (use default argument to capture current value)
                def make_persist_function(email: str):
                    def persist_session_with_email(session: str):
                        persist_session(session, email)
                    return persist_session_with_email
                persist_session_with_email = make_persist_function(email)
                ws = WealthsimpleAPI.from_token(session, persist_session_with_email)
                lunch = LunchMoney(access_token=config.access_token)

                # Get account and asset details
                wealthsimple_accounts = ws.get_accounts()
                lunch_money_assets = lunch.get_assets()

                # Create a mapping of IDs to names
                ws_account_map = {
                    account["id"]: account["description"]
                    for account in wealthsimple_accounts
                }
                lm_asset_map = {
                    asset.id: _get_asset_display_name(asset)
                    for asset in lunch_money_assets
                }

                # Display detailed mappings for this email
                console.print(f"\n[bold]Account Mappings for {email}[/bold]")
                mapping_table = Table("Wealthsimple Account", "Lunch Money Asset")
                for ws_account_id, lm_asset_id in config.account_map.items():
                    ws_account_name = ws_account_map.get(
                        ws_account_id, f"Account ID: {ws_account_id}"
                    )
                    lm_asset_name = lm_asset_map.get(
                        lm_asset_id, f"Asset ID: {lm_asset_id}"
                    )
                    mapping_table.add_row(ws_account_name, lm_asset_name)
                console.print(mapping_table)
            except Exception as e:
                console.print(
                    f"\n[yellow]Warning: Could not fetch detailed account information for {email}: {e}[/yellow]"
                )

    console.print()  # Add trailing newline


@app.command()
def sync(
    start_date: Annotated[
        datetime | None,
        typer.Option(
            formats=["%Y-%m-%d"],
            help="The date from which to start syncing from. Warning: dates far into the past may not work properly.",
        ),
    ] = None,
    apply_rules: Annotated[
        bool,
        typer.Option(help="Whether or not to apply transaction rules."),
    ] = True,
    email: Annotated[
        str | None,
        typer.Option(help="Email address to use for the session. If not provided, you will be prompted to select from available sessions."),
    ] = None,
):
    """
    Pull transactions from your Wealthsimple account and add them to Lunch Money.
    """
    # If no email provided, prompt user to select a session
    if email is None:
        email = prompt_session_selection()
    
    session = get_session(email)
    # Create a closure that captures the email
    def persist_session_with_email(session: str):
        persist_session(session, email)
    ws = WealthsimpleAPI.from_token(session, persist_session_with_email)
    config = load_config(email=email)
    lunch = LunchMoney(access_token=config.access_token)

    # Set sync start date
    if not start_date:
        # Fall back to the beginning of this month
        start_date = datetime.now()
        start_date = start_date.replace(day=1)

    # Zero-out time from datetime
    start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)

    # Follow ws-api's determination of end date when fetching activities
    end_date = (
        datetime.now() + timedelta(hours=23, minutes=59, seconds=59, milliseconds=999)
    ).date()

    console.print(f"Starting transaction sync since {start_date.strftime('%Y-%m-%d')}.")

    # Gather transactions to insert
    insert_transactions: list[TransactionInsertObject] = []
    wealthsimple_accounts = ws.get_accounts()
    for wealthsimple_account in track(
        wealthsimple_accounts, description="[red]Syncing..."
    ):
        wealthsimple_account_id = wealthsimple_account["id"]

        if lunch_money_asset_id := config.account_map.get(wealthsimple_account_id):
            # Get IDs of all existing transactions in Lunch Money for this asset
            transactions = lunch.get_transactions(
                asset_id=lunch_money_asset_id,
                start_date=start_date,
                end_date=end_date,
            )
            existing_transactions = {
                (transaction.external_id, lunch_money_asset_id)
                for transaction in transactions
            }

            wealthsimple_activities = ws.get_activities(
                wealthsimple_account_id, how_many=500
            )

            for wealthsimple_activity in wealthsimple_activities:
                # Take the first 75 characters as per Lunch Money's API restriction
                external_id = wealthsimple_activity["canonicalId"][:75]

                date = datetime.fromisoformat(
                    wealthsimple_activity["occurredAt"]
                ).replace(tzinfo=None)

                # Exit early if the activity is before our start date
                # TODO: Find a way to query the start date with ws-api
                if date < start_date:
                    continue

                # Handle purchases
                if name := wealthsimple_activity["spendMerchant"]:
                    payee = name
                    notes = ""
                # Handle deposits and withdrawals
                elif (
                    wealthsimple_activity["type"] in ["DEPOSIT", "WITHDRAWAL"]
                    and wealthsimple_activity["subType"] == "AFT"
                    and (name := wealthsimple_activity["aftOriginatorName"])
                ):
                    payee = name
                    notes = ""
                # Handle e-transfers
                elif wealthsimple_activity["subType"] == "E_TRANSFER":
                    payee = (
                        wealthsimple_activity["eTransferName"]
                        or wealthsimple_activity["eTransferEmail"]
                    )
                    notes = "Interac e-Transfer"
                # Handle whatever else
                else:
                    payee = "Wealthsimple"
                    notes = wealthsimple_activity["description"]
                
                amount = "0"
                if wealthsimple_activity["amount"] is not None:
                    amount = (
                        f"{'' if wealthsimple_activity['amountSign'] == 'positive' else '-'}"
                        + wealthsimple_activity["amount"]
                    )
                # Added this stupid check since it's not clear if WS changed their API st
                # the amount is now signed or unsigned. Scared to just remove the check for backwards
                # compatibility reasons so it's safer to just check for "--" and then remove one of the "-"
                if amount[:2] == "--":
                    amount = amount[1:]

                date = datetime.fromisoformat(
                    wealthsimple_activity["occurredAt"]
                ).date()

                # Only attempt to insert the transaction if it doesn't yet exist
                if (external_id, lunch_money_asset_id) not in existing_transactions:
                    transaction = TransactionInsertObject(
                        external_id=external_id,
                        notes=notes,
                        amount=amount,
                        date=date,
                        payee=payee,
                        asset_id=lunch_money_asset_id,
                        category_id=None,
                        currency=None,
                        status=None,
                        recurring_id=None,
                        tags=None,
                    )
                    insert_transactions.append(transaction)

    _insert_transactions(insert_transactions, lunch, apply_rules)


def _insert_transactions(
    transactions: list[TransactionInsertObject],
    lunch: LunchMoney,
    apply_rules: bool,
):
    """
    Bulk-insert transactions, removing any existing transactions.
    """
    # Insert transactions in bulk
    if len(transactions):
        try:
            ids = lunch.insert_transactions(
                transactions=transactions,
                debit_as_negative=True,
                apply_rules=apply_rules,
            )
            console.print(f"[green]Imported {len(ids)} transaction(s)![/green]")
        except LunchMoneyHTTPError as e:
            # Handle any existing transactions that slipped through the cracks
            if "already exists" in str(e):
                # Extract external_id from server response
                pattern = r"Key\s*\([^)]+\)\s*=\s*\(([^,]+),[^)]+\)"
                match = re.search(pattern, str(e))
                if match:
                    external_id = match.group(1)

                    # Find the problematic transaction
                    skip_index = -1
                    for index, transaction in enumerate(transactions):
                        if transaction.external_id == external_id:
                            skip_index = index

                    if skip_index >= 0:
                        # Remove transaction from list
                        _ = transactions.pop(skip_index)

                        # Re-attempt to insert transactions
                        # TODO: Cache these "bad" transactions somewhere to save on future network requests
                        _insert_transactions(transactions, lunch, apply_rules)
                    else:
                        err_console.print(
                            "[red] Unable to skip existing transactions. Bailing..."
                        )
                        raise e
                else:
                    err_console.print("[red] Unable to detect external_id. Bailing...")
                    raise e
            else:
                raise e
    else:
        console.print("No new transactions to import.")


@app.command()
def balance(
    email: Annotated[
        str | None,
        typer.Option(help="Email address to use for the session. If not provided, you will be prompted to select from available sessions."),
    ] = None,
) -> None:
    """
    Compare balances between Wealthsimple accounts and Lunch Money assets for a given session.
    """
    # If no email provided, prompt user to select a session
    if email is None:
        email = prompt_session_selection()
    
    session = get_session(email)
    # Create a closure that captures the email
    def persist_session_with_email(session: str):
        persist_session(session, email)
    ws = WealthsimpleAPI.from_token(session, persist_session_with_email)
    config = load_config(email=email)
    lunch = LunchMoney(access_token=config.access_token)

    console.print(f"\n[bold]Comparing balances for session: {email}[/bold]\n")

    # Get Wealthsimple accounts
    wealthsimple_accounts = ws.get_accounts()
    
    # Get Lunch Money assets
    lunch_money_assets = lunch.get_assets()
    
    # Create a map of asset ID to asset object for quick lookup
    lm_asset_map = {asset.id: asset for asset in lunch_money_assets}
    
    # Create a map of account ID to account name
    ws_account_map = {
        account["id"]: account["description"]
        for account in wealthsimple_accounts
    }
    
    # Build comparison table
    balance_table = Table(
        "Wealthsimple Account",
        "WS Balance",
        "Lunch Money Asset",
        "LM Balance",
        "Match"
    )
    
    all_match = True
    
    # Compare balances for each mapped account
    for ws_account_id, lm_asset_id in config.account_map.items():
        ws_account_name = ws_account_map.get(
            ws_account_id, f"Account ID: {ws_account_id}"
        )
        lm_asset = lm_asset_map.get(lm_asset_id)
        
        if not lm_asset:
            balance_table.add_row(
                ws_account_name,
                "[red]N/A[/red]",
                f"Asset ID: {lm_asset_id}",
                "[red]Not found[/red]",
                "[red]✗[/red]"
            )
            all_match = False
            continue
        
        lm_asset_name = _get_asset_display_name(lm_asset)
        
        # Get Wealthsimple account balance
        ws_balance = None
        ws_currency = None
        try:
            # Try to get balance from account financials
            account = next(
                (acc for acc in wealthsimple_accounts if acc["id"] == ws_account_id),
                None
            )
            if account:
                # Try different possible paths to get the balance
                financials = account.get("financials", {})
                if financials:
                    # Try currentCombined path
                    current_combined = financials.get("currentCombined", {})
                    if current_combined:
                        net_liquidation = current_combined.get("netLiquidationValue", {})
                        if net_liquidation:
                            # Try amount field (could be string or number)
                            amount = net_liquidation.get("amount")
                            if amount is not None:
                                ws_balance = float(amount)
                            # Also try cents field and convert
                            elif "cents" in net_liquidation:
                                ws_balance = float(net_liquidation["cents"]) / 100.0
                            ws_currency = net_liquidation.get("currency", "")
                    
                    # If that didn't work, try direct balance access
                    if ws_balance is None:
                        net_liquidation = financials.get("netLiquidationValue", {})
                        if net_liquidation:
                            amount = net_liquidation.get("amount")
                            if amount is not None:
                                ws_balance = float(amount)
                            elif "cents" in net_liquidation:
                                ws_balance = float(net_liquidation["cents"]) / 100.0
                            ws_currency = net_liquidation.get("currency", "")
        except (KeyError, ValueError, TypeError) as e:
            console.print(f"[yellow]Warning: Could not get balance for {ws_account_name}: {e}[/yellow]")
        
        # Get Lunch Money asset balance
        lm_balance = None
        lm_currency = None
        try:
            # AssetsObject should have balance field
            if hasattr(lm_asset, "balance") and lm_asset.balance is not None:
                lm_balance = float(lm_asset.balance)
            elif hasattr(lm_asset, "balance_as_of") and lm_asset.balance_as_of is not None:
                lm_balance = float(lm_asset.balance_as_of)
            # Check for currency
            if hasattr(lm_asset, "currency") and lm_asset.currency:
                lm_currency = lm_asset.currency
        except (ValueError, TypeError, AttributeError) as e:
            console.print(f"[yellow]Warning: Could not get balance for {lm_asset_name}: {e}[/yellow]")
        
        # Format balances for display
        if ws_balance is not None:
            ws_balance_str = f"{ws_balance:,.2f}"
            if ws_currency:
                ws_balance_str += f" {ws_currency}"
        else:
            ws_balance_str = "[red]N/A[/red]"
        
        if lm_balance is not None:
            lm_balance_str = f"{lm_balance:,.2f}"
            if lm_currency:
                lm_balance_str += f" {lm_currency}"
        else:
            lm_balance_str = "[red]N/A[/red]"
        
        # Compare balances
        if ws_balance is not None and lm_balance is not None:
            # Allow for small floating point differences (0.01)
            if abs(ws_balance - lm_balance) < 0.01:
                match_str = "[green]✓[/green]"
            else:
                match_str = "[red]✗[/red]"
                all_match = False
                diff = abs(ws_balance - lm_balance)
                console.print(
                    f"[yellow]Mismatch: {ws_account_name} differs by {diff:,.2f}[/yellow]"
                )
        else:
            match_str = "[yellow]?[/yellow]"
            all_match = False
        
        balance_table.add_row(
            ws_account_name,
            ws_balance_str,
            lm_asset_name,
            lm_balance_str,
            match_str
        )
    
    console.print(balance_table)
    
    # Summary
    if all_match:
        console.print("\n[green]✓ All balances match![/green]")
    else:
        console.print("\n[yellow]⚠ Some balances do not match or could not be retrieved.[/yellow]")
    
    console.print()  # Add trailing newline


if __name__ == "__main__":
    app()
