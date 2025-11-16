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
CONFIG_FILE_NAME = "config.json"

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


def persist_session(session: str):
    """
    Helper method to persist the Wealthsimple session to the system keyring.
    """
    keyring.set_password(keyring_service_name, "session", session)


def get_session() -> WSAPISession:
    """
    Get the JSON session data from the keyring.

    :return: The persisted session data
    """
    if session_data := keyring.get_password(keyring_service_name, "session"):
        return WSAPISession.from_json(session_data)
    else:
        err_console.print(f"Please run [cyan]{APP_NAME} login[/cyan] first.")
        raise typer.Exit(1)


def save_config(config: Config) -> None:
    """
    Save the configuration to a file in the user's home.
    """
    # Get or create config directory
    app_dir = typer.get_app_dir(APP_NAME)
    config_directory = Path(app_dir)

    config_directory.mkdir(parents=True, exist_ok=True)

    # Save config file
    config_path = Path(app_dir) / CONFIG_FILE_NAME
    with open(config_path, "w") as file:
        json.dump(asdict(config), file)

    console.print(f"Saved config to {config_path}", style="green")


def load_config(print_error: bool = True) -> Config:
    """
    Load the configuration from the filesystem.
    """
    # Get the config directory
    app_dir = typer.get_app_dir(APP_NAME)
    config_directory = Path(app_dir)
    config_path = Path(app_dir) / CONFIG_FILE_NAME

    # Check if it exists
    if not config_directory.is_dir() or not config_path.is_file():
        if print_error:
            err_console.print(f"Please run [cyan]{APP_NAME} configure[/cyan] first.")
        raise typer.Exit(1)

    # Load from filesystem
    with open(config_path, "r") as file:
        config_dict = cast(dict[str, str | dict[str, int]], json.loads(file.read()))

    return Config(**config_dict)  # pyright:ignore[reportArgumentType]


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
    try:
        WealthsimpleAPI.login(
            email,
            password,
            otp_answer,
            persist_session_fct=persist_session,
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
):
    """
    Link each Wealthsimple account with a corresponding Lunch Money asset.
    """
    # Get access token
    if not access_token:
        try:
            config = load_config(print_error=False)
            access_token = config.access_token
        except typer.Exit:
            access_token = cast(str, typer.prompt("Access token", type=str))

    # Get session
    session = get_session()
    ws = WealthsimpleAPI.from_token(session, persist_session)

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

    console.print(
        "Link accounts by choosing the corresponding number and letter (e.g. '1 B' would link Account '1' to Asset 'B')."
    )

    # Associate Wealth Simple accounts with Lunch Money assets
    account_map = {}
    while True:
        choice: str = cast(
            str,
            typer.prompt("Please provide a number and a letter (type DONE to finish)"),
        )
        match choice.split(" "):
            case [account_number, asset_letter]:
                wealthsimple_account = wealthsimple_accounts[
                    int(account_number) - 1
                ]  # -1
                lunch_money_asset = lunch_money_assets[
                    string.ascii_uppercase.index(asset_letter)
                ]
                account_map[wealthsimple_account["id"]] = lunch_money_asset.id

                console.print(
                    f"Linked {wealthsimple_account['description']} to {_get_asset_display_name(lunch_money_asset)}",
                    style="green",
                )
            case ["DONE"] | ["done"]:
                break
            case _:
                console.print(
                    "[red]Please enter a number followed by a space and a letter.[/red]"
                )

    # Save the config
    config = Config(access_token=access_token, account_map=account_map)
    save_config(config)


@app.command()
def view() -> None:
    """
    View your current configurations and login status.
    """
    # Check login status
    session_exists = False
    try:
        get_session()
        session_exists = True
    except typer.Exit:
        pass

    # Check config status
    config_exists = False
    config = None
    try:
        config = load_config(print_error=False)
        config_exists = True
    except typer.Exit:
        pass

    # Display login status
    console.print("\n[bold]Login Status[/bold]")
    login_table = Table("Status", "Details")
    if session_exists:
        login_table.add_row(
            "[green]✓ Logged in[/green]",
            "Wealthsimple session found in system keyring"
        )
    else:
        login_table.add_row(
            "[red]✗ Not logged in[/red]",
            "Run [cyan]lunchsimple login[/cyan] to authenticate"
        )
    console.print(login_table)

    # Display config status
    console.print("\n[bold]Configuration Status[/bold]")
    config_table = Table("Setting", "Status", "Details")
    if config_exists and config:
        # Show access token status (masked)
        token_display = (
            f"{config.access_token[:8]}...{config.access_token[-4:]}"
            if len(config.access_token) > 12
            else "***"
        )
        config_table.add_row(
            "Lunch Money Access Token",
            "[green]✓ Configured[/green]",
            token_display
        )

        # Show account mappings
        num_mappings = len(config.account_map)
        if num_mappings > 0:
            config_table.add_row(
                "Account Mappings",
                "[green]✓ Configured[/green]",
                f"{num_mappings} account(s) mapped"
            )
        else:
            config_table.add_row(
                "Account Mappings",
                "[yellow]⚠ Not configured[/yellow]",
                "No accounts mapped"
            )
    else:
        config_table.add_row(
            "Configuration",
            "[red]✗ Not configured[/red]",
            "Run [cyan]lunchsimple configure[/cyan] to set up"
        )
    console.print(config_table)

    # If both session and config exist, show detailed account mappings
    if session_exists and config_exists and config and len(config.account_map) > 0:
        try:
            session = get_session()
            ws = WealthsimpleAPI.from_token(session, persist_session)
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

            # Display detailed mappings
            console.print("\n[bold]Account Mappings[/bold]")
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
                f"\n[yellow]Warning: Could not fetch detailed account information: {e}[/yellow]"
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
):
    """
    Pull transactions from your Wealthsimple account and add them to Lunch Money.
    """
    session = get_session()
    ws = WealthsimpleAPI.from_token(session, persist_session)
    config = load_config()
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

                amount = (
                    f"{'' if wealthsimple_activity['amountSign'] == 'positive' else '-'}"
                    + wealthsimple_activity["amount"]
                )
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


if __name__ == "__main__":
    app()
