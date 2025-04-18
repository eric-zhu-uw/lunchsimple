# Lunchsimple

Lunchsimple syncs your Wealthsimple activity with your Lunch Money budget.

Note: this project uses unofficial Wealthsimple APIs, which may be revoked at any time.

## Getting Started

### Prerequisites

To install Lunchsimple, you'll need:

- at least Python 3.12
- `pipx` (recommended)
- a functioning and accessible system keyring
  - should be true for most people, [read more](https://pypi.org/project/keyring/) about keyring access if you have issues

### Installing

You can install Lunchsimple from your terminal using `pipx` with:

```commandline
pipx install lunchsimple
```

Alternatively, without `pipx` you can try to use plain 'ol `pip`:

```commandline
pip install lunchsimple
```

However, doing so may require you to run as `sudo` which isn't recommended.

### Logging In

You'll need to first log in with your Wealthsimple credentials:

```commandline
lunchsimple login
```

Your login information is then stored locally on your system's keyring.

### Configuring

You must tell Lunchsimple which Wealthsimple accounts belong to which Lunch Money assets.

First, go to the [Accounts page](https://my.lunchmoney.app/accounts) in Lunch Money and create a new account for each Wealthsimple account you want to sync with.

Then, go to the [Developers page](https://my.lunchmoney.app/developers) in Lunch Money and generate an Access Token by clicking **Request New Access Token**.

Once you have the token, run the following:

```commandline
lunchsimple configure --access-token "your-access-token"
```

You can re-run `lunchsimple configure` anytime to re-configure (or switch budgets if using a test budget).

### Syncing

After logging in and configuring, you can finally push Wealthsimple activity into Lunch Money with:

```commandline
lunchsimple sync
```

By default, syncing starts from the beginning of the current month.

You can also pass a date to start syncing from:

```commandline
lunchsimple sync --start-date "2024-12-15"
```

## Contributing

Know Python? Want to improve Lunchsimple? Submit patches and let's chat.

## Credits

This project wouldn't be here without these awesome packages:

- WS-API <https://github.com/gboudreau/ws-api-python>
- Lunchable <https://github.com/juftin/lunchable>
- Typer <https://github.com/fastapi/typer>
