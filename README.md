# dnsmonitor

Check Tor Exits for DNS resolution errors.

The script builds Tor circuits to each exit, using one of the others as the
guard. It tries to send an HTTP GET request to `example.com`, falling back to
the IP address and reporting a DNS resolution error if this succeeds.

## Configuration

The script requires a Tor controller and SOCKS port on `localhost`.

Supported environment variables:

| Variable | Description |
| --- | --- |
| `CONTROLLER_PORT` | Controller port. (Default: 9051) |
| `CONTROLLER_PASSWORD` | Controller password (Default: None) |
| `SOCKS_PORT` | SOCKS Port (Default: 9050) |

Exit fingerprints and nicknames are provided in a JSON file:

```json
{
    "FINGERPRINT1": "mycoolexit01",
    "FINGERPRINT2": "mycoolexit02",
    "FINGERPRINT3": "mycoolexit03"
}
```

## Usage

Install the dependencies into a Python virtual environment via `Pipfile` or
`requirements.txt`, then run `./dnsmonitor.py --help` for usage information.

dnsmonitor generates no output if no errors are found, so you can run it in a
cronjob and receive emails only if errors appear. The script also returns an
exit status of `1` in this case.
