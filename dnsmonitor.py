#!/usr/bin/env python3

from enum import Enum
import json
import os
import time

import click
from stem.control import Controller, EventType
from urllib3.contrib.socks import SOCKSProxyManager


CONTROLLER_PORT = os.environ.get('CONTROLLER_PORT', '9051')
CONTROLLER_PASSWORD = os.environ.get('CONTROLLER_PASSWORD')

SOCKS_PORT = os.environ.get('CONTROLLER_PORT', '9050')
SOCKS_URL = f'socks5h://localhost:{SOCKS_PORT}'

HTTP_RETRIES = 2
HTTP_TIMEOUT = 10


class CircuitCreationError(Exception):
    def __init__(self, path):
        self.path = path


class Result(Enum):
    SUCCESS = 0
    URL1_FAILURE = 1
    URL2_FAILURE = 2


class Circuit():
    """Context manager for Tor circuits."""

    def __init__(self, controller, path, retries=2, timeout=10, backoff=10):
        self.controller = controller
        self.path = path
        self.retries = retries
        self.timeout = timeout
        self.backoff = backoff
        self.listener = None

    def __enter__(self):
        attempts = 1 + self.retries
        while True:
            try:
                circuit_id = self.controller.new_circuit(
                    self.path,
                    await_build=True,
                    timeout=self.timeout)
                break
            except Exception:
                attempts -= 1
            if attempts > 0:
                time.sleep(self.backoff)
            else:
                raise CircuitCreationError(self.path)

        def attach_stream(stream):
            if stream.status == 'NEW':
                self.controller.attach_stream(stream.id, circuit_id)

        self.listener = attach_stream
        self.controller.add_event_listener(self.listener, EventType.STREAM)
        self.controller.set_conf('__LeaveStreamsUnattached', '1')
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if self.listener:
            self.controller.remove_event_listener(self.listener)
        self.controller.reset_conf('__LeaveStreamsUnattached')


@click.command()
@click.argument('exits_json', type=click.Path(exists=True, dir_okay=False))
@click.option('--errors', '-e',
              help='Threshold for reporting circuit creation errors.',
              default=0)
@click.option('--verbose', '-v', help='Show more information.', is_flag=True)
def main(exits_json, errors, verbose):
    """Check Tor Exits for DNS resolution errors.

    EXITS_JSON: JSON file with exit fingerprint/nickname mappings.
    """
    with open(exits_json) as file:
        exits = json.load(file)
    fingerprints = list(exits.keys())

    url1 = 'http://example.com/'
    url2 = 'http://93.184.216.34/'
    headers = {'Host': 'example.com'}
    circuit_errors = []
    error_status = False

    with Controller.from_port(port=int(CONTROLLER_PORT)) as controller:
        controller.authenticate(CONTROLLER_PASSWORD)
        for idx, exit_fp in enumerate(fingerprints):
            guard_fp = fingerprints[(idx + 1) % len(fingerprints)]
            path = [guard_fp, exit_fp]
            nickname = exits[exit_fp]
            try:
                result = check(controller, path, url1, url2, headers)
            except CircuitCreationError as e:
                circuit_errors.append(nickname)
                continue
            except Exception as e:
                click.echo(f'{nickname}: {e}')
                error_status = True
                continue
            if result == Result.URL1_FAILURE:
                click.echo(f'{nickname}: DNS resolution failed.')
                error_status = True
            elif result == Result.URL2_FAILURE:
                click.echo(f'{nickname}: Both requests failed.')
                error_status = True
            elif verbose:
                click.echo(f'{nickname}: OK')

    if circuit_errors and len(circuit_errors) >= errors:
        for nickname in circuit_errors:
            click.echo(f'{nickname}: Circuit creation failed.')
        error_status = True
    if error_status:
        click.get_current_context().exit(1)


def check(controller, path, url1, url2, headers):
    with Circuit(controller, path):
        proxy = SOCKSProxyManager(SOCKS_URL)
        try:
            res = proxy.request(
                'GET',
                url1,
                headers=headers,
                retries=HTTP_RETRIES,
                timeout=HTTP_TIMEOUT)
            if res.status == 200:
                return Result.SUCCESS
        except Exception as e:
            pass
    with Circuit(controller, path):
        proxy = SOCKSProxyManager(SOCKS_URL)
        try:
            res = proxy.request(
                'GET',
                url2,
                headers=headers,
                retries=HTTP_RETRIES,
                timeout=HTTP_TIMEOUT)
            if res.status == 200:
                return Result.URL1_FAILURE
        except Exception as e:
            pass
    return Result.URL2_FAILURE


if __name__ == '__main__':
    main()
