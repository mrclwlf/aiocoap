import logging
import asyncio
import sys

from aiocoap import *

import time
import argparse


class Timer():
    def __init__(self):
        self._start_time = None

    def start(self):
        if self._start_time is not None:
            raise Exception(f"Timer is running. Use .stop() to stop it")

        self._start_time = time.perf_counter()

    def stop(self):

        """Stop the timer, and report the elapsed time"""

        if self._start_time is None:
            raise Exception(f"Timer is not running. Use .start() to start it")

        elapsed_time = time.perf_counter() - self._start_time

        self._start_time = None
        return elapsed_time


async def main():
    transport = await Context.create_client_context()
    PSK = b'MyKey'
    identity = b'test-client'

    parser = argparse.ArgumentParser(description='Arguments to create a CoAP-Message.')
    parser.add_argument("-p", "--protocol", help="coap, coaps, tcp, quic, coaps+tcp")
    parser.add_argument("-c", "--code", help="get, put, post, delete")
    parser.add_argument("-pl", "--payload", help="insert your payload")
    args = parser.parse_args()

    match args.protocol:
        case "tcp":
            uri = 'coap+tcp://localhost/example'

        case "quic":
            uri = 'coap+quic://localhost:64999/example'

        case "dtls":
            transport.client_credentials.load_from_dict({'coaps://localhost/*': {
                "dtls": {"psk": PSK, "client-identity": identity}}})
            uri = 'coaps://localhost/example'

        case "coaps+tcp":
            from aiocoap.credentials import TLSCert
            transport.client_credentials['coaps+tcp://*'] = TLSCert(certfile="cert.pem")
            uri = 'coaps+tcp://localhost/example'

        case _:
            uri = 'coap://localhost/example'


    match args.code:
        case "put":
            code = PUT
        case "post":
            code = PUT
        case "delete":
            code = DELETE
        case _:
            code = GET

    if args.payload is None:
        payload = b''
    else:
        payload = args.payload.encode()

    t = Timer()
    t.start()
    for i in range(0, 102):
        # if i < 2:
        # continue
        # if i == 2:
        # t.start()
        request = Message(code=code, uri=uri, payload=payload)
        response = await transport.request(request).response
    #print(response.payload)
    print(t.stop())

if __name__ == "__main__":
    asyncio.run(main())
    #loop = asyncio.get_event_loop()
    #loop.run_until_complete(main())
