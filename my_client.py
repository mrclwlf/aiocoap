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
    psk = b'MyKey'
    identity = b'test-client'

    parser = argparse.ArgumentParser(description='Arguments to create a CoAP-Message.')
    parser.add_argument("-p", "--protocol", help="coap, coaps, tcp, quic, coaps+tcp, oscore")
    parser.add_argument("-c", "--code", help="get, put, post, delete")
    parser.add_argument("-pl", "--payload", help="insert your payload")
    parser.add_argument("-r", "--resource", help="insert target resource")
    args = parser.parse_args()

    rsc = args.resource if args.resource else "example"

    match args.protocol:
        case "tcp":
            uri = f'coap+tcp://localhost/{rsc}'
            #print("TCP")

        case "quic":
            uri = f'coap+quic://localhost:64999/{rsc}'
            #print("QUIC")


        case "coap+dtls":
            transport.client_credentials.load_from_dict({'coaps://localhost/*': {
                "dtls": {"psk": psk, "client-identity": identity}}})
            uri = f'coaps://localhost/{rsc}'
            #print("DTLS")


        case "coaps+tcp":
            from aiocoap.credentials import TLSCert
            transport.client_credentials['coaps+tcp://*'] = TLSCert(certfile="cert.pem")
            uri = f'coaps+tcp://localhost/example'
            #print("TLS+TCP")


        case "oscore":
            import json
            transport.client_credentials.load_from_dict(json.load(open("client.json", "rb")))
            uri = f'coap://localhost/{rsc}'

        case _:
            uri = f'coap://localhost/{rsc}'
            #print("CoAP")



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
    request = Message(code=code, uri=uri, payload=payload)
    response = await transport.request(request).response
    #print(response.payload)
    end_time = t.stop()
    print(end_time)

if __name__ == "__main__":
    asyncio.run(main())
