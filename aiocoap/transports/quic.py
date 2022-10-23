import ipaddress
import ssl
import asyncio
import socket
import sys
from typing import Optional

from aiocoap.numbers.codes import CSM, PING, PONG, RELEASE, ABORT
from aiocoap import interfaces, util, error
from aiocoap import COAP_PORT, Message
from aiocoap.transports import tcp
from aiocoap import optiontypes, util

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent, StreamDataReceived, HandshakeCompleted, ConnectionIdIssued, \
    ConnectionTerminated
from aioquic.asyncio.server import QuicServer


def get_transport_infos(transport) -> tuple:
    if transport.get_extra_info('sockname') == COAP_PORT:
        addr_local = transport.get_extra_info('sockname')[:2][0], None
    else:
        addr_local = transport.get_extra_info('sockname')[:2][0], \
                     transport.get_extra_info('sockname')[:2][1]

    try:
        if transport.get_extra_info('peername') == COAP_PORT:
            addr_remote = transport.get_extra_info('peername')[:2][0], None
        else:
            addr_remote = transport.get_extra_info('peername')[:2][0], \
                          transport.get_extra_info('peername')[:2][1]
    except:
        addr_remote = None

    key = addr_local, addr_remote

    return key


class Quic(QuicConnectionProtocol, interfaces.EndpointAddress):
    _my_max_message_size = 1024 * 1024

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data = b""
        self.key = None
        self._remote_settings = None

    def abort(self, errormessage=None, bad_csm_option=None):
        abort_msg = Message(code=ABORT)
        if errormessage is not None:
            abort_msg.payload = errormessage.encode('utf8')
        if bad_csm_option is not None:
            bad_csm_option_option = optiontypes.UintOption(2, bad_csm_option)
            abort_msg.opt.add_option(bad_csm_option_option)
        if self._transport is not None:
            self.send_data(abort_msg)
            self.close()


    def _process_signaling(self, msg):
        if msg.code == CSM:
            if self._remote_settings is None:
                self._remote_settings = {}
            for opt in msg.opt.option_list():
                if opt.number == 2:
                    self._remote_settings['max-message-size'] = int.from_bytes(opt.value, 'big')
                elif opt.number == 4:
                    self._remote_settings['block-wise-transfer'] = True
                elif opt.number.is_critical():
                    self.abort("Option not supported", bad_csm_option=opt.number)
                else:
                    pass
        elif msg.code in (PING, PONG, RELEASE, ABORT):
            for opt in msg.opt.option_list():
                if opt.number.is_critical():
                    self.abort("Unknown critical option")
                else:
                    pass

            if msg.code == PING:
                pong = Message(code=PONG, token=msg.token)
                self.send_data(pong)
            elif msg.code == PONG:
                pass
            elif msg.code == RELEASE:
                raise NotImplementedError
            elif msg.code == ABORT:
                raise NotImplementedError
            else:
                self.abort("Unknown signalling code")

    def _send_initial_csm(self):
        csm = Message(code=CSM)
        block_length = optiontypes.UintOption(2, self._my_max_message_size)
        csm.opt.add_option(block_length)
        supports_block = optiontypes.UintOption(4, 0)
        csm.opt.add_option(supports_block)
        self.send_data(csm)

    def send_data(self, message):
        sid = self._quic.get_next_available_stream_id()
        stream_end = True
        message = tcp._serialize(message)
        self._quic.send_stream_data(sid, message, stream_end)
        self.transmit()

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ConnectionTerminated):
            self.con = False
        if isinstance(event, ConnectionIdIssued):
            # print(event)
            pass
        if isinstance(event, HandshakeCompleted):
            self.key = get_transport_infos(self._transport)
            self._send_initial_csm()
        if isinstance(event, StreamDataReceived):
            self.data += event.data

            while True:
                msglen = tcp._extract_message_size(self.data)
                if msglen is None:
                    break

                # TODO:
                # if msglen > self._my_max_message_size:
                #    self.abort("Overly large message announced")
                #    return

                msglen = sum(msglen)
                if msglen > len(self.data):
                    break

                message = self.data[:msglen]
                try:
                    message = tcp._decode_message(message)
                except error.UnparsableMessage:
                    self.abort("Failed to parse message")
                    return
                message.remote = self


                self.ctx.log.debug("Received message: %r", message)
                self.data = self.data[msglen:]

                if message.code.is_signalling():
                    self._process_signaling(message)
                    continue

                if self._remote_settings is None:
                    self._remote_settings['max-message-size'] = 1024 * 1024

                self.dispatch_incoming(message)

    def dispatch_incoming(self, message):
        if message.code == 0:
            pass
        if message.code.is_response():
            self.ctx.tman.process_response(message)

        else:
            self.ctx.tman.process_request(message)

    @property
    def scheme(self):
        return self.ctx.scheme

    @property
    def blockwise_key(self):
        return self.key

    @property
    def hostinfo(self):
        host, port = self._transport.get_extra_info('peername')[:2]

        if port == COAP_PORT:
            port = None

        return util.hostportjoin(host, port)

    @property
    def hostinfo_local(self):
        host, port = self._transport.get_extra_info('sockname')[:2]

        return util.hostportjoin(host, port)

    @property
    def uri_base(self):
        if self._quic.configuration.is_client:
            return self.ctx.scheme + '://' + self.hostinfo
        else:
            raise error.AnonymousHost("Client side of %s can not be expressed as a URI" % self.ctx.scheme)

    @property
    def uri_base_local(self):
        if self._quic.configuration.is_client:
            return error.AnonymousHost("Client side of %s can not be expressed as a URI" % self.ctx.scheme)
        else:
            return self.ctx.scheme + '://' + self.hostinfo_local

    @property
    def is_multicast(self):
        return False

    @property
    def is_multicast_locally(self):
        return False

class QuicClient(interfaces.TokenInterface):
    def __init__(self):
        self.scheme = 'coap+quic'
        self.loop = None
        self.log = None
        self.tman = None
        self.default_port = COAP_PORT
        self.quic = None
        self.con = False

    async def connection(self, message):

        if message.unresolved_remote is None:
            host = message.opt.uri_host
            port = message.opt.uri_port or self.default_port

            if host is None:
                raise ValueError("No location found to send message to (neither in .opt.uri_host nor in .remote)")
        else:
            host, port = util.hostportsplit(message.unresolved_remote)
            port = port or self.default_port

        try:
            ipaddress.ip_address(host)
            server_name = None
        except ValueError as ve:
            server_name = host

        infos = await self.loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        self.addr = infos[0][4]

        config = QuicConfiguration(is_client=True, alpn_protocols='coap', idle_timeout=864000, server_name=server_name)
        config.verify_mode = ssl.CERT_NONE

        if config.server_name is None:
            config.server_name = server_name

        connection = QuicConnection(configuration=config)

        self.quic = Quic(connection)
        self.quic.ctx = self

        try:
            transport, protocol = await self.loop.create_datagram_endpoint(lambda: self.quic, remote_addr=(host, port))
            protocol.connect(self.addr)
            await protocol.wait_connected()
            self.con = True
        except OSError:
            raise error.NetworkError("Connection failed to %r" % host)
        self.protocol = protocol
        return protocol

    async def fill_or_recognize_remote(self, message):
        if message.requested_scheme == self.scheme:  # and not self.con:
            if not self.con:
                message.remote = await self.connection(message)
            else:
                message.remote = self.protocol
            return True

        if message.remote is not None \
                and isinstance(message.remote, QuicConnectionProtocol) \
                and message.remote.ctx is self:
            return True

        return False

    def send_message(self, message, message_monitor):
        if message.code.is_response():
            no_response = (message.opt.no_response or 0) & (1 << message.code.class_ - 1) != 0
            if no_response:
                return
        message.opt.no_response = None
        message.remote.send_data(message)

    @classmethod
    async def create_client_transport(cls, loop, tman, log):
        self = cls()
        self.loop = loop
        self.log = log
        self.tman = tman

        return self

    async def shutdown(self):
        self.con = False
        del self.tman


class Server(interfaces.TokenInterface):
    def __init__(self):
        self.scheme = 'coap+quic'
        self.loop = None
        self.log = None
        self.tman = None
        self.default_port = COAP_PORT

    async def fill_or_recognize_remote(self, message):
        if message.remote is not None \
                and isinstance(message.remote, QuicConnectionProtocol) \
                and message.remote.ctx is self:
            return True
        return False

    def send_message(self, message, message_monitor):
        if message.code.is_response():
            no_response = (message.opt.no_response or 0) & (1 << message.code.class_ - 1) != 0
            if no_response:
                return
        message.opt.no_response = None
        message.remote.send_data(message)

    @classmethod
    async def create_server(cls, bind, log, loop, tman):
        self = cls()
        self.loop = loop
        self.log = log
        self.tman = tman

        bind = bind or ('::', None)
        bind = (bind[0], bind[1] + (self.default_port - COAP_PORT) if bind[1] else self.default_port)
        config = QuicConfiguration(is_client=False, alpn_protocols='coap')
        config.load_cert_chain("aiocoap/ssl_cert.pem", "aiocoap/ssl_key.pem")
        config.secrets_log_file = open("my.log","w")

        PORT = 5684
        PORT = 64999
        try:
            server = await self.loop.create_datagram_endpoint(lambda: QuicServer(configuration=config,
                                                                                 create_protocol=Quic),
                                                              local_addr=(bind[0], PORT),
                                                              reuse_port=socket.SO_REUSEPORT)
            Quic.ctx = self

        except socket.gaierror:
            raise error.ResolutionError("No local bindable address found for %s" % bind[0])

        self.server = server

        return self
