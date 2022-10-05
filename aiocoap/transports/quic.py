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


def _extract_message_size(data: bytes):
    """Read out the full length of a CoAP messsage represented by data.

    Returns None if data is too short to read the (full) length.

    The number returned is the number of bytes that has to be read into data to
    start reading the next message; it consists of a constant term, the token
    length and the extended length of options-plus-payload."""

    if not data:
        return None

    l = data[0] >> 4
    tokenoffset = 2
    tkl = data[0] & 0x0f

    if l >= 13:
        if l == 13:
            extlen = 1
            offset = 13
        elif l == 14:
            extlen = 2
            offset = 269
        else:
            extlen = 4
            offset = 65805
        if len(data) < extlen + 1:
            return None
        tokenoffset = 2 + extlen
        l = int.from_bytes(data[1:1 + extlen], "big") + offset
    return tokenoffset, tkl, l


def _decode_message(data: bytes) -> Message:
    tokenoffset, tkl, _ = _extract_message_size(data)
    if tkl > 8:
        raise error.UnparsableMessage("Overly long token")
    code = data[tokenoffset - 1]
    token = data[tokenoffset:tokenoffset + tkl]

    msg = Message(code=code, token=token)

    msg.payload = msg.opt.decode(data[tokenoffset + tkl:])

    return msg


def _encode_length(l: int):
    if l < 13:
        return (l, b"")
    elif l < 269:
        return (13, (l - 13).to_bytes(1, 'big'))
    elif l < 65805:
        return (14, (l - 269).to_bytes(2, 'big'))
    else:
        return (15, (l - 65805).to_bytes(4, 'big'))


def _serialize(msg: Message) -> bytes:
    data = [msg.opt.encode()]
    if msg.payload:
        data += [b'\xff', msg.payload]
    data = b"".join(data)
    l, extlen = _encode_length(len(data))

    tkl = len(msg.token)
    if tkl > 8:
        raise ValueError("Overly long token")

    return b"".join((
        bytes(((l << 4) | tkl,)),
        extlen,
        bytes((msg.code,)),
        msg.token,
        data
    ))


class Quic(QuicConnectionProtocol, interfaces.EndpointAddress):
    _remote_settings: Optional[Message]
    _my_max_message_size = 1024 * 1024

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data = b""
        self.key = None
        self._remote_settings = None

    def abort(self, errormessage=None, bad_csm_option=None):
        self.log.warning("Aborting connection: %s", errormessage)
        abort_msg = Message(code=ABORT)
        if errormessage is not None:
            abort_msg.payload = errormessage.encode('utf8')
        if bad_csm_option is not None:
            bad_csm_option_option = optiontypes.UintOption(2, bad_csm_option)
            abort_msg.opt.add_option(bad_csm_option_option)
        self._abort_with(abort_msg)

    def _abort_with(self, abort_msg):
        if self._transport is not None:
            self.send_data(abort_msg)
            self._transport.close()
        else:
            # FIXME: find out how this happens; i've only seen it after nmap
            # runs against an aiocoap server and then shutting it down.
            # "poisoning" the object to make sure this can not be exploited to
            # bypass the server shutdown.
            self._ctx = None


    def _send_initial_csm(self):
        csm = Message(code=CSM)
        block_length = optiontypes.UintOption(2, self._my_max_message_size)
        csm.opt.add_option(block_length)
        supports_block = optiontypes.UintOption(4, 0)
        csm.opt.add_option(supports_block)
        self.send_data(csm)

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
                    pass  # ignoring elective CSM options
        elif msg.code in (PING, PONG, RELEASE, ABORT):
            # not expecting data in any of them as long as Custody is not implemented
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

    def send_data(self, message):
        sid = self._quic.get_next_available_stream_id()
        stream_end = True
        # message = tcp._serialize(message)
        self._quic.send_stream_data(sid, _serialize(message), stream_end)
        self.transmit()

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ConnectionTerminated):
            self.con = False
        if isinstance(event, ConnectionIdIssued):
            # print(event)
            pass
        if isinstance(event, HandshakeCompleted):
            self._send_initial_csm()
            self.key = get_transport_infos(self._transport)
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
                    message = _decode_message(message)
                except error.UnparsableMessage:
                    self.abort("Failed to parse message")
                    return
                message.remote = self

                # TODO:
                self.ctx.log.debug("Received message: %r", message)
                self.data = self.data[msglen:]

                # TODO
                if message.code.is_signalling():
                    self._process_signaling(message)
                    continue

                # TODO
                if self._remote_settings is None:
                    self.abort("No CSM received")
                    return

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

    @property
    def maximum_block_size_exp(self):
        if self._remote_settings is None:
            # This is assuming that we can do BERT, so a first Block1 would be
            # exponent 7 but still only 1k -- because by the time we send this,
            # we typically haven't seen a CSM yet, so we'd be stuck with 6
            # because 7959 says we can't increase the exponent...
            #
            # FIXME: test whether we're properly using lower block sizes if
            # server says that szx=7 is not OK.
            return 7

        max_message_size = (self._remote_settings or {}).get('max-message-size', 1152)
        has_blockwise = (self._remote_settings or {}).get('block-wise-transfer', False)
        if max_message_size > 1152 and has_blockwise:
            return 7
        return 6  # FIXME: deal with smaller max-message-size

    @property
    def maximum_payload_size(self):
        # see maximum_payload_size of interfaces comment
        slack = 100

        max_message_size = (self._remote_settings or {}).get('max-message-size', 1152)
        has_blockwise = (self._remote_settings or {}).get('block-wise-transfer', False)
        if max_message_size > 1152 and has_blockwise:
            return ((max_message_size - 128) // 1024) * 1024 + slack
        return 1024 + slack  # FIXME: deal with smaller max-message-size


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
