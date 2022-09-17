import asyncio
import logging
import os
import ssl

import aiocoap
import aiocoap.resource as resource

class ExamleResource(resource.Resource):

    def __init__(self, content):
        super().__init__()
        self.content = content
        # print(content)

    async def render_get(self, request):
        return aiocoap.Message(payload=self.content)

    async def render_put(self, request):
        self.content = request.payload
        return aiocoap.Message(code=aiocoap.CHANGED, payload=self.content)

    async def render_delete(self, request):
        self.content = None
        return aiocoap.Message(code=aiocoap.DELETED)

    async def render_post(self, request):
        response = request.payload.replace(b'0', b'O')
        return aiocoap.Message(code=aiocoap.CONTENT, payload=response)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("coap-server")
logger.setLevel(logging.DEBUG)
#handler = logging.FileHandler('mylog.log')
#logger.addHandler(handler)

async def main():
    os.environ['AIOCOAP_DTLSSERVER_ENABLED'] = str(True)
    root = resource.Site()
    root.add_resource(['.well-known', 'core'],
                      resource.WKCResource(root.get_resources_as_linkheader))

    PSK = b'MyKey'
    identity = b'test-client'
    content = b''
    while len(content) <= 10 ** 3:
        content += b'0123456789'
    root.add_resource(['example'], ExamleResource(content))

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
    ssl_context.set_alpn_protocols(["coap"])
    if hasattr(ssl_context, 'sni_callback'):  # starting python 3.7
        ssl_context.sni_callback = lambda obj, name, context: setattr(obj, "indicated_server_name", name)


    server = await aiocoap.Context.create_server_context(root, _ssl_context=ssl_context)
    server.server_credentials.load_from_dict(
        {':client': {"dtls": {"psk": PSK, "client-identity":  identity}}})

    print("Server is ready!")
    await asyncio.get_running_loop().create_future()



if __name__ == "__main__":

    try:
        asyncio.run(main())

    except KeyboardInterrupt:
        print("")
        print("Goodbye cruel world!")
