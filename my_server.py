import asyncio
import logging
import os
import ssl
import json

import aiocoap
import aiocoap.resource as resource
from aiocoap.credentials import CredentialsMap


class ExamleResource(resource.Resource):

    def __init__(self):
        super().__init__()
        # print(content)

    async def render_get(self, request):
        return aiocoap.Message(payload=b'TestResource')

    async def render_put(self, request):
        self.content = request.payload
        return aiocoap.Message(code=aiocoap.CHANGED, payload=self.content)

    async def render_delete(self, request):
        self.content = None
        return aiocoap.Message(code=aiocoap.DELETED)

    async def render_post(self, request):
        response = request.payload.replace(b'0', b'O')
        return aiocoap.Message(code=aiocoap.CONTENT, payload=response)


class ResourceOne(resource.Resource):
    def __init__(self):
        super().__init__()

    async def render_get(self, request):
        with open("./data/test_data_01_1MB", "rb") as content:
            return aiocoap.Message(payload=content.read())



class ResourceTwo(resource.Resource):
    def __init__(self, content):
        super().__init__()
        self.content = content

    async def render_get(self, request):
        with open("./data/test_data_02_5MB", "rb") as content:
            return aiocoap.Message(payload=content.read())


class ResourceThree(resource.Resource):
    def __init__(self):
        super().__init__()

    async def render_get(self, request):
        with open("./data/test_data_03_50MB", "rb") as content:
            return aiocoap.Message(payload=content.read())


class ResourceFour(resource.Resource):
    def __init__(self):
        super().__init__()

    async def render_get(self, request):
        with open("./data/test_data_04_100MB", "rb") as content:
            return aiocoap.Message(payload=content.read())


class ResourceFive(resource.Resource):
    def __init__(self):
        super().__init__()

    async def render_get(self, request):
        with open("./data/test_data_05_250MB", "rb") as content:
           return aiocoap.Message(payload=content.read())


class ResourceSix(resource.Resource):
    def __init__(self):
        super().__init__()

    async def render_get(self, request):
        with open("./data/test_data_06_500MB", "rb") as content:
            return aiocoap.Message(payload=content.read())


#logging.basicConfig(level=logging.INFO)
#logger = logging.getLogger("coap-server")
#logger.setLevel(logging.DEBUG)


#handler = logging.FileHandler('mylog.log')
#logger.addHandler(handler)

async def main():
    content = b''

    os.environ['AIOCOAP_DTLSSERVER_ENABLED'] = str(True)
    root = resource.Site()
    root.add_resource(['.well-known', 'core'],
                      resource.WKCResource(root.get_resources_as_linkheader))
    psk = b'MyKey'
    identity = b'test-client'
    root.add_resource(['example'], ExamleResource())
    root.add_resource(['01_resource'], ResourceOne())
    root.add_resource(['02_resource'], ResourceTwo(content))
    root.add_resource(['03_resource'], ResourceThree())
    root.add_resource(['04_resource'], ResourceFour())
    root.add_resource(['05_resource'], ResourceFive())
    root.add_resource(['06_resource'], ResourceSix())

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
    ssl_context.set_alpn_protocols(["coap"])
    if hasattr(ssl_context, 'sni_callback'):  # starting python 3.7
        ssl_context.sni_callback = lambda obj, name, context: setattr(obj, "indicated_server_name", name)

    server = await aiocoap.Context.create_server_context(root, _ssl_context=ssl_context)
    server.server_credentials.load_from_dict(
        {':client': {"dtls": {"psk": psk, "client-identity": identity}}})

    print("Server is ready!")
    await asyncio.get_running_loop().create_future()


if __name__ == "__main__":

    try:
        asyncio.run(main())

    except KeyboardInterrupt:
        print("")
        print("Goodbye cruel world!")
