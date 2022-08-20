import asyncio
import logging


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
logging.getLogger("coap-server").setLevel(logging.DEBUG)

async def main():
    root = resource.Site()
    root.add_resource(['.well-known', 'core'],
                      resource.WKCResource(root.get_resources_as_linkheader))

    content = b''
    while len(content) <= 10 ** 3:
        content += b'0123456789\n'
    root.add_resource(['example'], ExamleResource(content))



    await aiocoap.Context.create_server_context(root)

    print("Server is ready!")

    await asyncio.get_running_loop().create_future()



if __name__ == "__main__":

    try:
        asyncio.run(main())

    except KeyboardInterrupt:
        print("")
        print("Goodbye cruel world!")
