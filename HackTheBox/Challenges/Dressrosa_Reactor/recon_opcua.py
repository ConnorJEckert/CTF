import asyncio
from asyncua import Client, ua

URL = "opc.tcp://154.57.164.78:30567"

async def browse_node(node, depth=0, max_depth=10):
    try:
        name = await node.read_browse_name()
    except Exception as e:
        print("  " * depth, "ERR", e)
        return
    node_class = await node.read_node_class()
    line = "  " * depth + f"{name.Name} ({node.nodeid}) [{node_class.name}]"
    if node_class.name == "Variable":
        try:
            val = await node.read_value()
            line += f" = {val!r}"
        except Exception as e:
            line += f" <readerr {e}>"
    print(line)
    if depth >= max_depth:
        return
    try:
        children = await node.get_children()
    except Exception as e:
        print("  " * (depth+1), "childerr", e)
        return
    for c in children:
        await browse_node(c, depth+1, max_depth)

async def main():
    client = Client(url=URL)
    await client.set_security_string(
        "Basic256Sha256,SignAndEncrypt,client_cert.pem,client_key.pem"
    )
    async with client:
        root = client.get_objects_node()
        children = await root.get_children()
        for c in children:
            bn = await c.read_browse_name()
            print("TOP-LEVEL:", bn.Name, c.nodeid)
        print("=====")
        for c in children:
            bn = await c.read_browse_name()
            if bn.Name == "Server":
                continue
            await browse_node(c, 0, 10)

asyncio.run(main())
