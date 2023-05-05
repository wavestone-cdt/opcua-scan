import sys
import asyncio
sys.path.insert(0, "..")
import logging

from asyncua import Client


class SubHandler(object):

    """
    Subscription Handler. To receive events from server for a subscription
    """

    def datachange_notification(self, node, val, data):
        print("Python: New data change event", node, val)

    def event_notification(self, event):
        print("Python: New event", event)


async def main():
    url = "opc.tcp://192.168.0.20:49320"
    # url = "opc.tcp://olivier:olivierpass@localhost:53530/OPCUA/SimulationServer/"
    async with Client(url=url) as client:
        #print("Root children are", await client.nodes.root.get_children())

        tag1 = client.get_node("ns=2;s=ModbusPLC-10-3-0-150.Device2.head_up")
        tag2 = client.get_node("ns=2;s=ModbusPLC-10-3-0-150.Device2.R0001@Short")
        print(f"tag1 is: {tag1} with value {await tag1.read_value()} ")
        print(f"tag2 is: {tag2} with value {await tag2.read_value()} ")
        handler = SubHandler()
        sub = await client.create_subscription(500, handler)
        handle1 = await sub.subscribe_data_change(tag1)


        await sub.unsubscribe(handle1)
        await sub.delete()

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARN)
    asyncio.run(main())
