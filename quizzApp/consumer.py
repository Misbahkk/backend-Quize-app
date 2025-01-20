import json
from channels.generic.websocket import AsyncWebsocketConsumer

class QuizPollingConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.quiz_id = self.scope['url_route']['kwargs']['quiz_id']
        self.group_name = f'quiz_{self.quiz_id}'

        # Join the group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        # Leave the group
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )

    # Receive a message from the WebSocket client
    async def receive(self, text_data):
        data = json.loads(text_data)
        print(data)


        # await self.save_message(username, self.room_group_name, message, receiver)

        # Process the data (if needed) and broadcast to the group
        await self.channel_layer.group_send(
            self.group_name,
            {
                'type': 'poll_update',
                'message': data.get('message', 'No message sent')
            }
        )

    # Receive a message from the group
    async def poll_update(self, event):
        message = event['message']

        # Send the message to the WebSocket client
        await self.send(text_data=json.dumps({
            'message': message
        }))
