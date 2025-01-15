from channels.generic.websocket import AsyncWebsocketConsumer
import json

class QuizConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Get quiz ID from the URL
        self.quiz_id = self.scope['url_route']['kwargs']['quiz_id']

        # Create a group name based on quiz_id
        self.room_group_name = f"quiz_{self.quiz_id}"

        # Join the room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name,
        )
        await self.accept()

    async def disconnect(self, close_code):
        # Leave the room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name,
        )

    async def receive(self, text_data):
        data = json.loads(text_data)
        # Process the received data and send a response
        await self.send(text_data=json.dumps({
            'message': 'Message received'
        }))

    async def send_poll_data(self, event):
        # Send data to WebSocket
        await self.send(text_data=json.dumps({
            'poll_data': event['data']
        }))
