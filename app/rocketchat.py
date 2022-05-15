from flask import current_app
from rocketchat_API.rocketchat import RocketChat


class InventorpyRocketChatClient(object):

    def send_message_to_rocket_chat(self, message, channel=None):

        if channel is None:
            channel = current_app.config['ROCKET_CHANNEL']

        if current_app.config['ROCKET_ENABLED']:
            print("sending rocket message {} to {}".format(message, channel))
            rocket = RocketChat(current_app.config['ROCKET_USER'],
                                current_app.config['ROCKET_PASS'],
                                server_url=current_app.config['ROCKET_URL'])
            messageresult = rocket.chat_post_message(message,
                                                     channel=channel
                                                     )
            return messageresult

        else:
            return
