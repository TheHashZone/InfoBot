# bot url = https://discordapp.com/oauth2/authorize?client_id=509991584067223571&permissions=206848&scope=bot

import discord
import asyncio
from discord.ext.commands import Bot
import random
import time
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib import style

style.use("fivethirtyeight")

client = discord.Client()
token = open("token.txt", "r").read()
bot_id = 509991584067223571
guild = client.get_guild(509992354543960064)


num_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
         53: "DNS", 67: "DHCP Server", 68: "DHCP Client",
         80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
         }
text_ports = {v: k for k, v in num_ports.items()}


def community_report(guild):
    online = 0
    idle = 0
    offline = 0

    for member in guild.members:
        if str(member.status) == "online":
            online += 1
        if str(member.status) == "offline":
            offline += 1
        elif str(member.status) == "idle" or str(member.status) == "dnd":
            idle += 1

    return online, idle, offline


async def user_metrics_background_task():
    await client.wait_until_ready()
    global guild
    guild = client.get_guild(509992354543960064)

    while not client.is_closed():
        try:
            online, idle, offline = community_report(guild)
            with open("usermetrics.csv","a") as f:
                f.write(f"{int(time.time())},{online},{idle},{offline}\n")

            plt.clf()
            df = pd.read_csv("usermetrics.csv", names = ['time', 'online', 'idle', 'offline'])
            df['date'] = pd.to_datetime(df['time'],unit = 's')
            df['total'] = df['online'] + df['offline'] + df['idle']
            df.drop("time", 1,  inplace = True)
            df.set_index("date", inplace = True)
            df['online'].plot(), df['offline'].plot(), df['idle'].plot()
            plt.legend()
            plt.savefig("online.png")

            await asyncio.sleep(30)

        except Exception as e:
            print(str(e))
            await asyncio.sleep(5)


@client.event
async def on_ready(): # Connection confirmation.
    print(f"We have logged in as {client.user}.")


@client.event # Event wrapper.
async def on_message(message, *args):
    print(f"New message in {message.channel}:")
    print(f"    Author: {message.author} / {message.author.id}\n    Screen name: {message.author.name}\n    Message: {message.content}\n    Date: {message.created_at}\n")

    guild = client.get_guild(509992354543960064)

    if f"<@{bot_id}>" == message.content: # If bot is tagged.
        await message.channel.send(f"Hello, <@!{message.author.id}>. Use !help to get a list of my commands.")


    elif "!help" == message.content.lower():
        await message.channel.send("```\
    !help - Show this message\n\
    !clear - Delete channel messages up to 14 days old.\n\
    !passgen x - Password generator between 8 - 32 chars (x being the length you want the password)\n\
    !user_info - Get user count.\n\
    !ports - Show a list of common ports.\n\
    !user_analysis - Show a graph of activity.```")


    elif "!ports" == message.content.lower():
        await message.channel.send(f"```py\nCommon Ports: \n{pd.DataFrame.from_dict(text_ports, orient = 'index')}```")


    elif message.content.startswith("!passgen"): # Password generator
        args = message.content.split(" ")[1] # Get password length

        try:
            length = int(args)

        except ValueError:
            await message.channel.send("Error, not a valid input!")


        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.:_?$&#!<>'
        password = ''
        
        if length < 8 or length > 32:
            await message.channel.send("Error, not a valid input!")

        else:
            for i in range(length): # Create the password
                password += random.choice(chars)

            await message.author.create_dm()
            await message.author.send(f'Your password is: {password}') # Send the password as a DM


    elif "!clear" == message.content.lower(): # Delete all messages (Need to implement number of messages to delete)
        counter = 0
        messages = []
        channel = message.channel

        async for message in message.channel.history():
            counter += 1
            messages.append(message)

        await channel.delete_messages(messages)

        clear_end = await message.channel.send(f"I deleted {counter} messages.")
        messages.append(clear_end)

        time.sleep(1)

        await channel.delete_messages(messages)


    elif "!user_info" == message.content.lower(): # Gives server info
        online, idle, offline = community_report(guild)
        await message.channel.send(f"```py\nTotal Users: {guild.member_count}\n    Online: {online}.\n    Idle/busy/dnd: {idle}.\n    Offline: {offline}```")


    elif "!user_analysis" == message.content.lower(): # Sends a graph of user activity
        file = discord.File("online.png", filename = "online.png")
        await message.channel.send("User Analysis", file = file)


client.loop.create_task(user_metrics_background_task())
client.run(token)