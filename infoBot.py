# bot url = https://discordapp.com/oauth2/authorize?client_id=509991584067223571&permissions=206848&scope=bot

import discord
import asyncio
from discord.ext.commands import Bot
import time
import pandas as pd
import random
from Crypto import Random
import hashlib
import hmac
import base64 


client = discord.Client()
token = open("token.txt", "r").read()
bot_id = 509991584067223571
guild = client.get_guild(509992354543960064)


num_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", # List of ports
		 53: "DNS", 67: "DHCP Server", 68: "DHCP Client",
		 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",                # Need both for the port search later.
		 }
text_ports = {v: k for k, v in num_ports.items()} # Reversed list of ports


def community_report(guild):
	online = 0
	idle = 0
	dnd = 0
	offline = 0

	for member in guild.members: # Go through members in the server
		if str(member.status) == "online":
			online += 1

		elif str(member.status) == "idle":
			idle += 1
		
		elif str(member.status) == "dnd":
			dnd += 1

		elif str(member.status) == "offline":
			offline += 1

		else:
			print(str(member.status))


	total = guild.member_count
	online_p = (online / total) * 100
	idle_p = (idle / total) * 100
	dnd_p = (dnd / total) * 100
	offline_p = (offline / total) * 100

	return total, online, online_p, idle, idle_p, dnd, dnd_p, offline, offline_p

		
class BotCrypto: # Massive shoutout to @Nanibongwa on Discord/nsk89 on GitHub for this implementation.
	def generate_password(self, length):
		# generate random bytes and hash returned data
		password = self.hash_data(Random.get_random_bytes(length))
		secret = self.hash_data(Random.get_random_bytes(length))
		# create secure hmac'd hash password
		hmac_pass = base64.b64encode(hmac.new(password, secret, hashlib.sha3_384).digest())

		return self.symbol_insert(hmac_pass[:length].decode())

	def symbol_insert(self, passphrase):
		# list of symbols to choose from
		symbol_list = ['!', '@', '#', '$', '%', '^', '&' '*', '(', ')', '+', '=', '_']
		# define the amount of symbols to use in a given string based on length >= 8
		symbol_count = round(len(passphrase) / 4)
		count = 0
		while count < symbol_count:  # pick random symbols based on int chosen and append it to passphrase
			rand_int = random.randrange(0, len(symbol_list))
			passphrase += symbol_list[rand_int]
			count += 1

		passphrase = [char for char in passphrase]  # no delimiter, no .split(). list comprehension to split characters
		random.shuffle(passphrase)  # Pycrypdome shuffle, shuffle the list elements around
		passphrase = ''.join(passphrase)  # rejoin the list into the passphrase string

		return passphrase

	def hash_data(self, data):  # convert data to hash
		data = self.check_for_bytes(data)
		hasher = hashlib.new('sha3_384')
		hasher.update(data)

		return self.check_for_bytes(hasher.hexdigest())

	def check_for_bytes(self, data):  # verify incoming data is in byte form
		if type(data) != bytes:
			data = bytes(data, 'utf-8')
			return data
		else:
			return data


@client.event
async def on_ready(): # Connection confirmation.
	print(f"We have logged in as {client.user}.")


@client.event # Event wrapper.
async def on_message(message, *args):
	print(f"New message in {message.channel}:") # Outputs message in the terminal.
	print(f"    Author: {message.author} / {message.author.id}\n    Screen name: {message.author.name}\n    Message: {message.content}\n    Date: {message.created_at}\n")

	guild = client.get_guild(509992354543960064)

	if f"<@{bot_id}>" == message.content: # If bot is tagged.
		await message.channel.send(f"Hello, <@!{message.author.id}>. Use !help to get a list of my commands.")


	elif "!help" == message.content.lower(): # Command to list commands
		await message.channel.send("```!help - Show this message \n!qa - Shows common questions with answers \n!clear x - Delete channel messages. (x being number of messages to delete) \n!passgen x - Password generator between 8 - 32 chars. (x being the length you want the password) \n!user_info - Get user count. \n!ports x - Show a list of common ports. (x being the port number. If no port is given it will send the whole list)\n```")


	elif "!qa" == message.content.lower(): # Need to find a cleaner way to do this.
		await message.channel.send("**How to hack [insert social media]?** \nDon't! That isn't why we made the server. But if you want to learn from a security point of view, google these things: Phishing, Keyloggers, MiTM, session hijacking, cookie stealing. \n\n**How do I start hacking?** \nThere are a lot of resources, here a few: https://www.hacker101.com, https://bit.ly/2PLuDv4 \n\n**What is the link for Kali Linux?** \nhttps://www.kali.org \n\n**Wi-Fi Hacking?** \nLook on Google for stuff like Aircrack-ng. \n\n**What is Tor?** \nTor (The Onion Router).  It was originally developed with the U.S. Navy in mind, for the primary purpose of protecting government communications. Today, it is used every day for a wide variety of purposes by the military, journalists, law enforcement officers, activists, and many others. Here are some of the specific uses we've seen or recommend.\n\n**How do I use Tor?** \nGoogle it ;) \n\n**What is a CTF? How do I start?** \nhttps://www.ctf101.org")


	elif message.content.startswith("!ports"): # Ports list and search.
		try:
			args = message.content.split(" ")[1]
			port = int(args)

			if port in num_ports:
				await message.channel.send(f"```py\nPort {port}:\n{num_ports[port]}```")

			elif port not in num_ports:
				await message.channel.send("Error, not a common port. Sorry!")

		except ValueError:
			await message.channel.send("Error, port has to be an integer!")

		except IndexError:
			await message.channel.send(f"```py\nCommon Ports:\n{pd.DataFrame.from_dict(text_ports, orient = 'index')}```")


	elif message.content.startswith("!passgen"): # Password generator
		args = message.content.split(" ")[1]

		try:
			length = int(args) # Check if input is an int

		except ValueError:
			await message.channel.send("Error, not a valid input!")

		
		if length < 8 or length > 32: # Control length
			await message.channel.send("Error, not a valid input!")

		else: # Create password and send it as a private message
			crypto = BotCrypto()
			password = crypto.generate_password(length)

			await message.author.create_dm()
			await message.author.send(f'Your password is: {password}')


	elif message.content.startswith("!clear"): # Delete messages (Needs an int as input)
		args = message.content.split(" ")[1]

		try:
			limit = int(args) # Check if input is an int

		except ValueError:
			await message.channel.send("Error, not a valid input!")

		counter = 0
		messages = []
		channel = message.channel

		# Need to add date check

		async for message in message.channel.history(): # Go through messages in channel
			if counter < limit:
				counter += 1
				messages.append(message) # Add message to list
			else:
				pass

		await channel.delete_messages(messages) # Delete messages from list

		clear_end = await message.channel.send(f"I deleted {counter} messages.")
		messages.append(clear_end)

		time.sleep(1)

		await channel.delete_messages(messages) # delete the bot message


	elif "!user_info" == message.content.lower(): # Gives server info
		total, online, online_p, idle, idle_p, dnd, dnd_p, offline, offline_p = community_report(guild)
		await message.channel.send(f"```py\nTotal Users: {total} \nOnline: {int(online)} | {online_p}% \nIdle: {int(idle)} | {idle_p} \ndnd: {int(dnd)} | {dnd_p} \nOffline: {int(offline)} | {offline_p}%```")     


client.run(token)