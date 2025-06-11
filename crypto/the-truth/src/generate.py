#!/usr/bin/env python3
import random
import string

with open("message.txt", "r", encoding="utf-8") as msg_file:
    message = msg_file.read().strip()

with open("flag.txt", "r", encoding="utf-8") as flag_file:
    flag = flag_file.read().strip()

message += "\n" + flag

uppercase_message = message.upper()
uppercase_flag = flag.upper()

if uppercase_flag != flag:
    print("[!] The flag in uppercase differs from the original flag!")

emoji_list = [
    "😂", "😍", "🥺", "😊", "🔥", "💀", "🤔", "🙄", "🥰", "😎", "😢", "😏", "😡", "🤯", "🤩", "😱", "💖", "🤗",
    "🤑", "🤠", "😇", "😈", "😜", "🤪", "😴", "😵", "🎉", "💃", "🕺", "🥳", "💥", "🚀", "💯", "🎯", "🌟", "👽",
    "👻", "🐍", "🦄", "☠️", "🎭", "🎶", "🎵", "🎸", "🥁", "🎤", "🔮", "🦊", "🐉", "🍀", "🌈", "🕷️", "🦂", "⚡"
]

random.seed(len(message))
random.shuffle(emoji_list)
letter_to_emoji = {letter: emoji for letter, emoji in zip(string.ascii_uppercase, emoji_list)}

encrypted_message = "".join(letter_to_emoji.get(char, char) for char in uppercase_message)

with open("encrypted.txt", "w", encoding="utf-8") as enc_file:
    enc_file.write(encrypted_message)

print("Encryption complete.")
