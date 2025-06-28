#!/usr/bin/env python3
import os
import sys
import random
from paillier import Paillier

FLAG = 'ECSC{this_is_an_example_flag_for_testing}'
if os.path.exists("flag.txt"):
	FLAG = open("flag.txt", "rb").read().strip()

# Generate 1024-bit key
crypto = Paillier(1024)

# Break flag into 10-byte chunks
chunk_size = 10
flag_chunks = [FLAG[i:i+chunk_size] for i in range(0, len(FLAG), chunk_size)]
ITEM_COUNT = len(flag_chunks)

items = {}
items_initial_val = {}
guess_streak = {}
block_double_guess = {}

for i, chunk in enumerate(flag_chunks):
	chunk_int = int.from_bytes(chunk, 'big')
	items[i] = crypto.encrypt(chunk_int)
	items_initial_val[i] = items[i]
	guess_streak[i] = 0
	block_double_guess[i] = False

def print_flush(x=""):
	print(x, end='', flush=True)

def auction_win(i):
	print_flush(f"\n🏆 You won the guess auction for item{i}!")
	print_flush("🎉 Congratulations!\n")

def display_menu():
	print_flush("""
🔐 Welcome to the Velvet Auction Gambling House
5 encrypted items are up for bid.

Each has a hidden price. You can:
- list                      - See item IDs
- bid <id> <enc value>      - Place a bid on an item
- guess <id> <even|odd>     - Guess if the bid price is even or odd
- retract <id>              - retracts your bid offer and resets item's price
- info                      - See public key info
- quit                      - Leave the auction

Guess correctly 100 times in a row on any item, and to win the auction...
""")

def prompt():
	print_flush("\n> "),


def main():
	display_menu()

	while True:
		prompt()
		line = sys.stdin.readline()
		if not line:
			break
		line = line.strip()
		if not line:
			prompt()
			continue

		args = line.split()
		cmd = args[0].lower()

		try:
			if cmd == "list":
				print_flush("🧾 Available items:\n")
				for i in range(ITEM_COUNT):
					print_flush(f"- Item ID {i}: {items[i]}\n")

			elif cmd == "bid" and len(args) == 3:
				idx = int(args[1])
				amt_ct = int(args[2])
				if idx < 0 or idx >= ITEM_COUNT:
					print_flush("❌ Invalid item ID\n")
					continue
				items[idx] = crypto.add(items[idx], amt_ct)
				block_double_guess[idx] = False
				print_flush(f"💰 Bid of {amt_ct} placed on item {idx}.\n")

			elif cmd == "retract" and len(args) == 2:
				idx = int(args[1])
				if idx < 0 or idx >= ITEM_COUNT:
					print_flush("❌ Invalid item ID\n")
					continue
				items[idx] = items_initial_val[idx]
				guess_streak[i] = 0
				block_double_guess[idx] = False
				print_flush(f"🧾 Item {idx}'s price was reset'.\n")

			elif cmd == "guess" and len(args) == 3:
				idx = int(args[1])
				choice = args[2].lower()
				if idx < 0 or idx >= ITEM_COUNT:
					print_flush("❌ Invalid item ID\n")
					continue
				if block_double_guess[idx]:
					print_flush("❌ You already guessed this price\n")
					continue
				block_double_guess[idx] = True
				if choice not in ("even", "odd"):
					print_flush("❌ Guess must be 'even' or 'odd'\n")
					continue

				decrypted = crypto.decrypt(items[idx])
				actual = "even" if decrypted % 2 == 0 else "odd"

				if choice == actual:
					guess_streak[idx] += 1
					print_flush(f"✅ Correct guess! ({guess_streak[idx]} in a row)\n")
					if guess_streak[idx] >= 100:
						auction_win(idx)
				else:
					guess_streak[idx] = 0
					print_flush(f"❌ Wrong guess. The streak resets.\n")

			elif cmd == "info":
				print_flush(f"🔓 Public Key (n): {crypto.n}\n")
				print_flush(f"🎰 Generator (g): {crypto.g}\n")

			elif cmd == "quit":
				print_flush("👋 Goodbye.\n")
				sys.exit(0)

			else:
				print_flush("❌ Invalid command.\n")

		except Exception as e:
			print_flush(f"⚠️ Error: {e}\n")

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print_flush("\n👋 Interrupted.\n")
