#!/usr/bin/env python3
from pwn import *
import re
from time import sleep
from secrets import randbelow
from Crypto.Util.number import GCD, long_to_bytes

#context.log_level = 'debug'

# ===== CONFIGURATION =====
SERVER_SCRIPT = '../setup/server.py'  	# path to your server script
LOCAL = True                  			# True to run locally, False for remote
HOST = 'localhost'
PORT = 1337

# =========================

class PaillierPub:
	def __init__(self, n, g):
		self.n = n
		self.n2 = self.n * self.n
		self.g = g
	
	def pubkey(self):
		return (self.n, self.g)
	
	def encrypt(self, m):
		m %= self.n
		while True:
			r = randbelow(self.n)
			if GCD(r, self.n) == 1: break
		c = pow(self.g, m, self.n2) * pow(r, self.n, self.n2) % self.n2
		return c
	
	def mul_const(self, c, k):
		return pow(c, k, self.n2)

	def add(self, a, b):
		return (a * b) % self.n2

def start():
	if LOCAL:
		return process(['python3.10', SERVER_SCRIPT])
	else:
		return remote(HOST, PORT)

def recv_menu(io):
	return io.recvuntil(b'\n> ')

def send_cmd(io, cmd):
	io.sendline(cmd.encode())

def get_public_key(io):
	send_cmd(io, 'info')
	data = io.recvuntil(b'> ').decode()
	n = int(re.search(r'Public Key \(n\): (\d+)', data).group(1))
	g = int(re.search(r'Generator \(g\): (\d+)', data).group(1))
	return n, g

def list_items(io):
	send_cmd(io, 'list')
	data = io.recvuntil(b'> ').decode()
	return [([int(y) for y in x.split(': ')]) for x in re.findall(r'Item ID (\d+: \d+)', data)]

def bid(io, item_id, val):
	send_cmd(io, f'bid {item_id} {val}')
	data = io.recvuntil(b'> ')
	#print(data)
	return False if b'Error' in data else True

def retract(io, item_id):
	send_cmd(io, f'retract {item_id}')
	data = io.recvuntil(b'> ')
	#print(data)

def guess(io, item_id, parity):
	send_cmd(io, f'guess {item_id} {parity}')
	data = io.recvuntil(b'> ').decode()
	#print(data)
	return 'Correct guess' in data or '✅' in data

"""
def parity_oracle_attack2(io, n, g, item_id, item_ct):
	print(f"[*] Starting parity oracle attack on item {item_id}")

	crypto = PaillierPub(n, g)
	#bit_len = 55
	bit_len = n.bit_length()
	LB = 0
	UB = n

	#ct_of_2 = crypto.encrypt(2)
	ct_current = item_ct

	for i in range(bit_len - 1):
		print(f'Item {item_id} - Step {i} - Distance {UB - LB}')
		#print(f"bidding {item_id} {tmp}")
		#bid(io, item_id, tmp)
		ct_current = crypto.mul_const(ct_current, 2)
		bid(io, item_id, ct_current)

		#print(f"Guessing {item_id}")
		correct = guess(io, item_id, 'even')
		lsb = 0 if correct else 1

		mid = (LB + UB) // 2
		if lsb == 0:
			UB = mid
		else:
			LB = mid

		#print(f"Retracting {item_id}")
		#retract(io, item_id)
		#tmp = (tmp * ct_of_2) % n

	print(LB, UB, UB - LB)


	for candidate in range(LB, UB + 1):
		try:
			chunk = long_to_bytes(candidate, blocksize=10)
			print(f"Trying {candidate}: {chunk}")
		except Exception:
			continue


	deduced_ciphertext = int(UB)
	flag_chunk = long_to_bytes(deduced_ciphertext, blocksize=10)
	#print(f"Flag chunk recovered: {flag_chunk}")
	return flag_chunk
"""

def parity_oracle_attack(io, n, g, item_id, item_ct):
	print(f"[*] Starting parity oracle attack on item {item_id}")

	crypto_pub = PaillierPub(n, g)
	# Flag chunks are 10 bytes, so max value is 2^80 - 1.
	bit_len = 10 * 8 
	
	# Initialize the search range for the plaintext value.
	# LB is inclusive, UB is exclusive.
	LB = 0
	UB = (1 << bit_len) 

	# Get the LSB of the original message once. This is crucial because 'n' is odd.
	retract(io, item_id) # Ensure item is at E(M_original)
	sleep(0.1) 
	original_M_is_even = guess(io, item_id, 'even')
	original_M_LSB = 0 if original_M_is_even else 1

	for i in range(bit_len):
		print(f'Item {item_id} - Step {i} - Current Range: [{LB}, {UB})')

		mid = (LB + UB) // 2

		# Reset the item to its original encrypted value E(M_original) for each step.
		retract(io, item_id)
		#sleep(0.1) 

		# Calculate the plaintext value to add to M_original such that its parity reveals
		# if M_original is greater or less than 'mid'.
		# We want to effectively query the parity of (M_original - mid) mod n.
		# To do this, we add (n - mid) mod n to M_original.
		plaintext_to_add_for_mid_check = (n - (mid % n)) % n
		
		# Encrypt this plaintext on the client side to get a ciphertext.
		# This ciphertext will then be sent to the server's 'bid' command.
		ciphertext_to_bid = crypto_pub.encrypt(plaintext_to_add_for_mid_check)
		
		# Send the crafted ciphertext to the server's 'bid' function.
		# The server's item will become E(M_original + plaintext_to_add_for_mid_check)
		# which is E((M_original - mid) % n).
		bid(io, item_id, ciphertext_to_bid)
		#sleep(0.1)

		# Guess the parity of the new value of the item (which is (M_original - mid) % n).
		is_even = guess(io, item_id, 'even')
		parity_of_difference = 0 if is_even else 1

		# Logic for updating the binary search range:
		# If M_original >= mid: (M_original - mid) is non-negative.
		#   The decrypted value's parity will be (M_original % 2) XOR (mid % 2).
		# If M_original < mid: (M_original - mid) is negative.
		#   The decrypted value will be (M_original - mid + n) % n.
		#   Its parity will be ((M_original % 2) XOR (mid % 2)) XOR (n % 2).
		# Since n is odd, n % 2 = 1. So, if M_original < mid, the parity is flipped.

		# Calculate the expected parity if M_original >= mid.
		expected_parity_if_M_ge_mid = original_M_LSB ^ (mid % 2)

		if parity_of_difference == expected_parity_if_M_ge_mid:
			# If the observed parity matches the expected parity for M_original >= mid,
			# then M_original is indeed greater than or equal to mid.
			LB = mid
		else:
			# Otherwise, the parity was flipped, meaning M_original < mid.
			UB = mid

	print(f"[*] Final range for item {item_id}: [{LB}, {UB})")
	deduced_ciphertext = LB # The lower bound of the converged range is the recovered plaintext.
	flag_chunk = long_to_bytes(deduced_ciphertext, blocksize=10)
	return flag_chunk.lstrip(b'\x00')


def main():
	io = start()
	sleep(1)
	recv_menu(io)

	n, g = get_public_key(io)
	items = list_items(io)
	print(f"[*] Public key n: {n}")
	print(f"[*] Items: {items}")

	flag_bytes = b""
	for item in items:
		print(f"--- Attacking item {item[0]} ---")
		chunk = parity_oracle_attack(io, n, g, item[0], item[1])
		flag_bytes += chunk

	print("\n[+] Recovered flag (raw bytes):", flag_bytes)
	try:
		print("[+] Recovered flag (utf-8):", flag_bytes.decode())
	except Exception:
		print("[!] Could not decode flag as utf-8")

	io.close()

if __name__ == "__main__":
	main()
