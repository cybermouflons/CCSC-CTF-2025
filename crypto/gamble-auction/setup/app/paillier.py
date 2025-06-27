#!/usr/bin/env python3
from math import lcm
from secrets import randbelow
from Crypto.Util.number import GCD, getPrime

class Paillier:
	def __init__(self, bits):
		self.p = getPrime(bits//2)
		self.q = getPrime(bits//2)
		self.n = self.p * self.q
		self.λ = lcm(self.p-1, self.q-1)
		self.n2 = self.n * self.n
		self.g = randbelow(self.n2)
		self.μ = pow(self.L(pow(self.g, self.λ, self.n2)), -1, self.n)
	
	def L(self, x):
		return (x-1) // self.n
	
	def pubkey(self):
		return (self.n, self.g)
	
	def privkey(self):
		return (self.λ, self.μ)
	
	def encrypt(self, m):
		m %= self.n
		while True:
			r = randbelow(self.n)
			if GCD(r, self.n) == 1: break
		c = pow(self.g, m, self.n2) * pow(r, self.n, self.n2) % self.n2
		return c
	
	def decrypt(self, c):
		if not (0 < c < self.n2):
			return randbelow(self.n2)
		m = self.L(pow(c, self.λ, self.n2)) * self.μ % self.n
		return m
	
	def add(self, a, b):
		return (a * b) % self.n2
