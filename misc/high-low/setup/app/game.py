#!/usr/bin/env python
import os
import sys
import time
import random
import platform

def get_user_choice():
	while True:
		try:
			print("Guess what the next number will be:")
			print("1. Higher")
			print("2. Lower")
			choice = input('> ')
			choice = int(choice)
			if choice == 1:
				return 1
			elif choice == 2:
				return -1
			else:
				return 0
		except Exception as e:
			print('Invalid input! Try again.')
			return 0


def get_server_choice():
	return random.randint(1, 100)

def determine_winner(user_guess, visible_number, hidden_number):
	if user_guess == 1 and visible_number < hidden_number:
		return 1
	elif user_guess == -1 and visible_number > hidden_number:
		return 1
	else:
		return 0

def round(visible_number, hidden_number):
	time.sleep(1)
	
	print("The number on the table is %d" % visible_number)
	user_guess = get_user_choice()
	round_result = determine_winner(user_guess, visible_number, hidden_number)
	visible_number = hidden_number
	print("The next number on the table is %d" % visible_number)
	
	if round_result == 1:
		print('Your guess was CORRECT!')
		return 1
	else:
		print('Your guess was WRONG!')
		return -1


def main():
	# Game stats
	consecutive_wins = 0
	WIN_STREAK_NEEDED = 10
	platform_system = platform.system().upper()

	# Print welcome message
	print('WELCOME TO THE HIGH-LOW GUESSING GAME')
	print("RUNNING ON PYTHON %s ON %s!" % (sys.version.split()[0], platform_system))
	time.sleep(0.5)
	print('')
	print('TRY TO GUESS IF THE NEXT NUMBER IS HIGHER OR LOWER!')
	print('TO WIN THE GAME, YOU NEED TO WIN 50 TIMES IN A ROW!')
	print('')
	time.sleep(0.5)

	# Game loop for multiple rounds
	visible_number = get_server_choice()

	while True:
		hidden_number = get_server_choice()
		result = round(visible_number, hidden_number)
		visible_number = hidden_number

		if result == 1:
			consecutive_wins += 1
			print("Current consecutive wins: %d/%d" % (consecutive_wins, WIN_STREAK_NEEDED))
		else:
			print("Streak broken! You had %d consecutive wins." % consecutive_wins)
			consecutive_wins = 0

		time.sleep(1)

		# Check for game winner
		if consecutive_wins >= WIN_STREAK_NEEDED:
			print("CONGRATULATIONS! YOU WON %d TIMES IN A ROW!" % WIN_STREAK_NEEDED)
			print('YOU WON THE GAME!')
			break
		
		print('')

	print('THANKS FOR PLAYING! BYE!')


if __name__ == "__main__":
	main()
