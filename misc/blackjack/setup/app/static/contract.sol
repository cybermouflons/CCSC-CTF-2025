// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

// Math Library
// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/Math.sol
import "Math.sol";


contract Blackjack {

	address payable public dealer;
	address payable public player;
	address public last_winner;

	uint public round;
	uint public currentBet;

	uint private randomSeed;

	uint public dealerScore;
	uint private dealerAces;
	Card[] public dealerCards;
	uint public playerScore;
	uint private playerAces;
	Card[] public playerCards;

	struct Card {
		uint cat;
		uint num;
	}

	constructor(uint seed) payable {
		dealer = payable(msg.sender);
		randomSeed = seed;
		round = 0;
		end_game();
	}

	function bet() payable public {
		require(player == address(0), "A player already betted.");
		require(msg.value >= 0, "Your bet amount is too small.");
		new_game();

		player = payable(msg.sender);
		currentBet = msg.value;
		
		// One card to dealer;
		dealerDrawCard();

		// Two cards to the player
		playerDrawCard();
		playerDrawCard();

		checkWinner(false);
	}

	function hit() public {
		require(player != address(0), "Player has not betted yet.");

		// One card for the player
		playerDrawCard();
		checkWinner(false);
	}

	function stand() public {
		require(player != address(0), "Player has not betted yet.");

		while (dealerScore < playerScore) {
			dealerDrawCard();
		}

		checkWinner(true);
	}

	function double() public payable {
		require(player != address(0), "Player has not betted yet.");
		require(msg.value >= currentBet, "Invalid bet amount");

		currentBet *= 2;

		// One card for the player
		playerDrawCard();

		if (!checkWinner(false)) {
			stand();
		}
	}

	function forfeit() public {
		last_winner = dealer;
		end_game();
	}

	function checkWinner(bool endgame) private returns (bool) {
		if (dealerScore > 21 || playerScore == 21 || (endgame && playerScore > dealerScore)) {
			last_winner = player;
			player.transfer(Math.min(currentBet * 2, address(this).balance));
			end_game();
			return true;
		}
		if (playerScore > 21 || (endgame && dealerScore >= playerScore)) {
			last_winner = dealer;
			end_game();
			return true;
		}
		return false;
	}

	function dealerDrawCard() private {
		uint card = drawCard();
		dealerCards.push(Card((randomSeed % 4) + 1, card));

		dealerAces += card == 1 ? 1 : 0;
		dealerScore += card == 1 ? 11 : Math.min(10, card);

		while (dealerScore > 21 && dealerAces > 0) {
			dealerAces -= 1;
			dealerScore -= 10;
		}
	}

	function playerDrawCard() private {
		uint card = drawCard();
		playerCards.push(Card((randomSeed % 4) + 1, card));

		playerAces += card == 1 ? 1 : 0;
		playerScore += card == 1 ? 11 : Math.min(10, card);

		while (playerScore > 21 && playerAces > 0) {
			playerAces -= 1;
			playerScore -= 10;
		}

	}

	function drawCard() private returns (uint) {
		randomSeed = uint(keccak256(abi.encodePacked(randomSeed)));
		uint card = (randomSeed % 13) + 1;
		return card;
	}

	function new_game() private {
		round += 1;
		currentBet = 0;
		dealerScore = 0;
		dealerAces = 0;
		while (dealerCards.length > 0) {
			dealerCards.pop();
		}
		playerScore = 0;
		playerAces = 0;
		while (playerCards.length > 0) {
			playerCards.pop();
		}
	}

	function end_game() private {
		player = payable(address(0));
	}
}
