default: print
	tar cvf public/docker-challenge.tar -C setup app Dockerfile
	cd setup/app && zip -r - . --exclude='*flag*' > ../../public/crypto-gamble-auction.zip
	@echo Challenge compiled.

print:
	@echo Current Flag: $$(cat setup/app/flag.txt)
	@echo Description: I hope you have enough time for this. Good luck!

clean:
	rm -f public/*.zip
	rm -f public/*.tar
	@echo Challenge cleaned.
