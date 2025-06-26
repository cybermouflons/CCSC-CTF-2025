default: print
	tar cvf dist/docker-challenge.tar -C src app Dockerfile
	cd src/app && zip -r - . --exclude='*flag*' > ../../dist/crypto-this-is-different.zip
	@echo Challenge compiled.

print:
	@echo Current Flag: $$(cat src/app/flag.txt)
	@echo Description: I hope you have enough time for this. Good luck!

clean:
	rm -f dist/*.zip
	rm -f dist/*.tar
	@echo Challenge cleaned.
