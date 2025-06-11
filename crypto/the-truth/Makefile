default: print
	cd src && python3 ./generate.py
	cd src && zip -r - encrypted.txt > ../dist/crypto-the-truth.zip
	@echo Challenge compiled.

print:
	@echo Current Flag: $$(cat src/flag.txt)

change: print changeflag clean default print

changeflag:
	$(shell bash -c 'read -p "New Flag: " flag; echo $$flag > src/flag.txt')
	@echo Flag changed.

clean:
	-rm -f dist/crypto-the-truth.zip
	-rm -f src/encrypted.txt
	@echo Challenge cleaned.
