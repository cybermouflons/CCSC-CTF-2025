default: print
	#cd setup && ./setup.sh
	cd setup && zip -r - chall > ../public/rev-just-a-key.zip
	@echo Challenge compiled.

print:
	@echo Current Flag: $$(cat setup/flag.txt)

change: print changeflag clean default print

changeflag:
	$(shell bash -c 'read -p "New Flag: " flag; echo $$flag > setup/flag.txt')
	@echo Flag changed.

clean:
	rm -f public/rev-just-a-key.zip
	@echo Challenge cleaned.
