default: print
	tar cvf public/docker-challenge.tar -C setup app Dockerfile
	cd setup/app/static/ && zip -r - *.sol --exclude='*flag*' > ../../../public/misc-blackjack.zip
	@echo Challenge compiled.

print:
	@echo Current Flag: $$(cat setup/app/flag)

change: print changeflag clean default print

changeflag:
	$(shell bash -c 'read -p "New Flag: " flag; echo $$flag > setup/app/flag')
	@echo Flag changed.

clean:
	rm -f public/*.tar
	rm -f public/*.zip
	@echo Challenge cleaned.
