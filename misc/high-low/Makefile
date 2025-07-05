default: print
	tar cvf public/docker-challenge.tar -C setup server Dockerfile run_game.sh
	cd setup/app && zip -r - . --exclude='*flag*' > ../../public/misc-high-low.zip
	@echo Challenge compiled.

print:
	@echo Current Flag: $$(cat setup/server/flag.txt)

change: print changeflag clean default print

changeflag:
	$(shell bash -c 'read -p "New Flag: " flag; echo $$flag > setup/server/flag.txt')
	@echo Flag changed.

clean:
	rm -f public/*.tar
	rm -f public/*.zip
	@echo Challenge cleaned.
