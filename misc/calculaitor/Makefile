default: print
	tar cvf public/docker-challenge.tar -C setup app ai Dockerfile supervisord.conf
	cd setup && zip -r - . --exclude='*flag*' > ../public/misc-calculaitor.zip
	@echo Challenge compiled.

print:
	@echo Current Flag: $$(cat setup/app/flag.txt)

change: print changeflag clean default print

changeflag:
	$(shell bash -c 'read -p "New Flag: " flag; echo $$flag > setup/app/flag.txt')
	@echo Flag changed.

clean:
	rm -f public/docker-challenge.tar
	rm -f public/misc-calculaitor.zip
	@echo Challenge cleaned.
