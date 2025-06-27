default: print
	tar cvf public/docker-challenge.tar -C setup app Dockerfile flag.txt supervisord.conf
	cd setup && zip -r - . --exclude='*flag*' > ../public/web-the-missing-essence.zip
	@echo Challenge compiled.

print:
	@echo Current Flag: $$(cat setup/app/flag.txt)

change: print changeflag clean default print

changeflag:
	$(shell bash -c 'read -p "New Flag: " flag; echo $$flag > setup/app/flag.txt')
	@echo Flag changed.

clean:
	rm -f public/docker-challenge.tar
	rm -f public/web-the-missing-essence.zip
	@echo Challenge cleaned.
