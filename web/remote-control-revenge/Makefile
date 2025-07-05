default: print
	tar cvf public/docker-challenge.tar -C setup app flag.txt Dockerfile
	cd setup && zip -r - . --exclude='*flag*' > ../public/web-remote-control-revenge.zip
	@echo Challenge compiled.

print:
	@echo Current Flag: $$(cat setup/flag.txt)

change: print changeflag clean default print

changeflag:
	$(shell bash -c 'read -p "New Flag: " flag; echo $$flag > setup/flag.txt')
	@echo Flag changed.

clean:
	rm -f public/*.tar
	rm -f public/*.zip
	@echo Challenge cleaned.
