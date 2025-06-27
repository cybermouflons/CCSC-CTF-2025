default: print
	mkdir -p public
	tar cvf public/docker-challenge.tar -C setup challenge Dockerfile
	@echo Challenge compiled.

print:
	@echo Current Flag: $$(cat setup/challenge/flag.txt)

change: print changeflag clean default print

changeflag:
	$(shell bash -c 'read -p "New Flag: " flag; echo $$flag > setup/challenge/flag.txt')
	@echo Flag changed.

clean:
	rm -f public/docker-challenge.tar
	@echo Challenge cleaned.
