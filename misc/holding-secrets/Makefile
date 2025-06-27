default: print
	mkdir -p public
	tar cvf public/docker-challenge.tar -C setup Dockerfile flag.st prep.sh run.sh
	@echo Challenge compiled.
print:
	#@echo Current Flag: $$(cat setup/flag.txt)
	@echo Can not print flag
change: print changeflag clean default print
changeflag:
	#$(shell bash -c 'read -p "New Flag: " flag; echo $$flag > setup/flag.txt')
	#@echo Flag changed.
	@echo Can not change flag
clean:
	-rm -f public/docker-challenge.tar
	@echo Challenge cleaned.
