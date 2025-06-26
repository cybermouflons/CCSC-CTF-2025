default: print
	tar cvf public/docker-challenge.tar -C setup app Dockerfile
	cd setup/app && zip -r - log-recorder --exclude='*flag*' > ../../public/pwn-log-recorder.zip
	@echo Challenge compiled.
print:
	@echo Current Flag: $$(cat setup/app/flag.txt)
change: print changeflag clean default print
changeflag:
	$(shell bash -c 'read -p "New Flag: " flag; echo $$flag > setup/app/flag.txt')
	@echo Flag changed.
clean:
	-rm -f public/docker-challenge.tar
	-rm -f public/pwn-log-recorder.zip
	@echo Challenge cleaned.
