default: print
	tar cvf public/docker-challenge.tar -C setup Dockerfile zer0cool flag.txt ld ld-linux-x86-64.so.2 libc  libc.so.6
	@echo Challenge compiled.
print:
	@echo Current Flag: $$(cat setup/flag.txt)
change: print changeflag clean default print
changeflag:
	$(shell bash -c 'read -p "New Flag: " flag; echo $$flag > setup/flag.txt')
	@echo Flag changed.
clean:
	-rm -f public/docker-challenge.tar
	@echo Challenge cleaned.
