default: print
	-cd setup/app && rm pwnb0t && rm -r glibc
	cd setup/app && cp ../build/pwnb0t . && cp -r ../build/glibc .
	tar cvf public/docker-challenge.tar -C setup app Dockerfile
	cd setup/app && zip -r ../../public/pwnb0t.zip ./pwnb0t ./glibc/libc.so.6 ./glibc/ld.so.2
	@echo Challenge compiled.
print:
	@echo Current Flag: $$(cat setup/app/flag.txt)
change: print changeflag clean default print
changeflag:
	$(shell bash -c 'read -p "New Flag: " flag; echo $$flag > setup/app/flag.txt')
	@echo Flag changed.
clean:
	-rm setup/app/pwnb0t
	-rm -r setup/app/glibc
	-rm -f public/docker-challenge.tar
	-rm -f public/pwnb0t.zip
	@echo Challenge cleaned.
