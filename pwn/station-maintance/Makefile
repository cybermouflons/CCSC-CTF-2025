default: print
	tar cvf public/docker-challenge.tar -C setup app Dockerfile
	#cd setup/app && zip -r ../../public/pwn-station-maintenance.zip ./station-maintenance ./glibc/libc.so.6 ./glibc/ld-linux-x86-64.so.2
	@echo Challenge compiled.
print:
	@echo Current Flag: $$(cat setup/app/flag.txt)
change: print changeflag clean default print
changeflag:
	$(shell bash -c 'read -p "New Flag: " flag; echo $$flag > setup/app/flag.txt')
	@echo Flag changed.
clean:
	-rm -f public/docker-challenge.tar
	#-rm -f public/pwn-station-maintenance.zip
	@echo Challenge cleaned.
