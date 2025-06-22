default: print
	tar cvf public/docker-challenge.tar -C src app Dockerfile
	cd src/app && zip -r - log-recorder --exclude='*flag*' > ../../public/log-recorder.zip
	@echo Challenge compiled.
print:
	@echo Current Flag: $$(cat src/app/flag.txt)
change: print changeflag clean default print
changeflag:
	$(shell bash -c 'read -p "New Flag: " flag; echo $$flag > src/app/flag.txt')
	@echo Flag changed.
clean:
	-rm -f public/docker-challenge.tar
	-rm -f public/log-recorder.zip
	@echo Challenge cleaned.
