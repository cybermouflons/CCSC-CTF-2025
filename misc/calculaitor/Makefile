default: print
	tar cvf public/docker-challenge.tar -C setup app ai Dockerfile supervisord.conf
	cd setup && zip -r - . --exclude='*flag*' > ../public/misc-calculaitor.zip
	# add fake flag on zip
	mkdir -p ./setup/tmp/app
	cd setup/tmp && echo "ECSC{example_flag}" > ./app/flag.txt
	cd setup/tmp && zip -ur ../../public/misc-calculaitor.zip app/flag.txt
	rm -r setup/tmp
	
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
