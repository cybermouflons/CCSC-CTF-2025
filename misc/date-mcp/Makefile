default: print
	tar cvf public/docker-challenge.tar -C setup server Dockerfile
	cd setup && zip -r - . --exclude='*flag*' > ../public/misc-date-mcp.zip
	# add fake flag on zip
	mkdir -p ./setup/tmp/server
	cd setup/tmp && echo "ECSC{example_flag}" > ./server/flag.txt
	cd setup/tmp && zip -ur ../../public/misc-date-mcp.zip server/flag.txt
	rm -r setup/tmp
	
	@echo Challenge compiled.

print:
	@echo Current Flag: $$(cat setup/server/flag.txt)

change: print changeflag clean default print

changeflag:
	$(shell bash -c 'read -p "New Flag: " flag; echo $$flag > setup/server/flag.txt')
	@echo Flag changed.

clean:
	rm -f public/docker-challenge.tar
	rm -f public/misc-date-mcp.zip
	@echo Challenge cleaned.
