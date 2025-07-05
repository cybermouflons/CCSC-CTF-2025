default: print
	tar cvf public/docker-challenge.tar -C setup gatekeeper-foundry checker.py Dockerfile entrypoint.sh rpc_proxy.py
	@echo Challenge compiled.

print:
	#@echo Current Flag: $$(cat setup/app/flag.txt)
	@echo No flag to print

change: print changeflag clean default print

changeflag:
	#$(shell bash -c 'read -p "New Flag: " flag; echo $$flag > setup/app/flag.txt')
	@echo Flag cant be changed.

clean:
	rm -f public/*.tar
	@echo Challenge cleaned.
