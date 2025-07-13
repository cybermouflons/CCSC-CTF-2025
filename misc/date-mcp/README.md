# Date MCP

[![Try in PWD](https://raw.githubusercontent.com/play-with-docker/stacks/master/assets/images/button.png)](https://labs.play-with-docker.com/?stack=https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2025/master/misc/date-mcp/docker-compose.yml)


**Category**: misc

**Author**: [GramThanos](https://github.com/GramThanos)

## Description

Hey! I just set up an MCP server so that your AIs know that you are playing CTFs at 2am... lol!


Author: GramThanos


## Run locally

Launch challenge:
```
curl -sSL https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2025/master/misc/date-mcp/docker-compose.yml | docker compose -f - up -d
```

Shutdown challenge:
```
curl -sSL https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2025/master/misc/date-mcp/docker-compose.yml | docker compose -f - down
```
