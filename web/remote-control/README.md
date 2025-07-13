# Remote Control

[![Try in PWD](https://raw.githubusercontent.com/play-with-docker/stacks/master/assets/images/button.png)](https://labs.play-with-docker.com/?stack=https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2025/master/web/remote-control/docker-compose.yml)


**Category**: web

**Author**: [GramThanos](https://github.com/GramThanos)

## Description

We can now monitor our server securely.


Author: GramThanos


## Run locally

Launch challenge:
```
curl -sSL https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2025/master/web/remote-control/docker-compose.yml | docker compose -f - up -d
```

Shutdown challenge:
```
curl -sSL https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2025/master/web/remote-control/docker-compose.yml | docker compose -f - down
```
