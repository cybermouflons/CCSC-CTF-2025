# Station Maintenace

[![Try in PWD](https://raw.githubusercontent.com/play-with-docker/stacks/master/assets/images/button.png)](https://labs.play-with-docker.com/?stack=https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2025/master/pwn/station-maintance/docker-compose.yml)


**Category**: pwn

**Author**: [r3dsh3rl0ck](https://github.com/R3dSh3rl0ck)

## Description

Maintain the station using our standard maintenance app. A recent system patch has locked a flag within the station's database. Access the app, bypass the security measures, and retrieve the flag before the system fully reboots.


Author: r3dsh3rl0ck


## Run locally

Launch challenge:
```
curl -sSL https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2025/master/pwn/station-maintance/docker-compose.yml | docker compose -f - up -d
```

Shutdown challenge:
```
curl -sSL https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2025/master/pwn/station-maintance/docker-compose.yml | docker compose -f - down
```
