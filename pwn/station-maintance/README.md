# Station Maintenace

[![Try in PWD](https://raw.githubusercontent.com/play-with-docker/stacks/master/assets/images/button.png)](https://labs.play-with-docker.com/?stack=https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2024/master/pwn/station-maintance/docker-compose.yml)


**Category**: pwn

**Author**: Mike Takaronis <mtakaronis@ssl-unipi.gr>

## Description

Maintain the station using our standard maintenance app. A recent system patch has locked a flag within the station's database. Access the app, bypass the security measures, and retrieve the flag before the system fully reboots.


## Run locally

Launch challenge:
```
curl -sSL https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2024/master/pwn/station-maintance/docker-compose.yml | docker compose -f - up -d
```

Shutdown challenge:
```
curl -sSL https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2024/master/pwn/station-maintance/docker-compose.yml | docker compose -f - down
```
