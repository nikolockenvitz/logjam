# MITM old browser inside a virtual machine
## Software setup
- Static IPs in docker network for easier configuration
- Virtualbox machine to run the browser
    - For MITM setup, set `machine settings` → `network` → `adapter 1` → `attached to` to `Bridged Adapter` ("Netzwerkbrücke") such that virtual machine gets own IP address
    - For Firefox: Use Ubuntu (I used version 14.04.6 LTS) and download old compiled versions of Firefox from their [FTP server](http://ftp.mozilla.org/pub/firefox/releases/), as the default Firefox 65.0.1 on Ubuntu 14.04.6 LTS is too new
    - For Rekonq browser that also supports 128 bit DH parameters: Run Kubuntu 13.10 as live CD (downloadable from archive.org or in the resource folder of this repository)

## Network setup
```text
                ┌──────────────────────────────────────────────────┐
       ┌────────┤  Host machine                                    │
       │        │ 192.168.178.25                                   │
       │        │   ▲         │                                    │
       │        │   │         │                                    │
       │        │   │   ┌─────▼───────┐    ┌────────────────────┐  │
┌──────┴─┐      │   │   │ Docker MITM ◄────┤ Docker weak-server │  │
│ Router │      │   │   │ 172.22.0.11 │    │    172.22.0.10     │  │
└──────┬─┘      │   │   └─────────────┘    └────────────────────┘  │
       │        │   │                                              │
       │        │  ┌┴───────────────────────┐                      │
       │        │  │   Virtualbox machine   │                      │
       └────────┼──┤ (bridged network mode) │                      │
                │  │     192.168.178.85     │                      │
                │  └────────────────────────┘                      │
                │                                                  │
                └──────────────────────────────────────────────────┘
```

- To get no problems with a self signed SSL certificate, change the `nginx.conf` parameters to use a valid certificate (at this time for example the `www.network-security.net` domain)
- IP addresses of docker components are hardcoded (if you change them you need to adjust several files - a global search and replace could help)
- All other IP addresses may vary per network anyway
- We need to create routing rules at three locations, depicted by the arrows in the above figure:
    1. Route traffic from the Virtualbox machine to the weak-server via the host machine. Therefore, execute in the Virtualbox machine:
        ```sh
        # ip route add 172.22.0.10 via 192.168.178.25
        ```
        If you want to use the C&C JavaScript injection server, also add a routing rule for that machine:
        ```sh
        # ip route add 172.22.0.15 via 192.168.178.25
        ```
    2. Route traffic from the host machine not directly to the weak-server, but via the MITM. Therefore, execute on the host machine:
        ```sh
        # ip route add 172.22.0.10 via 172.22.0.11
        ```
        (The command may file if docker-compose is not started yet.)
    3. Route response traffic from weak-server via MITM. This rule is automatically added by the weak-server. *But you need to adjust the VM IP-address in the weak server's `init.py`!*
- Rules can later be deleted as follows, here for the host machine: `# ip route del 172.22.0.10 via 172.22.0.11`
- For convenience, one can add the following line to the `/etc/hosts` file of the Virtualbox machine (maybe adjust the server name for your valid SSL certificate):
    ```text
    172.22.0.10 www.network-security.net
    ```

## Rekonq browser
- Works with 128 bit DH parameters and cipher suits we need → perfect for local demonstration of attack

### Instructions for setup in live CD
1. Change to German keyboard: `$ setxkbmap de`
2. Add routing rules and `/etc/hosts` entry as described above
3. Disable browser cache and clear history:
    - Set `Configure rekonq...` → `Privacy` → `Remove history items:` to `At application exit`
    - Disable the checkbox `Configure rekonq...` → `Privacy` → `Manage Cache` → `Use cache`
4. Open weak-server's webpage
5. Go inside "shell command and control" server (`$ sudo docker exec -it cc /bin/bash`) and start the C&C server (`start-cc`). Now, a visit of the `counter.html` page should connect to the C&C server.

## Firefox versions
- According to our research, Firefox 38 should be the last version that works with export ciphers
- Firefox 35.0.1 works for pure network sniffing with 512 bit DH
    - Traffic manipulation not yet possible, as Firefox refuses 128 and 256 bit DH parameters and we did not yet broke the 512 bit group
    - Self signed erver certificate needs to be trusted manually; TODO: use Dörrs certificate

## Experiments with Konqueror v4.13.3 (year 2008)
- Does not work well with 128 bit DH parameters (at least in cipher suite combinations we need for our attack)

