This folder contains subdirectories for each component.
Each is a Docker container.

Run with
`sudo docker-compose up`

| Component     | Description                                                                                                                                    |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| weak-server   | Server using a weak configuration (e.g. 128 bit DH prime)                                                                                      |
| weak-client   | Client that accepts weak DH groups                                                                                                             |
| mitm          | Python script to actively downgrade TLS connections and manipulate content                                                                     |
| cado-nfs      | Container to run cado-nfs and compute the discrete log for server's ephemeral public keys. Listens on cado:5000, see `mitm/cado_nfs_helper.py` |
| demo-shell-cc | Command and control server that can send JavaScript code to the client's browser if corresponding code was injected by mitm                    |

To manually send requests from the `weak-client` that will be intercepted by the `mitm`, connect to it via `docker exec -it client /bin/bash` and use the aliases defined in the `weak-client`'s dockerfile, e.g. `openssl-connect-main`.

The server hosts several web pages / applications that show how the Logjam attack can be used for exploits.

| Path          | Application + Exploit                                                      |
| ------------- | -------------------------------------------------------------------------- |
| /             | HTML page; minor modifcation of the content                                |
| /counter.html | Simple JavaScript counter; mitm injects JavaScript code for a remote shell |
| /flask/login  | Login page; mitm sniffs content and retrieves login credentials            |

To access the webpages not only from the command line but from a web browser, find setup instructions for a VM in `docs/MITM_old_browser_in_VM.md`.
