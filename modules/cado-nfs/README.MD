# Run cado-nfs
root@f1e5b78acf9b:/home/cado-nfs# ./installed/bin/cado-nfs.py 90377629292003121684002147101760858109247336549001090677693

# Helpful (docker) commands
- `export-ciphers-tls/modules/cado-nfs# docker build -t cadodocker .`
- `export-ciphers-tls/modules/cado-nfs# docker run -it cadodocker bash`
    - In the docker container, run `python3 master.py &` and `python3 client.py`. You find these scripts in the `/opt` folder.
