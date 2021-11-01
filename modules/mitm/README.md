# mitm

This Docker container runs a Python script to manipulate the connection between `weak-client` and `weak-server`.
The Docker containers are set up in a way, that all traffic between these two passes via the `mitm`.
The packets are passed to the Python script using `iptables` and `nfqueue`.
Parsing IP and TCP packets is done using `scapy`.
The parsing and manipulation of the TLS messages is implemented in `tls.py`.

If you want to prevent the MITM from manipulating the TLS content, you can set the `tls_only_log_bytes` flag in line 12 of `init.py` to `True`.
This will only log the TLS message bytes (no parsing).
