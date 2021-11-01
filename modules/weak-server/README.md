# Setup

## Create DH Params

```bash
$ openssl dhparam -out dhparams/dhparam-512.pem 512
```

You can configure the used DH params in `nginx.conf` with `ssl_dhparam /etc/nginx/ssl/dhparam-128.pem;`.

## Create Certificate

```bash
$ openssl req -x509 -newkey rsa:4096 \
 -keyout cert/key.pem -out cert/cert.pem -days 365 -nodes \
 -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.weak-server.com"
```
