# cloudflare-mtls-ocsp

This is a test script to add an OCSP verification option for Cloudflare mTLS client certificates. It can be attached to Cloudflare proxy endpoints protected by API Shield or Access mTLS with BYO CA.

Created for testing purpose. Do not use it in production.

## Prerequisite 
### Package installation
asn1js and pkijs
### Cloudflare configuration (via API)
Forward a client certificate to this Worker via `cf-client-cert-der-base64` request header.
https://developers.cloudflare.com/ssl/client-certificates/enable-mtls/#forward-a-client-certificate
```
  --data '{
    "settings": [
        {
            "hostname": "<HOSTNAME>",
            "client_certificate_forwarding": true
        }
    ]
}'
```
### Edit wrangler.toml
`routes`:
replace it with your mTLS application URL

`vars`: 
`CA_CLIENT_ISSUER` - replace it with your client certificate issuer - BASE64
`CA_OCSP_ROOT` - replace it with your OCSP responder's issuer - BASE64
* remove `BEGIN/END lines` and `EOL (e.g. LF)` from a PEM to create a one-liner 
* e.g. ""MIID....76"
