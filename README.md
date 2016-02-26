# ssl-checker
Report the status of SSL certificates over HTTP. Useful for monitoring your certificates with services such as Uptime Robot.

```
Usage:
  -listenAddr="0.0.0.0:10000": the address to listen on
  -warningDuration=168h0m0s: how long until expiry before a certificate enters 'warning' state
  -watch="./**/cert.pem": the directories to check for certificates
```
