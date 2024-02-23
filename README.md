# Prepareation
Copy dualnpsextension.dll and config.json to a folder on NPS server.

# Sample config.json

```
{
	"das_host": "nano190013.bletchley19.com",
    "das_port": 8071,
    "domain":"bletchley19.com",
    "application":"winlogon",
    "client_key":"c:\\temp\\client_cert.key",
    "client_cer":"c:\\temp\\client_cert.cer",
    "log_level":6,
	"ttl": 120
}
```

`client_cert` is the un-encrypted agent certificate (PEM format) which is used for client certificate authentication.
You can get it from `DAC`

```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4KL7Vwesrr+MkKXbxtgCGvCyX+nSBm/Wmkx8lY9LpXM1Ldu1
...
q7l0B1kKEhNPQSJiz8gTAzr7c6iP7T3dvy6DTpGrf5NajbLmX5eh
-----END RSA PRIVATE KEY-----
```


```
-----BEGIN CERTIFICATE-----
MIIDWDCCAsGgAwIBAgIGAXyJ0orTMA0GCSqGSIb3DQEBCwUAMEMxCzAJBgNVBAYT
...
XXFBMi/QEb9fQY9HnHZ/Gr94GkWMEP5rn8UwWqHFGnyOBssIIuU0VFFUqkw=
-----END CERTIFICATE-----

```

# Register DLL

`regsvr32 dualnpsextension.dll`

# Unregister DLL

`regsvr32 /u dualnpsextension.dll`