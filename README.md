# Reporter karton service

Uploads samples and static configs to malwaredb

**Author**: CERT.pl

**Maintainers**: psrok1, nazywam

**Consumes:**
```
{
    "type": "sample",
    "stage": "recognized" || "analyzed"
},
{
    "type": "config"
},
{
    "type": "blob"
}
```

**Produces:**
```
(nothing)
```


## Usage

First of all, make sure you have setup the core system: https://github.com/CERT-Polska/karton

Modify your `karton.ini` config to include information about your mwdb-core instance and reporter credentials:

```ini
[mwdb]
api_url = http://mwdb.my-awesome-org/api/
api_key = eyJhYWF....
```

Instead of providing `api_key` you can also use `username`/`password` but password-authenticated sessions are short-lived and service will need to re-auth from time to time.


Then install karton-mwdb-reporter from PyPi:

```shell
$ pip install karton-mwdb-reporter

$ karton-mwdb-reporter
```

![Co-financed by the Connecting Europe Facility by of the European Union](https://www.cert.pl/uploads/2019/02/en_horizontal_cef_logo-e1550495232540.png)