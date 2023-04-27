# Reporter karton service

Uploads samples and static configs to malwaredb

**Author**: CERT.pl

**Maintainers**: psrok1, nazywam

**Consumes:**
```
{
    "type": "sample",
    "stage": "recognized" || "analyzed" || "unrecognized"
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


## Configuration

Using the `--report-unrecognized` flag you specify whether the reporter should upload files unrecognized by the classifier. You can also configure this using the built-in configuration backend by either adjusting it in the karton.ini

```ini
[mwdb-reporter]
report_unrecognized=true
```

or setting the environmental variable like so `KARTON_MWDB-REPORTER_REPORT_UNRECOGNIZED=true`.

To learn more about configuring your karton services, take a look at [karton configuration docs](https://karton-core.readthedocs.io/en/latest/service_configuration.html)


![Co-financed by the Connecting Europe Facility by of the European Union](https://www.cert.pl/uploads/2019/02/en_horizontal_cef_logo-e1550495232540.png)
