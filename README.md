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

Then install karton-mwdb-reporter from PyPi:

```shell
$ pip install karton-mwdb-reporter

$ karton-mwdb-reporter
```

![Co-financed by the Connecting Europe Facility by of the European Union](https://www.cert.pl/wp-content/uploads/2019/02/en_horizontal_cef_logo-1.png)