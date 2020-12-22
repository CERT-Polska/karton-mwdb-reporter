# Reporter karton service

Uploads samples and static configs to malwaredb

Author: CERT.pl

Maintainers: psrok1, nazywam

**Consumes:**
```
{
    "type": "sample",
    "stage": "recognized" || "analyzed"
},
{
    "type": "config"
}
```

**Produces:**
```
(nothing)
```
