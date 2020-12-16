# Reporter karton service

Uploads samples and static configs to malwaredb

Author: CERT.pl

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
