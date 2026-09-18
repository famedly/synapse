# Modules API

This API returns the currently loaded modules (name and version).

The api is:

```
GET /_synapse/admin/v1/modules
```

It returns a JSON body like the following:

```json
{
    "modules": [
        {
            "module_name": "mjolnir.antispam.Module",
            "package_name": "mjolnir"
            "version": "1.2.3"
        }
    ]
}
```
