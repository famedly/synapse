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
            "name": "my_module.MyModule",
            "version": "1.2.3"
        }
    ]
}
```
