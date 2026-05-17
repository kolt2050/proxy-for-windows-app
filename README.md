# proxy-for-windows-app

## Single executable workflow

The application is intended to be distributed as one executable: `proxy-for-windows-app.exe`.

Inside that single binary:

- the GUI is embedded;
- the proxy engine is embedded;
- selected applications are proxied while all others go directly.

The GUI lets you configure selective proxying without editing command-line flags:

1. Enter the proxy URL and TUN device name.
2. Click rows in the live process table, or drag an `.exe` / `.lnk` into the window, to choose applications.
3. Click **Запустить** to start the built-in proxy engine with the selected process list.

The GUI stores local settings in `netmonitor-gui/proxy_config.json`.

## Local builds in restricted environments

When the normal Go build cache is not writable, use a project-local cache:

```powershell
New-Item -ItemType Directory -Force .cache\go-build | Out-Null
$env:GOCACHE = (Resolve-Path '.cache\go-build')
go build .
```

The combined application currently requires Go 1.25 to build because the embedded `tun2socks` module requires it.
