# proxy-for-windows-app

## Selective proxying on Windows

`tun2socks` now supports selective routing by process name:

```powershell
.\tun2socks.exe `
  --device wintun://mytun `
  --proxy socks5://127.0.0.1:1080 `
  --proxy-processes chrome.exe,telegram.exe
```

With `--proxy-processes` enabled:

- matching applications use the configured proxy;
- all other applications are sent directly;
- process matching is case-insensitive and currently works on Windows IPv4 flows.

## GUI workflow

`netmonitor-gui` now lets you configure selective proxying without editing command-line flags:

1. Enter the proxy URL and TUN device name.
2. Click rows in the live process table, or drag an `.exe` / `.lnk` into the window, to choose applications.
3. Click **Запустить** to launch the bundled `tun2socks.exe` with the selected process list.

The GUI stores local settings in `netmonitor-gui/proxy_config.json`.

## Local builds in restricted environments

When the normal Go build cache is not writable, use a project-local cache:

```powershell
New-Item -ItemType Directory -Force .cache\go-build | Out-Null
$env:GOCACHE = (Resolve-Path '.cache\go-build')
go build .
```

`tun2socks` currently requires Go 1.25, so a machine with only Go 1.24.x will still need the newer toolchain available.
