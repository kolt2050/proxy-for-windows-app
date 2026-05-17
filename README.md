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
