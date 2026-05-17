# proxy-for-windows-app

## Single executable workflow

The application is distributed as one executable: `proxy-for-windows-app.exe`.

Inside that single binary:

- the GUI is embedded;
- the proxy engine is embedded;
- each shortcut can be assigned its own proxy;
- only apps launched from the GUI are routed through their assigned proxy, while unrelated apps go directly.

## Current workflow

1. Add one or more proxies.
2. Add an application shortcut from the Start Menu catalog or by choosing an `.exe`.
3. Assign a proxy to each shortcut.
4. Double-click a shortcut to launch a new process and bind that launched process tree to the selected proxy.
5. Reorder shortcuts by drag-and-drop or remove them from the list.

Local settings are stored next to the executable in `proxy_config.json`.

## Important boundary

This is a one-file launcher with selective routing, not a full Windows sandbox.  
It routes the launched process tree by PID so an already-running unrelated instance is not automatically affected, but applications that intentionally reuse an existing instance may still need app-specific launch arguments to behave as a truly separate instance.

## Local builds in restricted environments

When the normal Go build cache is not writable, use a project-local cache:

```powershell
New-Item -ItemType Directory -Force .cache\go-build | Out-Null
$env:GOCACHE = (Resolve-Path '.cache\go-build')
go build .
```

The combined application currently requires Go 1.25 to build because the embedded `tun2socks` module requires it.
