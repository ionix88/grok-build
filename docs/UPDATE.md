# Updating Orca

```sh
orca update            # install latest allowed host version
orca update --check    # report without installing
orca --version
```

Host update replaces only receipt-listed host files. It does not change plugin activation, defaults, pins, or private runtimes.

There is no public `grok` or `orca-grok` updater command.
