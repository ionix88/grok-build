# Shell completions

Generate completions from the packaged binary:

```sh
orca completions bash
orca completions zsh
orca completions fish
orca completions powershell
```

Scripts always use the public name **`orca`**. Installers may write them under the product config directory; generation itself is side-effect free (no network or auth).
