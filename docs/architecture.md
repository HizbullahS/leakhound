# Architecture

```text
CLI arguments
    ├── --path         → filesystem traversal
    ├── --staged       → Git index blobs
    └── --install-hook → non-overwriting hook installer
                              ↓
                    UTF-8 / size checks
                              ↓
              format rules + Shannon entropy
                              ↓
              redacted findings + exit status
```

`leakhound/cli.py` selects inputs and prints reports. Git is invoked with argument lists, without a shell. Staged paths are NUL-delimited, and blob data comes from the index rather than the working tree. Git errors fail the scan instead of looking like an empty index.

`leakhound/detector.py` contains pure detection functions. Rules are compiled once. Pattern spans suppress overlapping entropy findings, and finding previews never contain source values.

`leakhound/hooks.py` asks Git for its hook path, including custom `core.hooksPath` settings. Exclusive file creation refuses to overwrite an existing hook. The hook returns the scanner's exit code and fails if the scanner is unavailable.

The scanner does not make network requests. Package installation and Git operations such as cloning or pushing are separate operations that may use the network.
