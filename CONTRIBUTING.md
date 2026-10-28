# Contributing

Open an issue for a bug or a proposed detection rule. Include the command, operating system, Python version, and expected behavior. Use synthetic examples; never paste real credentials or sensitive source files into issues.

For a change:

1. Create a branch and install with `python -m pip install -e .`.
2. Add a regression test using synthetic strings assembled at runtime.
3. Run `python -m unittest discover -s tests -v`.
4. Open a pull request describing the behavior change and how you checked it.

Detection rules should document likely false positives. Keep output redacted, preserve exit-code meanings, and avoid sending file content over the network.
