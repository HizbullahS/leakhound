#!/usr/bin/env bash
set -e

HOOK_PATH=".git/hooks/pre-commit"

if [ ! -d ".git" ]; then
    echo "Error: Run this from the root of your Git repository."
    exit 1
fi

cat << 'EOF' > "$HOOK_PATH"
#!/usr/bin/env bash
# Runs leakhound over staged files
leakhound --staged
EOF

chmod +x "$HOOK_PATH"
echo "Pre-commit hook successfully installed at $HOOK_PATH"
