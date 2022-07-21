#!/usr/bin/env bash

set -eoux pipefail

SPLIT="***"

cat <<EOF > ATTRIBUTIONS.md
# Attributions

This application uses Open Source components. You can find the source
code of their open source projects along with license information below.
We acknowledge and are grateful to these developers for their contributions
to open source.

## libgit2

Libgit2 was obtained in source-code form from its github repository: 
https://github.com/libgit2/libgit2/

No changes were made to its original source code. 

Copyright notice (https://raw.githubusercontent.com/libgit2/libgit2/main/COPYING):

$(curl --max-time 5 -L https://raw.githubusercontent.com/libgit2/libgit2/main/COPYING)
EOF
