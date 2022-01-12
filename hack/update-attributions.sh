#!/usr/bin/env bash

set -eoux pipefail

SPLIT="***"

cat <<EOF > ATTRIBUTIONS.md
# Attributions

This application uses Open Source components. You can find the source
code of their open source projects along with license information below.
We acknowledge and are grateful to these developers for their contributions
to open source.

## libssh2

Libssh2 was obtained in source-code form from its github repository: 
https://github.com/libssh2/libssh2/

No changes were made to its original source code. 

Copyright notice (https://raw.githubusercontent.com/libssh2/libssh2/master/COPYING):

$(curl --max-time 5 -L https://raw.githubusercontent.com/libssh2/libssh2/master/COPYING)

${SPLIT}

## libgit2

Libgit2 was obtained in source-code form from its github repository: 
https://github.com/libgit2/libgit2/

No changes were made to its original source code. 

Copyright notice (https://raw.githubusercontent.com/libgit2/libgit2/main/COPYING):

$(curl --max-time 5 -L https://raw.githubusercontent.com/libgit2/libgit2/main/COPYING)

${SPLIT}

## zlib

Zlib was obtained in binary form via official distribution channels.
No changes were made to its original source code. 

Copyright notice (https://zlib.net/zlib_license.html):

 /* zlib.h -- interface of the 'zlib' general purpose compression library
  version 1.2.11, January 15th, 2017

  Copyright (C) 1995-2017 Jean-loup Gailly and Mark Adler

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Jean-loup Gailly        Mark Adler
  jloup@gzip.org          madler@alumni.caltech.edu

*/
EOF
