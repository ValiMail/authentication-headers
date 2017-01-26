#!/usr/bin/env python3

# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the author be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
#
# Copyright (c) 2017 Valimail Inc
# Contact: Gene Shuman <gene@valimail.com>
#

import sys
from authheaders import authenticate_message

if len(sys.argv) != 5:
    print("Usage: authenticate_message.py authserv_id ip mail_from helo")
    sys.exit(1)

if sys.version_info[0] >= 3:
    # Make sys.stdin a binary stream.
    sys.stdin = sys.stdin.detach()    

message = sys.stdin.read()
res = authenticate_message(message, sys.argv[1], ip=sys.argv[2], mail_from=sys.argv[3], helo=sys.argv[4])

for line in res:
  sys.stdout.write(line)

sys.stdout.write("\n")
