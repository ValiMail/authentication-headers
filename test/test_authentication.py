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

import unittest

import sys
from authheaders import authenticate_message

#import logging
#logging.basicConfig(level=10)

class TestAuthenticateMessage(unittest.TestCase):
    def setUp(self):
        records = {b"google2048._domainkey.valimail.com.": "v=DKIM1\; k=rsa\; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg1i2lO83x/r58cbo/JSBwfZrrct6S/yi4L6GsG3wNgFE9lO3orzBwnAEJJM33WrvJfOWia1fAx64Vs1QEpYtLFCzyeIhDDMaHv/G8NgKPgnWK4gI8/x2Q2SYCmiqil66oHaSOC2phMDRI+c/Q35MlZbc2FqlgevpKzdCg+YE6mYA0XN7/tdQplbx4meLVsVPI" "L9QCP4yu8oBsNqcwyxkQafJucVyoZI+VEO+dySw3QXNdmJhr7y1hD1tCNqoAG0iphKQVXPXmGnGhaxaVU92Kq5UKL6/LiTZ1piqyJfJyZ/zCgH+mtY8MNk9f7LHpwFljI7TbYmr7MmV3d6xj3sghwIDAQAB",
                   b"_dmarc.valimail.com.": "v=DMARC1\; p=reject\; rua=mailto:dmarc.reports@valimail.com,mailto:dmarc_agg@vali.email\; ruf=mailto:dmarc.reports@valimail.com,mailto:dmarc_c0cb7153_afrf@vali.email"}
    
        self.dnsfunc = records.get
        
    def test_authenticate_dkim(self):
        msg = b"""DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=valimail.com; s=google2048;
        h=mime-version:from:date:message-id:subject:to;
        bh=3VWGQGY+cSNYd1MGM+X6hRXU0stl8JCaQtl4mbX/j2I=;
        b=gntRk4rCVYIGkpO09ROkbs3n4YSIcp/Pi7tUnSIgs8uS+uZ2a77dG+/qlSvnk+mWET
         IBrkt1YpDzev/0ITTDy/zgTHjPiQIFcg9Q+3hn3sTz8ExCyM8/YYgoPqSs3oUXn3jwXk
         N/wpMuF29LTVp1gpkYzaoCDNPGd1Wag6Vh2lw65S7ruECCAdBm5XeSnvTOzIC0E/jmEt
         3hvaPiKAohCAsC5JAN89EATPOjnYJL4Q6X6p2qUsusz/8tkHuYvReHmxQkjQ0/N3fPP0
         6VfkIrPOHympq6qDUizbjiBmgiMWKnarrptblJvyt66/aIHx+QamP6LUA+/RUFY1q7TG
         MSDg==
MIME-Version: 1.0
From: Gene Shuman <gene@valimail.com>
Date: Wed, 25 Jan 2017 16:13:31 -0800
Message-ID: <CANtLugNVcUMfjVH22FN=+A6Y_Ss+QX_=GnJ3xGfDY1iuEbbuRA@mail.gmail.com>
Subject: Test
To: geneshuman@gmail.com
Content-Type: text/plain; charset=UTF-8

This is a test!
"""
        res = authenticate_message(msg, "example.com", spf=False, dmarc=False, dnsfunc=self.dnsfunc)
        self.assertEqual(res, "Authentication-Results: example.com; dkim=pass header.d=valimail.com")


    def test_authenticate_dmarc(self):
        msg = b"""DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=valimail.com; s=google2048;
        h=mime-version:from:date:message-id:subject:to;
        bh=3VWGQGY+cSNYd1MGM+X6hRXU0stl8JCaQtl4mbX/j2I=;
        b=gntRk4rCVYIGkpO09ROkbs3n4YSIcp/Pi7tUnSIgs8uS+uZ2a77dG+/qlSvnk+mWET
         IBrkt1YpDzev/0ITTDy/zgTHjPiQIFcg9Q+3hn3sTz8ExCyM8/YYgoPqSs3oUXn3jwXk
         N/wpMuF29LTVp1gpkYzaoCDNPGd1Wag6Vh2lw65S7ruECCAdBm5XeSnvTOzIC0E/jmEt
         3hvaPiKAohCAsC5JAN89EATPOjnYJL4Q6X6p2qUsusz/8tkHuYvReHmxQkjQ0/N3fPP0
         6VfkIrPOHympq6qDUizbjiBmgiMWKnarrptblJvyt66/aIHx+QamP6LUA+/RUFY1q7TG
         MSDg==
MIME-Version: 1.0
From: Gene Shuman <gene@valimail.com>
Date: Wed, 25 Jan 2017 16:13:31 -0800
Message-ID: <CANtLugNVcUMfjVH22FN=+A6Y_Ss+QX_=GnJ3xGfDY1iuEbbuRA@mail.gmail.com>
Subject: Test
To: geneshuman@gmail.com
Content-Type: text/plain; charset=UTF-8

This is a test!
"""
        res = authenticate_message(msg, "example.com", spf=False, dnsfunc=self.dnsfunc)
        self.assertEqual(res, "Authentication-Results: example.com; dkim=pass header.d=valimail.com; dmarc=pass header.from=valimail.com")

        
        
if __name__ == '__main__':
    unittest.main()
