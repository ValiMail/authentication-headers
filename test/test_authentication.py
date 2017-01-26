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
from authheaders import authenticate_message, sign_message

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

class TestSignMessage(unittest.TestCase):        
    def test_arc_sign(self):
        msg = b"""MIME-Version: 1.0
Return-Path: <jqd@d1.example.org>
Received: by 10.157.14.6 with HTTP; Tue, 3 Jan 2017 12:22:54 -0800 (PST)
Message-ID: <54B84785.1060301@d1.example.org>
Date: Thu, 14 Jan 2015 15:00:01 -0800
From: John Q Doe <jqd@d1.example.org>
To: arc@dmarc.org
Subject: Example 1

Hey gang,
This is a test message.
--J."""

        privkey = b"""-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQi
Y/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqM
KrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB
AoGAH0cxOhFZDgzXWhDhnAJDw5s4roOXN4OhjiXa8W7Y3rhX3FJqmJSPuC8N9vQm
6SVbaLAE4SG5mLMueHlh4KXffEpuLEiNp9Ss3O4YfLiQpbRqE7Tm5SxKjvvQoZZe
zHorimOaChRL2it47iuWxzxSiRMv4c+j70GiWdxXnxe4UoECQQDzJB/0U58W7RZy
6enGVj2kWF732CoWFZWzi1FicudrBFoy63QwcowpoCazKtvZGMNlPWnC7x/6o8Gc
uSe0ga2xAkEA8C7PipPm1/1fTRQvj1o/dDmZp243044ZNyxjg+/OPN0oWCbXIGxy
WvmZbXriOWoSALJTjExEgraHEgnXssuk7QJBALl5ICsYMu6hMxO73gnfNayNgPxd
WFV6Z7ULnKyV7HSVYF0hgYOHjeYe9gaMtiJYoo0zGN+L3AAtNP9huqkWlzECQE1a
licIeVlo1e+qJ6Mgqr0Q7Aa7falZ448ccbSFYEPD6oFxiOl9Y9se9iYHZKKfIcst
o7DUw1/hz2Ck4N5JrgUCQQCyKveNvjzkkd8HjYs0SwM0fPjK16//5qDZ2UiDGnOe
uEzxBDAr518Z8VFbR41in3W4Y3yCDgQlLlcETrS+zYcL
-----END RSA PRIVATE KEY-----
"""

        auth_res = b"""lists.example.org; spf=pass smtp.mfrom=jqd@d1.example; dkim=pass (1024-bit key) header.i=@d1.example; dmarc=pass"""
        
        res = sign_message(msg, b"dummy", b"example.org", privkey, b"from:to:date:subject:mime-version:arc-authentication-results".split(b':'), sig='ARC', auth_res=auth_res, timestamp="12345")

        headers = [b'ARC-Seal: i=1; cv=none; a=rsa-sha256; d=example.org; s=dummy; t=12345;  b=FWOEyeRJ8YiqKt9x9GaZF62z/iy9i2606XLlnLC+Mfzf+8M92eWPPb50Pa+9d1iMwVRVeE 8Rsdh6a7t+on2vLqBzFCuhA48AyQBVOMf4YgYKIxYbVHa5TD7GUOGSNCse8PGblJTcogmTL7 FhApk4DJZQkuE4EWrMRMpzfxG24l4=', b'ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=dummy; t=12345;  h=from : to : date : subject : mime-version :  arc-authentication-results;  bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=;  b=LNev0+5hTRq5x+38IWMxbyZBXxZS6Ddacbul1XE7lEBKDXxh9MUvdGvCqdDoSSlUmJyx/s PLfucMfmftarx1xVIRPJeUrtuOZuUdQMPVpQcfQJ9pUfE1TG1KS4E2suCz3TF7uxu5OjaP21 mjquuQP5lQe2fsnwBjBgVFcsSAwPw=', b'ARC-Authentication-Results: i=1; lists.example.org; spf=pass smtp.mfrom=jqd@d1.example; dkim=pass (1024-bit key) header.i=@d1.example; dmarc=pass']
        
        headers = [b"".join(x.split()) for x in headers]
        print(res)
        res = [b"".join(x.split()) for x in res]
        self.assertEqual(res, headers)
        
if __name__ == '__main__':
    unittest.main()
