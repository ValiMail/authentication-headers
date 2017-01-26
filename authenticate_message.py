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

#message = sys.stdin.read()

message = b"""Delivered-To: gene@valimail.com
Received: by 10.157.32.10 with SMTP id n10csp1340724ota;
        Mon, 23 Jan 2017 08:49:04 -0800 (PST)
X-Received: by 10.98.208.70 with SMTP id p67mr34181308pfg.101.1485190144055;
        Mon, 23 Jan 2017 08:49:04 -0800 (PST)
Return-Path: <dimitri.n@allsetnow.com>
Received: from mail-pg0-x230.google.com (mail-pg0-x230.google.com. [2607:f8b0:400e:c05::230])
        by mx.google.com with ESMTPS id y76si16175257pfg.155.2017.01.23.08.49.03
        for <gene@valimail.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 23 Jan 2017 08:49:04 -0800 (PST)
Received-SPF: pass (google.com: domain of dimitri.n@allsetnow.com designates 2607:f8b0:400e:c05::230 as permitted sender) client-ip=2607:f8b0:400e:c05::230;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@allsetnow-com.20150623.gappssmtp.com;
       spf=pass (google.com: domain of dimitri.n@allsetnow.com designates 2607:f8b0:400e:c05::230 as permitted sender) smtp.mailfrom=dimitri.n@allsetnow.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=allsetnow.com
Received: by mail-pg0-x230.google.com with SMTP id 194so46282349pgd.2
        for <gene@valimail.com>; Mon, 23 Jan 2017 08:49:03 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=allsetnow-com.20150623.gappssmtp.com; s=20150623;
        h=from:date:subject:message-id:to:mime-version;
        bh=FT3+BUOs3tC5f5jffbigI9BU/nvQ7/VJKW66dqJikrU=;
        b=vtHiHq4azEMs/v/+nBG8w3stARoDN7QMRWB6yrb/lWHm2IGoN35DF4/NwIXiSZg4CA
         raUWt9sdUJL9IZKSzbaTsc2WMx99sGPJ0QL9OafQhbnErW+mJKXqOBgrorlHgvEYSEAM
         WOofaWHt1+QaCgMc/oPPg/CP+wmJyu+5gZcIF5T7o81e3H4XgRAOh7IF0LPY7P8Aum4e
         xsGpKD6XhxNn6v/LQnd/Eet3pX3ros1KOqxNeZZoen+JB+zkhX9teHsbW5cWMRl7Tu/3
         E079QtR3CN2890mmX38I5th40yqxhTF22qyZ4cDdUKFjO2ocjACDnyGlSktp0UzSiFCY
         PTrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:from:date:subject:message-id:to:mime-version;
        bh=FT3+BUOs3tC5f5jffbigI9BU/nvQ7/VJKW66dqJikrU=;
        b=XdcaOdJUs0Oa0+LGDTRhySXWK6EuI8qGmRN8tL/9nAT16gwW8nLk6jkxxsLFkLj47/
         pBgaFbFFu6t8XOPC9w8c+uoKz+s4qWV1fO+E2q1Dj/UCzyfMpkSdRR9BqE92tc+1CIjw
         oKfE2z2AsubPe2FJ233Bgmm7PX/8O+R+2cub7IaWiRG5EGWweMNscwLOT8xYCkeuiIc9
         z8v4nOTlFk5CFVXYYl9hcz2kZ4OzgNRXE57oAP3h0NS7H412ODUAf7t1c4vqY78piTmi
         Wx4PoojXrrlbKpi5MFa9bza9F/R3m1xC6QNeVGodw5mprUtSlibfNvFIVD3hnt4GUuGl
         J25g==
X-Gm-Message-State: AIkVDXLYHgpD4pdzIKchmgaFq1y8fwtKuQMD6hufiL40ub6U1xuZTuknkwRf5ctjgl6U+g==
X-Received: by 10.84.231.205 with SMTP id g13mr44767721pln.118.1485190143563;
        Mon, 23 Jan 2017 08:49:03 -0800 (PST)
Return-Path: <dimitri.n@allsetnow.com>
Received: from [10.85.212.109] ([13.93.148.200])
        by smtp.gmail.com with ESMTPSA id o18sm38395863pgn.36.2017.01.23.08.49.02
        for <gene@valimail.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-SHA bits=128/128);
        Mon, 23 Jan 2017 08:49:03 -0800 (PST)
From: Dimitri Nikulin <dimitri.n@allsetnow.com>
Date: Mon, 23 Jan 2017 16:49:02 +0000
Subject: Just checking in
Message-Id: <I3P5UP5VC0U4.VYLD837X5SHD1@RD00155DAAEB82>
To: gene@valimail.com
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="=-/yxooSiibOTaV61wZ2Vtaw=="

--=-/yxooSiibOTaV61wZ2Vtaw==
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit


Hi Gene,
I hope your day is going well.
I've previously reached out to you and wanted to see if you had any questions about Allset (www.allsetnow.com), or if there is anything I can do to help you take advantage of our $30 promo code VIPTRY30 ($10 off each of your first three orders).
As a reminder, Allset (iOS  / Android) allows you to both book a table and pre-order your meal at SF restaurants making for a wait-free and more seamless lunch. We've gotten great feedback from employees of local companies so far and I'd love to hear how your lunch goes too.
Again, thanks so much for your time, Gene.
Sincerely,
Dimitri Nikulin
Co-founder and CCO Allset

--=-/yxooSiibOTaV61wZ2Vtaw==
Content-Type: text/html; charset=utf-8
Content-Id: <3HCFQD8VC0U4.I1QGVEDZX13C@RD00155DAAEB82>
Content-Transfer-Encoding: 8bit

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
                <html xmlns="http://www.w3.org/1999/xhtml">
                <head>
                <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
                <title></title>
                <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
                </head>
                <body><p>Hi Gene,</p>
<p>I hope your day is going well.</p>
<p>I&rsquo;ve previously reached out to you and wanted to see if you had any questions about Allset&nbsp;(<a href="https://allsetnow.com/">www.allsetnow.com</a>),&nbsp;or if there is anything I can do to help you take advantage of our $30 promo code <strong>VIPTRY30</strong> ($10 off each of your first three orders).</p>
<p>As a reminder, Allset&nbsp;(<a href="https://itunes.apple.com/us/app/allset-restaurant-reservations/id1016005447?mt=8">iOS </a>&nbsp;/&nbsp;<a href="https://play.google.com/store/apps/details?id=com.allset.client&amp;hl=en">Android</a>)&nbsp;allows you to both book a table and pre-order your meal at SF restaurants making for a wait-free and more seamless lunch. We&rsquo;ve gotten great feedback from employees of local companies so far and I&rsquo;d love to hear how your lunch goes too.</p>
<p>Again, thanks so much for your time, Gene.</p>
<p>Sincerely,</p>
<p>Dimitri Nikulin<br>Co-founder and CCO Allset</p><div class="opt-out"><br/><p>Just let me know if you are not interested so that I'll know to stop trying to follow up. Thanks!</p><br/></div><div class="tracking"><img alt="" height="0" src="http://opnstrack.com/home/index/I3P5UP5VC0U4.VYLD837X5SHD1@RD00155DAAEB82?cid=44627" width="0" /></div></body>
            </html>

--=-/yxooSiibOTaV61wZ2Vtaw==--"""

res = authenticate_message(message, sys.argv[1], ip=sys.argv[2], mail_from=sys.argv[3], helo=sys.argv[4])

for line in res:
  sys.stdout.write(line)

sys.stdout.write("\n")
