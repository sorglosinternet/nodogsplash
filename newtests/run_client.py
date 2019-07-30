#!/usr/bin/env python3

import requests
import logging

LOG = logging.getLogger("run_client")

# download startwlan.de
resp = requests.get("http://startwlan.de")
if not resp.text.find("Nodogsplash"):
    LOG.warn("Could not find the splash")

# search auth target
auth = None
for line in resp.text.splitlines():
    if "authtarget: http://" in line:
        auth = line

offset = auth.find('http://')

# auth to nodogsplash
resp_auth = requests.get(auth[offset:])
if re.status_code != 200:
    LOG.warn("status code of the auth is not 200. Is %s", re.status_code)

# download google.com
google = requests.get("http://startwlan.de")
if google.status_code != 200:
    LOG.warn("status code of the google is not 200. Is %s", google.status_code)

if not google.find("google"):
    LOG.warn("Could not find google in the request")


