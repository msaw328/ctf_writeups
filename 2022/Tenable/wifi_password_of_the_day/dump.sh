#!/bin/bash
echo $1 | base64 -d | hexdump -C
