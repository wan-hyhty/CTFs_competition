#!/bin/bash
docker build --network host --tag=device_control .
docker run -it -p 1337:1337 --rm --name=device_control device_control