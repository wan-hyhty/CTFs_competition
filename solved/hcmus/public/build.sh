#!/bin/bash
export DOCKER_BUILDKIT=0
export COMPOSE_DOCKER_CLI_BUILD=0
docker build --pull --rm -f "Dockerfile" -t m3k4/introduction "."
