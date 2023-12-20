#!/usr/bin/env bash

BUILD_DIR=$1; shift

[ -f oe-init-build-env ] && . oe-init-build-env "$BUILD_DIR"

bitbake "$@"
