#!/usr/bin/env bash

for arg in "$@"
do
  /bin/bash quick-build.sh afuzz "${arg}"
done
