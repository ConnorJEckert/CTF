#!/bin/bash

docker build --network=host -t overheadyeet .
docker run --rm -it -v $PWD/mount:/svc/mount --net host -p 1234:1234 overheadyeet
