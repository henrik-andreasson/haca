#!/bin/bash

docker build -t haca  .

docker run -p5000:5000 -it  --mount type=bind,source="$(pwd)",target=/haca haca flask run --host=0.0.0.0 --reload
