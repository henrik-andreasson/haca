# haca

Certification Authority service for multiple teams.

REST API for automatic management of all components

Very early version but working software.

Author: https://github.com/henrik-andreasson/

Heavily based on the excellent tutorial  [Flask Mega Tutorial](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world) by Miguel Grinberg.

Big Thanks to Miguel!


# Running

## Running on Debian

Install python3 and sqlite

    apt-get install --no-install-recommends -y python3 \
        sqlite3 jq python3-pip  \
        python3-wheel gunicorn3

Used modules from pip

    pip3 install -U pip
    pip3 install -r requirements.txt

install source, download from github or clone via git

    mkdir /opt/haca
    cd /opt/haca
    unzip inventorpy-x.y.z.zip

or
    git clone https://github.com/henrik-andreasson/haca.git

start

    export FLASK_APP=haca.py
    cd /opt/haca
    flask run --host=0.0.0.0 --port 5000


## Running in Docker

build docker:

    docker build -t haca  .

Run the app

    docker run -it -p5000:5000 haca

Developer mode, ie mount the current directory into the docker container and have it self reload when python files are written

    docker run -p5000:5000 -it  --mount type=bind,source="$(pwd)",target=/haca haca flask run --host=0.0.0.0 --reload

# clean database

    * rm ca.db
    * flask db init
    * flask db migrate -m baseline
    * flask db upgrade
    * flask user new admin foo123 admin@example.com


# docs

todo  <https://henrik-andreasson.github.io/haca/>
