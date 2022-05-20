# Use an official Python runtime as a parent image
FROM debian:latest

# Set the working directory to /app
WORKDIR /haca

COPY . /haca

# Install any needed packages
RUN apt-get update

RUN apt-get install --no-install-recommends -y python3 \
        sqlite3 jq python3-pip  \
        python3-wheel gunicorn3

#        python3-dev libssl-dev python3-setuptools  cargo\
#        build-essential libffi-dev rustc

RUN pip3 install -U pip
RUN pip3 install -r requirements.txt

RUN apt-get clean
RUN rm -rf /var/lib/apt/lists/*

# Make port available to the world outside this container
EXPOSE 5000

ENV FLASK_APP=/haca/haca.py

# Run flask when the container launches
CMD [ "/haca/gunicorn-start.sh"]
