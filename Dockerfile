FROM python:3.10

WORKDIR /opt/sator
COPY . /opt/sator


RUN pip install .
RUN ./setup.sh

ENTRYPOINT sator -u $SQLALCHEMY_DATABASE_URI server -a 0.0.0.0 -p $PORT -k $SERVER_SECRET_KEY run
