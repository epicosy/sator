# Sator: a vulnerability database API

## Installation

```
$ git clone https://github.com/epicosy/sator.git
$ pip install .
$ ./setup.sh
```

### Setting up database

```sh
$ docker run --shm-size 128MB --name sator_db -e POSTGRES_PASSWORD=user123 -e POSTGRES_USER=user1 -e POSTGRES_DB=sator -d -p 5432:5432 postgres
```

### Usage

Set up URI string in environment variable:
```sh
$ export SQLALCHEMY_DATABASE_URI='postgresql://user:password@127.0.0.1:5432/db'
```

Init database (optional, if not already done):
```sh
$ arepo -u $SQLALCHEMY_DATABASE_URI init
```

Populate database with NVD:
```sh
$ sator source -n nvd collect -s 1999 -e 2024
```


### Docker 
```shell
 $ docker build --network="host" . -t sator
 $ docker run --name sator --network="host" sator
```

### Running server 

```sh
$ sator run [-h] [-p PORT] [-a ADDRESS]
```

## Development

This project includes a number of helpers in the `Makefile` to streamline common development tasks.

### Environment Setup

The following demonstrates setting up and working with a development environment:

```
### create a virtualenv for development

$ make virtualenv

$ source env/bin/activate


### run sator cli application

$ sator --help


### run pytest / coverage

$ make test
```


### Releasing to PyPi

Before releasing to PyPi, you must configure your login credentials:

**~/.pypirc**:

```
[pypi]
username = YOUR_USERNAME
password = YOUR_PASSWORD
```

Then use the included helper function via the `Makefile`:

```
$ make dist

$ make dist-upload
```
