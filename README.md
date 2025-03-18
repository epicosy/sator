# Sator: Open Source Vulnerability Analysis

An application for analysis of security vulnerabilities in open source software projects.

## Installation

```
$ git clone https://github.com/epicosy/sator.git
$ pip install .
$ ./setup.sh
```

### Setup 

Copy the `config/sator.yml` file and place under `~/.sator/config/sator.yml`. Edit the file to provide the relevant 
paths for the repositories and the gateway login credentials.

### Usage

Dissect the vulnerability data and extract relevant information for analysis by running the following commands:

1. Resolve the vulnerability description and references and extract and analyze the attributes to identify the vulnerable product.
```sh
$ sator resolve vulnerability-description -vid <vulnerability_id>
$ sator resolve vulnerability-references -vid <vulnerability_id>
$ sator extract vulnerability-attributes -vid <vulnerability_id>
$ sator annotate vulnerability-attributes -vid <vulnerability_id>
$ sator analyze vulnerability-attributes -vid <vulnerability_id>
```

2. Resolve the product references and extract and analyze the attributes to indentify its open source project.
```sh
$ sator resolve product-references -vid <vulnerability_id>
$ sator extract product-attributes -vid <vulnerability_id>
$ sator annotate product-attributes -pid <product_id>
$ sator analyze product-attributes -vid <vulnerability_id>
```

3. Resolve the patch references and extract and analyze the attributes to identify the patch for the root bug.
```sh
$ sator resolve patch-references -vid <vulnerability_id>
$ sator extract patch-attributes -vid <vulnerability_id>
$ sator annotate patch-attributes -vid <vulnerability_id>
$ sator analyze patch-attributes -vid <vulnerability_id>
```
