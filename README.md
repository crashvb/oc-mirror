# oc-mirror

## Overview

A utility that can be used to mirror OpenShift releases between docker registries.

## Compatibility

* Tested with python 3.8

## Installation
### From [pypi.org](https://pypi.org/project/oc-mirror/)

```
$ pip install oc_mirror
```

### From source code

```bash
$ git clone https://github.com/crashvb/oc-mirror
$ cd oc-mirror
$ virtualenv env
$ source env/bin/activate
$ python -m pip install --editable .[dev]
```

## Usage

```bash
DRCA_CREDENTIALS_STORE=~/.docker/quay.io-pull-secret.json \
oc-mirror \
  --signature-store https://mirror.openshift.com/pub/openshift-v4/signatures/openshift/release \
  mirror \
  quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64 \
  some-other-registry.com:5000/openshift-release-dev/ocp-release:4.4.6-x86_64
```

```bash
DRCA_CREDENTIALS_STORE=~/.docker/quay.io-pull-secret.json \
op-mirror \
  --no-check-signatures \
  mirror \
  registry.redhat.io/redhat/redhat-operator-index:v4.8 \
  some-other-registry.com:5000/redhat/redhat-operator-index:v4.8 \
  compliance-operator:release-0.1 \
  local-storage-operator \
  ocs-operator
```

### Environment Variables

None.

## Development

[Source Control](https://github.com/crashvb/oc-mirror)
