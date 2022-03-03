# oc-mirror

## Overview

A utility that can be used to mirror OpenShift releases, Operator releases, and atomic signatures between docker registries.

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

### Creating an atomic signature

Note: Currently, only WebDAV upload is supported.

```bash
  atomic \
    --signature-store https://my-webdav-server/ \
    sign \
    --keyid=my-magic-keyid \
    registry.redhat.io/redhat/redhat-operator-index:v4.8@sha256:6ddf56b65877a0d603fcc8f06bca7314f18816d5734c878094b7a1b5598ce251
```

### Verifying an atomic signature

```bash
DRCA_CREDENTIALS_STORE=~/.docker/quay.io-pull-secret.json \
  atomic \
    --signature-store=https://mirror.openshift.com/pub/openshift-v4/signatures/openshift/release \
    --signature-type=manifest \
    verify \
    quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64@sha256:7613d8f7db639147b91b16b54b24cfa351c3cbde6aa7b7bf1b9c80c260efad06
```

### Mirroring an OpenShift release

```bash
DRCA_CREDENTIALS_STORE=~/.docker/quay.io-pull-secret.json \
oc-mirror \
  --signature-store=https://mirror.openshift.com/pub/openshift-v4/signatures/openshift/release \
  mirror \
  quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64 \
  some-other-registry.com:5000/openshift-release-dev/ocp-release:4.4.6-x86_64
```

### Mirroring an Operator release
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

| Variable | Default Value | Description |
| ---------| ------------- | ----------- |
| ATOMIC_KEYID | | Identifier of the GnuPG key to use for signing.|
| ATOMIC_KEYPASS | | The corresponding key passphrase. |
| ATOMIC_SIGNATURE_STORE | https://mirror.openshift.com/pub/openshift-v4/signatures/openshift/release | Signature store location at which atomic signatures are (to be) located. |
| ATOMIC_SIGNATURE_TYPE | iamge-config | Whether atomic signature digest reference Manifests or Image Configurations. |
| ATOMIC_SIGNING_KEY | | Path to the GnuPG armored keys used to verify atomic signatures. |
| OCM_SIGNATURE_STORE | _use locations embedded in release metadata_ | Signature store location at which atomic signatures are located. |
| OCM_SIGNING_KEY | _use keys embedded in release metadata_ | Path to the GnuPG armored keys used to verify atomic signatures. |
| OPM_SIGNATURE_STORE | https://mirror.openshift.com/pub/openshift-v4/signatures/openshift/release | Signature store location at which atomic signatures are located. |
| OPM_SIGNING_KEY | | Path to the GnuPG armored keys used to verify atomic signatures. |

## Development

[Source Control](https://github.com/crashvb/oc-mirror)
