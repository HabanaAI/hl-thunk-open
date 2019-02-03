# HabanaLabs thunk library for kernel driver

This is the userspace thunk library for HabanaLabs kernel driver.

# Building

This project uses a cmake based build system. Quick start:

```sh
$ bash build.sh
```

### Debian Derived

```sh
$ apt-get install build-essential cmake gcc
```

### Fedora

```sh
$ dnf install cmake gcc
```

## Building on CentOS 7

Install required packages:

```sh
$ yum install epel-release
$ yum install gcc make cmake3
```

## Coding Style

This project uses the Linux kernel coding style with some minor changes, such
as allowing typedefs.

Best practice is to use the checkpatch utility of the Linux kernel with the
following ignores:

checkpatch.pl --ignore SPDX_LICENSE_TAG,NEW_TYPEDEFS
