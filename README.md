# Sysrepo Snabb plugin

Sysrepo is an YANG-based configuration and operational state data store for Unix/Linux applications.

Snabb (formerly "Snabb Switch") is a simple and fast packet networking toolkit.

This plugin is responsible for connecting the Snabb data plane with the Sysrepo data plane. In this
configuration the Sysrepo data plane is active while the Snabb data plane is passive, that means that
this plugin will actively listen for Sysrepo datastore changes and translate them into Snabb operations
while the reverse is not true.

## Requirements

* sysrepo
* snabb

## Build and install Sysrepo plugin

```
$ cmake ..
$ make
$ make install
$ # start/restart sysrepo-plugind
```

## Build and install Sysrepo application

```
$ cmake -DPLUGIN=OFF ..
$ make
$ make install
$ ./sysrepo-snabb-plugin
```
