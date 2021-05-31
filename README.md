ipv6-discovery
==============

Patrick Wagstrom &lt;patrick@wagstrom.net&gt;

May 2021

Overview
--------

Have you ever attacked a problem only to wonder "Either I'm going too deep into this problem or I'm solving it completely wrong?". That's my challenge as I go on a quest to get a better grasp of what's going on in my network.

This application works by connecting to multiple hosts on a network and looking at their IPv6 neighbors to get an idea of what IPv6 hosts are on the network and what their MAC addresses are. This is then used to generate a text file that can be fed into dnsmasq for local DNS and reverse DNS support.

Configuration
-------------

There's enough settings that you're best off writing a configuration file in TOML to configure the program.

```toml
# ignore local link IPv6 addresses
# keep_local = false
# keep hosts for 2 hours after last seen
retention_time = 7200
# if not specified - rescan after 360 seconds
rescan_interval = 360
#  set the destination for the output
outputfile = "ipv6.hosts"
# set the hostname suffix
hostname_suffix = "ipv6.local.example.com"

[ipv6hosts]
    [ipv6hosts.pihole]
    connection = "ssh"
    host = "192.168.1.2"
    username = "pi"
    auth = "agent"

    [ipv6hosts.udmpro]
    connection = "ssh"
    host = "192.168.1.1"
    username = "root"
    auth = "agent"

[ipv4hosts]
    [ipv4hosts.pihole]
    connection = "ssh"
    host = "192.168.1.2"
    username = "pi"
    auth = "agent"
```

Usage
-----

Although the program will gladly run without a configuration file, it won't do anything until a configuration file is supplied.

```bash
./ipv6-discovery -config config.toml
```


License
-------

Copyright © 2021 Patrick Wagstrom

Licensed under the terms of the MIT license