#!/usr/bin/env python

import lxc


def configure_network(container, bridge, ip_netmask):
    """ configure the container and connect them to the bridge
    container is a lxc container
    bridge the name of your bridge to attach the container
    ip_netmask is the give address in cidr. e.g. 192.168.1.2/24"""
    config = [
        ('lxc.network.type', 'veth'),
        ('lxc.network.link', bridge),
        ('lxc.network.flags', 'up'),
        ('lxc.network.ipv4', ip_netmask),
    ]

    for item in config:
        container.append_config_item(item[0], item[1])


containers = []

base = lxc.Container("nodogsplash-base")

# run 200 contains
for i in range(10, 210):
    # start container
    name = "test-nodogsplash-{}".format(i)
    cont = base.clone(name, None, lxc.LXC_CLONE_SNAPSHOT, bdevtype='aufs')
    containers.append(cont)

    if cont.defined:
        container.destroy()

    configure_network(cont, "br-lan", "192.168.128.{}".format(i))
    cont.start()
