#!/bin/bash
# Check if euid is root
if [ $USER != "root" ] ; then
	echo "Please run with root access"
	exit 1
fi
# Check if the containers are running
if [ $(docker inspect -f '{{.State.Pid}} ' BRGr) -eq 0 ] ; then
	docker start BRGr
fi
if [ $(docker inspect -f '{{.State.Pid}} ' BRG1) -eq 0 ] ; then
	docker start BRG1
fi
if [ $(docker inspect -f '{{.State.Pid}} ' BRG2) -eq 0 ] ; then
	docker start BRG2
fi
if [ $(docker inspect -f '{{.State.Pid}} ' h1) -eq 0 ] ; then
	docker start h1
fi
if [ $(docker inspect -f '{{.State.Pid}} ' h2) -eq 0 ] ; then
	docker start h2
fi
if [ $(docker inspect -f '{{.State.Pid}} ' router) -eq 0 ] ; then
	docker start router
fi
if [ $(docker inspect -f '{{.State.Pid}} ' edge_router) -eq 0 ] ; then
	docker start edge_router
fi

# Create virtual ethernet interfaces for the containers
ip link add r-eth0 type veth peer name BRGr-eth0
ip link set r-eth0 netns $(docker inspect -f '{{.State.Pid}} ' router)
if [ $? -ne 0 ] ; then
	ip link delete r-eth0
fi
docker exec -i router ip link set r-eth0 up && docker exec -i router ip addr add 140.113.0.1/16 dev r-eth0
ip link set BRGr-eth0 netns $(docker inspect -f '{{.State.Pid}}' BRGr)
if [ $? -ne 0 ] ; then
        ip link delete BRGr-eth0
fi
docker exec -i BRGr ip link set BRGr-eth0 up && docker exec -i BRGr ip addr add 140.113.0.2/16 dev BRGr-eth0

ip link add r-eth1 type veth peer name er-eth0
ip link set r-eth1 netns $(docker inspect -f '{{.State.Pid}} ' router)
if [ $? -ne 0 ] ; then
        ip link delete r-eth1
fi
docker exec -i router ip link set r-eth1 up && docker exec -i router ip addr add 140.114.0.2/16 dev r-eth1
ip link set er-eth0 netns $(docker inspect -f '{{.State.Pid}}' edge_router)
if [ $? -ne 0 ] ; then
        ip link delete er-eth0
fi
docker exec -i edge_router ip link set er-eth0 up && docker exec -i edge_router ip addr add 140.114.0.1/16 dev er-eth0

ip link add BRG1-eth0 type veth peer name h1-eth0
ip link set BRG1-eth0 netns $(docker inspect -f '{{.State.Pid}} ' BRG1)
if [ $? -ne 0 ] ; then
        ip link delete BRG1-eth0
fi
docker exec -i BRG1 ip link set BRG1-eth0 up
ip link set h1-eth0 netns $(docker inspect -f '{{.State.Pid}}' h1)
if [ $? -ne 0 ] ; then
        ip link delete h1-eth0
fi
docker exec -i h1 ip link set h1-eth0 up

ip link add BRG2-eth0 type veth peer name h2-eth0
ip link set BRG2-eth0 netns $(docker inspect -f '{{.State.Pid}} ' BRG2)
if [ $? -ne 0 ] ; then
        ip link delete BRG2-eth0
fi
docker exec -i BRG2 ip link set BRG2-eth0 up
ip link set h2-eth0 netns $(docker inspect -f '{{.State.Pid}}' h2)
if [ $? -ne 0 ] ; then
        ip link delete h2-eth0
fi
docker exec -i h2 ip link set h2-eth0 up

ip link add BRGr-eth1 type veth peer name veth
ip link set BRGr-eth1 netns $(docker inspect -f '{{.State.Pid}} ' BRGr)
if [ $? -ne 0 ] ; then
        ip link delete BRGr-eth1
fi
docker exec -i BRGr ip link set BRGr-eth1 up
ip link set veth up
ip addr add 20.0.0.1/8 dev veth
sysctl net.ipv4.ip_forward=1
iptables -A FORWARD -i veth -o enp0s8 -j ACCEPT
iptables -A FORWARD -o veth -i enp0s8 -j ACCEPT
iptables -t nat -A POSTROUTING -s 20.0.0.0/8 -o enp0s8 -j MASQUERADE

ip link add br0 type bridge

ip link add BRG1-eth1 type veth peer name br0-brg1
ip link set BRG1-eth1 netns $(docker inspect -f '{{.State.Pid}} ' BRG1)
if [ $? -ne 0 ] ; then
        ip link delete BRG1-eth1
	ip link delete br0-brg1
else
	docker exec -i BRG1 ip link set BRG1-eth1 up
	ip link set br0-brg1 up
fi

ip link add BRG2-eth1 type veth peer name br0-brg2
ip link set BRG2-eth1 netns $(docker inspect -f '{{.State.Pid}} ' BRG2)
if [ $? -ne 0 ] ; then
        ip link delete BRG2-eth1
        ip link delete br0-brg2
else
        docker exec -i BRG2 ip link set BRG2-eth1 up
        ip link set br0-brg2 up
fi

ip link add er-eth1 type veth peer name br0-er
ip link set er-eth1 netns $(docker inspect -f '{{.State.Pid}} ' edge_router)
if [ $? -ne 0 ] ; then
        ip link delete er-eth1
        ip link delete br0-er
else
        docker exec -i edge_router ip link set er-eth1 up
	docker exec -i edge_router ip addr add 172.27.0.1/24 dev er-eth1
        ip link set br0-er up
fi

brctl addif br0 br0-brg1
brctl addif br0 br0-brg2
brctl addif br0 br0-er
ip link set br0 up
iptables -P FORWARD ACCEPT

# Run DHCP service on edge_router
docker cp ./dhcpd.conf edge_router:/
docker exec -i edge_router touch /var/lib/dhcp/dhcpd.leases
docker exec -i edge_router dhcpd -pf /var/run/dhcpd.pid -cf /dhcpd.conf er-eth1
docker exec -i BRG1 dhclient BRG1-eth1
docker exec -i BRG2 dhclient BRG2-eth1


# Run DHCP service on veth
ls /var/lib/dhcp/dhcpd.leases 1> /dev/null
if [ $? -ne 0 ] ; then
	touch /var/lib/dhcp/dhcpd.leases
else
	chown root /var/lib/dhcp/dhcpd.leases
fi
dhcpd veth

# Set ip_forward to 1
docker exec -i router sysctl net.ipv4.ip_forward=1
docker exec -i edge_router sysctl net.ipv4.ip_forward=1
docker exec -i BRGr sysctl net.ipv4.ip_forward=1
docker exec -i BRG1 sysctl net.ipv4.ip_forward=1
docker exec -i BRG2 sysctl net.ipv4.ip_forward=1

# Set route for routers
docker exec -i BRGr route add -net 140.114.0.0/16 gw 140.113.0.1
docker exec -i router route add -net 140.114.0.0/16 gw 140.114.0.1
docker exec -i edge_router route add -net 140.113.0.0/16 gw 140.114.0.2

# Run NAT on edge_router
docker exec -i edge_router iptables -t nat -A POSTROUTING -o er-eth0 -s 172.27.0.0/24 -j MASQUERADE

# Load fou module to kernel
modprobe fou
addr=$(docker exec -i BRG1 ip addr show BRG1-eth1 | grep -o "inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | cut -d ' ' -f2)
docker exec -i BRG1 ip link add GRE type gretap remote 140.113.0.2 local ${addr} encap fou encap-sport 22222 encap-dport 55555
docker exec -i BRG1 ip link set GRE up
docker exec -i BRG1 ip link add br0 type bridge
docker exec -i BRG1 brctl addif br0 BRG1-eth0
docker exec -i BRG1 brctl addif br0 GRE
docker exec -i BRG1 ip link set br0 up
docker exec -i BRG1 ip fou add port 22222 ipproto 47

addr=$(docker exec -i BRG2 ip addr show BRG2-eth1 | grep -o "inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | cut -d ' ' -f2)
docker exec -i BRG2 ip link add GRE type gretap remote 140.113.0.2 local ${addr} encap fou encap-sport 33333 encap-dport 55555
docker exec -i BRG2 ip link set GRE up
docker exec -i BRG2 ip link add br0 type bridge
docker exec -i BRG2 brctl addif br0 BRG2-eth0
docker exec -i BRG2 brctl addif br0 GRE
docker exec -i BRG2 ip link set br0 up
docker exec -i BRG2 ip fou add port 33333 ipproto 47

docker cp ./auto_tunnel BRGr:/
