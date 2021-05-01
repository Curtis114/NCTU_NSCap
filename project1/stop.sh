if [ $USER != "root" ] ; then
	echo "Please run with root access"
	exit 1
fi
pid=$(ps -aux | grep dhcpd | grep veth | awk '{printf("%s", $2)}')
if [ ! -z $pid ] ; then
	echo "killing process..."
	kill -15 $pid
else
	echo "dhcpd veth: process not found"
fi
echo "stopping all containers..."
docker stop $(docker ps -aq) 1> /dev/null
ip link delete br0
sudo iptables -D FORWARD -o veth -i enp0s8 -j ACCEPT
sudo iptables -D FORWARD -i veth -o enp0s8 -j ACCEPT
sudo iptables -D FORWARD -o veth -i enp0s3 -j ACCEPT
sudo iptables -D FORWARD -i veth -o enp0s3 -j ACCEPT
