# macos-virtio-net
this provides virtio-net to macos virtual machine by an unix socket file, with no fruit's bridged entitlement needed, to get a bridged network to vm..
(ref :	https://amodm.com/blog/2024/07/03/running-a-linux-router-on-macos )

usage:
1. $ sudo mvn -s /tmp/s.socket -a c2:6d:fd:60:10:2b -i en0
2. $ vfkit .. --device virtio-net,unixSocketPath=/tmp/s.socket,mac=c2:6d:fd:60:10:2b

notes:
1. mac address keep the same between
2. ethernet cable interface such as en0 is tested ok; wifi interface tested not ok


