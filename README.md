# connect-without-vpn
connect directly to a country(ip range) and use tunnel for outside of that country(ip range).
for example we want to use internet directly for iran. and vpn for outside of iran(probably filtered). works with python2 in linux

## Usage

```
python2.7 director.py [--interface INTERFACE] [-i [I]]
                   [-gw [GW]]
```
## Arguments
*  `-h, --help`            show this help message and exit
*  `--version`             show program's version number and exit
*  `--interface INTERFACE`              your desired interface that ip/masks should route in
*  `-i [I]`                input file, each line should consist of ip/netmask ,   lines with # will be ignored
*  `-gw [GW]`              default gateway of your interface

## Example
my interface name is enp6s0 (find out with `ifconfig`) and default gateway of that interface is 192.168.1.1 (find out with `route -n`).

```python2.7 directory.py --interface enp6s0 -i ~/temp/iran.txt -gw 192.168.1.1```

## TODO
* crawl ip range of a country and add a argument for selecting a country instead of a local file
* finding default interface
* finding default gateway
* adding a self learning system to route filtered ip's to tunnel and not filters ip's directly


## Self learning
`sniffer.py` is a basic implementation of self learning patterns. which takes a different approach rather than `director.py` which is:
* route every packet in default censored interface and sniff all packets, if there is a censored ip then route that in tunnel interface.
* route dns through tunnel which solve dns censored ssl websites.

### self learning pattern's :
* `403 Forbidden` in socket's data.
* no answer. but the site might be down. should find a better approach
