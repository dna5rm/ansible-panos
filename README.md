# ansible-panos

Palo Alto Networks Ansible Playbook

## Overview

This project is written in ansible and contains tasks to configure the following:

- _DEVICE_ *(panos_device.yaml)*
  - Device management
  - Admin user account(s)
  - Dynamic updates
    - anti-virus
    - threats
    - wildfire
    - global-protect-clientless-vpn
    - global-protect-datafile
- _NETWORK_ *(panos_network.yaml)*
  - LLDP profile & Enable
  - Management profile(s)
  - IKE crypto profile(s)
  - IPsec crypto profile(s)
  - _ZONES_ *(panos_network_zones.yaml)*
    - Security zone(s)
    - Security rule tag(s)
  - Manage interfaces
    - Aggregate interface(s)
    - Layer3 vlan interface(s)
    - Virtual-wire interface(s)
    - Layer2 interface(s)
    - Layer3 interface(s)
    - Aggregate member interface(s)
    - Layer2 subinterface(s)
    - Virtual Wire(s)
  - ECMP enable
  - Static route(s)
  - DHCP server interface(s)
- _OBJECTS_ *(panos_objects.yaml)*
  - Address object tasks
    - Address tag objects(s)
    - Address object(s)
    - Dynamic address group(s)
  - Service object tasks
    - Service tag objects(s)
    - Service object(s)
    - Service group(s)
  - Application group(s)
- _POLICIES_ *(panos_policies.yaml)*
  - Security rule tasks
    - Security rule tag(s)
    - Security rule group tag(s)
    - Security rule(s)
  - NAT rule tasks
    - NAT rule tag(s)
    - NAT rule group tag(s)
    - NAT rule(s)

## Deploying (quickstart)

Reference the following example files.

### inventory (example)

```ini
[panos]
pa220           ansible_host=192.0.2.100
pa440           ansible_host=192.0.2.200

[panos:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_connection=ansible.builtin.local
ansible_network_os=paloaltonetworks.panos
ansible_ssh_extra_args=-o BindAddress=192.0.2.1
ansible_user=admin
ansible_password=admin
```

### group_vars (example)

```yaml
---
global:
  domain_name: local
  name_servers:
    - 1.1.1.3
    - 1.0.0.3
  banner:
    login: Unauthorized access is denied.
    motd: This is an ansible managed host.
address_objects:
  - { name: any-v4, value: 0.0.0.0/0, tag: ['any'] }
  - { name: any-v6, value: '::/0', tag: ['any'] }
  - { name: 10.0.0.0, value: 10.0.0.0/8, description: "Private-Use Networks", tag: ['NET-PRIVATE', 'RFC1819'] }
  - { name: 172.16.0.0, value: 172.16.0.0/12, description: "Private-Use Networks", tag: ['NET-PRIVATE', 'RFC1819'] }
  - { name: 192.168.0.0, value: 192.168.0.0/16, description: "Private-Use Networks", tag: ['NET-PRIVATE', 'RFC1819'] }
  - { name: 100.64.0.0, value: 100.64.0.0/10, description: "Carrier-Grade NAT", tag: ['NET-PRIVATE', 'RFC6598'] }
  - { name: 192.0.0.0, value: 192.0.0.0/24, description: "IETF Protocol Assignments", tag: ['NET-PRIVATE', 'RFC5736'] }
  - { name: 198.18.0.0, value: 198.18.0.0/15, description: "Device Benchmark Testing", tag: ['NET-PRIVATE', 'RFC2544'] }
  - { name: 127.0.0.0, value: 127.0.0.0/8, description: "Loopback", tag: ['NET-LOCALHOST', 'RFC1122'] }
  - { name: 169.254.0.0, value: 169.254.0.0/16, description: "Link Local", tag: ['NET-LINKLOCAL', 'RFC3927'] }
  - { name: 192.0.2.0, value: 192.0.2.0/24, description: "TEST-NET-1", tag: ['NET-DOCUMENTATION', 'RFC5737'] }
  - { name: 198.51.100.0, value: 198.51.100.0/24, description: "TEST-NET-2", tag: ['NET-DOCUMENTATION', 'RFC5737'] }
  - { name: 203.0.113.0, value: 203.0.113.0/24, description: "TEST-NET-3", tag: ['NET-DOCUMENTATION', 'RFC5737'] }
application_groups:
  - { name: 'DHCP', value: ['dhcp','dhcpv6'] }
  - { name: 'ICMP', value: ['ipv6-icmp','ipv6-icmp-base','ping','ping6'] }
ike_profiles:
  - { name: aws, encryption: ['aes-256-cbc'], authentication: ['sha256'], dh_group: ['group14'], lifetime_seconds: 28000 }
  - { name: azure, encryption: ['aes-256-cbc'], authentication: ['sha256'], dh_group: ['group2'], lifetime_seconds: 28000 }
  - { name: oracle, encryption: ['aes-256-cbc'], authentication: ['sha384'], dh_group: ['group20'], lifetime_seconds: 28000 }
  - { name: gcp, encryption: ['aes-256-cbc'], authentication: ['sha256'], dh_group: ['group14'], lifetime_seconds: 36000 }
ipsec_profiles:
  - { name: aws, esp_encryption: ['aes-256-cbc'], esp_authentication: ['sha256'], dh_group: ['group14'], lifetime_seconds: 3600 }
  - { name: azure, esp_encryption: ['aes-256-cbc'], esp_authentication: ['sha1'], dh_group: ['no-pfs'], lifetime_seconds: 8400 }
  - { name: oracle, esp_encryption: ['aes-256-gcm'], esp_authentication: ['sha1'], dh_group: ['group5'], lifetime_seconds: 3600 }
  - { name: gcp, esp_encryption: ['aes-256-gcm'], esp_authentication: ['sha256'], dh_group: ['group14'], lifetime_seconds: 10800 }
mgmt_profiles:
  - { name: mgmt, ping: true, ssh: true, https: true, snmp: true, response_pages: true, userid_service: true }
  - { name: ping, ping: true }
service_objects:
  - { name: tcp_1935, destination_port: 1935, description: 'playstation service', tag: ['PLAYSTATION'] }
  - { name: tcp_8384, destination_port: 8384, description: 'syncthing default', tag: ['SYNCTHING'] }
  - { name: tcp_3478, destination_port: 3478, description: 'playstation service', tag: ['PLAYSTATION'] }
  - { name: tcp_3479, destination_port: 3479, description: 'playstation service', tag: ['PLAYSTATION'] }
  - { name: tcp_3480, destination_port: 3480, description: 'playstation service', tag: ['PLAYSTATION'] }
  - { name: tcp_5001, destination_port: 5001, description: 'dsm https service', tag: ['SYNOLOGY'] }
  - { name: tcp_5006, destination_port: 5006, description: 'dsm webdav https service', tag: ['SYNOLOGY'] }
  - { name: udp_3478, destination_port: 3478, protocol: udp, description: 'playstation service', tag: ['PLAYSTATION'] }
  - { name: udp_3479, destination_port: 3479, protocol: udp, description: 'playstation service', tag: ['PLAYSTATION'] }
tags:
  - { name: any, color: red }
  - { name: RFC1122, color: gray, comments: 'localhost networks' }
  - { name: RFC1819, color: gray, comments: 'private-use networks' }
  - { name: RFC2544, color: gray, comments: 'benchmark networks' }
  - { name: RFC3927, color: gray, comments: 'linklocal networks' }
  - { name: RFC5736, color: gray, comments: 'ietf networks' }
  - { name: RFC5737, color: gray, comments: 'documentation networks' }
  - { name: RFC6598, color: gray, comments: 'cgn networks' }
  - { name: NET-DOCUMENTATION, color: 'blue gray', comments: 'documentation networks' }
  - { name: NET-LINKLOCAL, color: 'blue gray', comments: 'linklocal networks' }
  - { name: NET-LOCALHOST, color: 'blue gray', comments: 'localhost networks' }
  - { name: NET-PRIVATE, color: 'blue gray', comments: 'private networks' }
  - { name: VWIRE, color: gray, comments: 'vwire passthrough' }
  - { name: INSIDE, color: green, comments: 'lan inside' }
  - { name: OUTSIDE, color: red, comments: 'wan outside' }
  - { name: WAN, color: yellow, comments: 'wan link' }
  - { name: BASTION, color: cyan, comments: 'bastion host' }
  - { name: SYNCTHING, color: brown, comments: 'syncthing' }
  - { name: SYNOLOGY, color: brown, comments: 'synology diskstation' }
  - { name: PLAYSTATION, color: black, comments: 'sony playstation' }
zones:
  - { name: inside, enable_userid: true, color: green }
  - { name: outside, color: red }
  - { name: lan_secure, mode: layer2, color: green }
  - { name: lan_insecure, mode: layer2, color: red }
  - { name: trust, mode: virtual-wire, color: lime }
  - { name: untrust, mode: virtual-wire, color: magenta }
```

### host_vars (example)

```yaml
---
interfaces:
  - { name: ae1, type: aggregate, mode: layer2 }
  - { name: ae1.2, type: subinterface, comment: outside vlan, mode: layer2, vlan_name: lan_insecure, zone_name: lan_insecure }
  - { name: ethernet1/1, type: vwire, comment: vwire untrust, vwire: wan, zone_name: untrust }
  - { name: ethernet1/2, type: vwire, comment: vwire trust, vwire: wan, zone_name: trust }
  - { name: ethernet1/3, type: layer2, vlan_name: lan_secure, zone_name: lan_secure }
  - { name: ethernet1/4, type: layer2, vlan_name: lan_secure, zone_name: lan_secure }
  - { name: ethernet1/5, type: layer2, vlan_name: lan_secure, zone_name: lan_secure }
  - { name: ethernet1/6, type: layer2, vlan_name: lan_secure, zone_name: lan_secure }
  - { name: ethernet1/7, type: ae1 }
  - { name: ethernet1/8, type: ae1 }
  - { name: vlan.2, type: vlan, ip: ['203.0.113.2/30'], management_profile: ping, vlan_name: lan_insecure, zone_name: outside }
  - { name: vlan.3, type: vlan, ip: ['192.0.2.1/24'], management_profile: mgmt, vlan_name: lan_secure, zone_name: inside }
static_routes:
  - { name: default, destination: 0.0.0.0/0, interface: vlan.2, nexthop: 203.0.113.1 }
dhcp_server:
  - interface: vlan.3
security_rules:
  - rule_name: drop panw-ip-lists
    location: top
    description: drop if source comes from any panw ip-list
    group_tag: any
    source_ip: ['panw-bulletproof-ip-list', 'panw-highrisk-ip-list', 'panw-known-ip-list', 'panw-torexit-ip-list']
    service: ['any']
    action: drop
  # vwire security rules
  - rule_name: vwire dhcp permit
    location: after
    existing_rule: drop panw-ip-lists
    description: permit dhcp from getting blocked
    group_tag: VWIRE
    source_zone: ['untrust']
    destination_zone: ['trust']
    application: ['DHCP']
    log_end: false
  - rule_name: trusted networks
    location: after
    existing_rule: vwire dhcp permit
    description: trust anything comming from these networks
    group_tag: VWIRE
    source_zone: ['untrust']
    source_ip: ['OUTSIDE']
    destination_zone: ['trust']
    service: ['any']
  - rule_name: untrusted networks
    location: after
    existing_rule: trusted networks
    description: drop anything comming from these networks
    group_tag: VWIRE
    source_zone: ['untrust']
    source_ip: ['NET-DOCUMENTATION','NET-PRIVATE']
    destination_zone: ['trust']
    service: ['any']
    action: drop
  - rule_name: vwire permit all out
    location: after
    existing_rule: untrusted networks
    description: permit all traffic out
    group_tag: VWIRE
    source_zone: ['trust']
    destination_zone: ['untrust']
    service: ['any']
  - rule_name: vwire untrust in
    location: after
    existing_rule: vwire permit all out
    description: permit application-default traffic in
    group_tag: VWIRE
    source_zone: ['untrust']
    destination_zone: ['trust']
  - rule_name: vwire untrust in deny
    location: after
    existing_rule: vwire untrust in
    description: deny all other traffic in
    group_tag: VWIRE
    source_zone: ['untrust']
    destination_zone: ['trust']
    service: ['any']
    action: deny
  - rule_name: inside to outside
    location: after
    existing_rule: vwire untrust in deny
    group_tag: INSIDE
    source_zone: ['inside']
    destination_zone: ['outside']
    service: ['any']
    antivirus: default
    vulnerability: strict
    spyware: strict
    file_blocking: 'basic file blocking'
    wildfire_analysis: default
  - rule_name: outside ping services
    description: permit ping from outside
    group_tag: OUTSIDE
    source_zone: ['outside']
    source_ip: ['US']
    destination_zone: ['inside']
    application: ['ICMP']
    antivirus: default
    vulnerability: strict
    wildfire_analysis: default
  - rule_name: ssh service
    description: ssh services
    group_tag: OUTSIDE
    source_zone: ['outside']
    source_ip: ['US']
    destination_zone: ['inside']
    application: ['ssh']
    vulnerability: strict
    wildfire_analysis: default
  - rule_name: ssl service
    location: after
    existing_rule: ssh service
    description: ssl services
    group_tag: OUTSIDE
    source_zone: ['outside']
    source_ip: ['US']
    destination_zone: ['inside']
    application: ['ssl']
    vulnerability: strict
    wildfire_analysis: default
nat_rules:
  - name: inside internet
    location: bottom
    group_tag: INSIDE
    from_zones: ['inside']
    to_zones: ['outside']
    service: any
    source_addresses: ['any']
    destination_addresses: ['any']
    source_translation_type: dynamic-ip-and-port
    source_translation_address_type: interface-address
    source_translation_interface: ethernet1/1
# - name: type2 nat
#   location: before
#   existing_rule: inside internet
#   group_tag: INSIDE
#   tags: ['PLAYSTATION']
#   from_zones: ['inside']
#   to_zones: ['outside']
#   service: any
#   source_addresses: ['playstation.local']
#   destination_addresses: ['any']
#   source_translation_type: dynamic-ip
#   source_translation_address_type: translated-address
#   source_translation_translated_addresses: ['outside.local']
```

## Reference Documentation

Please see the following for more info, including install instructions and complete documentation:

- [Module Reference](https://paloaltonetworks.github.io/pan-os-ansible/modules.html)
