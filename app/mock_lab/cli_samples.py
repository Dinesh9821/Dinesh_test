from __future__ import annotations

"""Canonical CLI samples used to prove parsers against real Cisco formats."""

SHOW_VERSION_IOSXE = """
Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.9.4a, RELEASE SOFTWARE
RTR-MUM-CORE uptime is 12 weeks, 3 days, 4 hours, 11 minutes
System returned to ROM by reload
System image file is "bootflash:isr4300-universalk9.17.09.04a.SPA.bin"
cisco ISR4331/K9 (1RU) processor with 1686561K/6147K bytes of memory.
Processor board ID FCZ1234CORE
"""

SHOW_CDP_DETAIL = """
Device ID: SW-MUM-DIST.lab.local
Entry address(es):
  IP address: 10.10.1.11
Platform: cisco C9300-24T,  Capabilities: Switch IGMP
Interface: GigabitEthernet0/0/1,  Port ID (outgoing port): TenGigabitEthernet1/1/1
Holdtime : 157 sec

Device ID: VEDGE-MUM-001
Entry address(es):
  IP address: 10.10.10.2
Platform: cisco C8000V,  Capabilities: Router
Interface: GigabitEthernet0/0/0,  Port ID (outgoing port): GigabitEthernet0/0/1
Holdtime : 141 sec
"""

SHOW_ARP = """
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.20.10.45             0   aabb.cc11.2245  ARPA   Vlan20
Internet  10.20.10.46             4   aabb.cc11.2246  ARPA   Vlan20
Internet  10.40.10.88             1   aabb.cc40.1088  ARPA   Vlan40
Internet  10.10.10.2              0   00aa.bbcc.dd02  ARPA   GigabitEthernet0/0/0
"""

SHOW_MAC = """
          Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  20    aabb.cc11.2245    DYNAMIC     Gi1/0/1
  20    aabb.cc11.2246    DYNAMIC     Gi1/0/2
  40    001a.2baa.0101    DYNAMIC     Gi1/0/1
"""

SHOW_CPU = """
CPU utilization for five seconds: 12%/3%; one minute: 28%; five minutes: 32%
"""

SHOW_IP_INT_BRIEF = """
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0/0   10.10.10.1      YES NVRAM  up                    up
GigabitEthernet0/0/1   10.10.20.1      YES NVRAM  up                    up
Vlan20                 10.20.10.1      YES NVRAM  up                    up
GigabitEthernet0/0/2   unassigned      YES NVRAM  administratively down down
"""

SHOW_INTERFACES = """
GigabitEthernet0/0/0 is up, line protocol is up
  Hardware is ISR4331, address is 001a.2b3c.4d01 (bia 001a.2b3c.4d01)
  Description: TO-VEDGE-MUM-001
  Internet address is 10.10.10.1/30
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
  5 minute input rate 180000000 bits/sec, 12000 packets/sec
  5 minute output rate 220000000 bits/sec, 14000 packets/sec
"""

SHOW_ROUTE = """
S*    0.0.0.0/0 [1/0] via 10.10.10.2, GigabitEthernet0/0/0
C        10.20.10.0/24 is directly connected, Vlan20
O        10.40.10.0/24 [110/2] via 10.10.20.2, 00:11:02, GigabitEthernet0/0/1
"""

SHOW_AP_SUMMARY = """
AP Name                            Slots AP Model  Ethernet MAC    Radio MAC       State
------------------------------------------------------------------------------------------------
AP-MUM-01                          2     C9120AXI  001a.2baa.0101  001a.2baa.1101  Registered
AP-MUM-02                          2     C9120AXI  001a.2baa.0102  001a.2baa.1102  Registered
"""

SHOW_CLIENTS = """
MAC Address          AP Name                           WLAN     State            IP Address
----------------------------------------------------------------------------------------------------------------
aabb.cc40.1088       AP-MUM-01                         MUM-CORP Run              10.40.10.88
"""
