# BlueBorne Penetration Testing Tool
## Description
The BlueBorne Penetration Testing Tool (BBPTT) is to create a tool that checks nearby devices for BlueBorne security vulnerabilities. If vulnerable devices are found nearby, the BBPTT will attempt to execute the exploits. In order to prevent accidental unauthorized access, the tool will only target devices that are allowlisted. Nearby devices on the allowlist will be targeted. The results of the vulnerability scan that identifies vulnerable devices and the results of any implemented exploits will be logged using the syslog messaging standard.

BlueBorne is a family of zero-day security vulnerabilities in the Bluetooth stack that was discovered by Armis Labs in 2017. The BlueBorne attack can target unpatched devices with Bluetooth turned on, even if they are not in discovery mode. At the time, the only way to protect against the exploit was to turn Bluetooth off. BlueBorne attacks are particularly dangerous because they can be executed without any action by the user, and they can target devices on air-gapped networks.

BlueBorne vulnerabilities are found in Android, Windows, Linux, and iOS devices. The vulnerabilities differ depending on the implementation of the Bluetooth stack on the operating system (OS). The exploits include Information Leaks, Remote Code Execution (RCE), Man-in-the-Middle (MitM) attacks, and remote control over the device or Arbitrary Code Execution (ACE).

Although many devices impacted by BlueBorne vulnerabilities have been patched, a large number still remain. Traditional network security measures, such as firewalls and Intrusion Prevention Systems (IPS), are built for internet traffic and do not offer protection against Bluetooth attacks. Given the inability of these tools to prevent Bluetooth attacks, more tools should be made available to administrators looking to protect their networks.

The BBPTT runs on a Linux server. Periodically, it will search for nearby Bluetooth devices. When it encounters a new device, it will identify the device type based on the MAC address Organizationally Unique Identifier (OUI). Then, the BBPTT will send packets crafted to identify BlueBorne vulnerabilities based on the device type. The results of the vulnerability scan will be logged using the Syslog message format to make integrations with existing logging and monitoring solutions easier. A list of devices that have already been checked will be kept in memory so that devices are not scanned more than once. In order to prevent the tool from scanning devices that it is not authorized for, an allowlist will be implemented so only devices with matching Bluetooth MAC addresses will be scanned.

## Libraries
- [BlueZ](http://www.bluez.org/) - The official Linux Bluetooth protocol stack.
- [Check](https://libcheck.github.io/check/) - Unit testing framework for C.

## Features

## Building
The BBPTT is built using [CMake](https://cmake.org). Run the following commands from the project root to build the project executable:
```
cmake clean .
make
```
An executable called bluebornepentest will be created under the ./bin directory, and the unit test executable called check_bbptt will be created under the ./tests directory.

## Running
The BBPTT can be run as follows:
```
./bin/bluebornepentest
```
Unit tests can be run as follows:
```
./tests/check_bbptt
```
