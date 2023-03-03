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
- **Allowlisting** - Devices located in the allowlist file will processed.  Other devices will be ignored.  The path to the allowlist is passed in as a command line option with the `-a` flag. Each address should be placed on a newline.  All hex letters should be in uppercase.

## Set Up
Two changes need to be made to Bluetooth settings on the machine running the BBPTT to ensure that the following vulnerabilities are tested:
- CVE-2017-0781
- CVE-2017-0782
- CVE-2017-0783
- CVE-2017-8628
> **WARNING**: These changes will make the device running the BBPTT less secure and should be reversed when not running the tool.

First, the Bluetooth service needs to enable Just Works pairing with Bluetooth.  This can be done by:
1. Opening the configuration file found at `/etc/bluetooth/main.conf`.
2. Uncomment the `# JustWorksRepairing` option.
3. Set the value to `JustWorksRepairing = true` or `JustWorksRepairing = always` depending on the installed version of bluez.
4. Restart the Bluetooth service by running `sudo systemctl restart bluetooth`.

Next, the host machine needs to configure its Bluetooth agent to respond to I/O capability requests with `NoInputNoOutput`.  To do this using the `bluetoothctl` tool, run the following commands:
```
# sudo bluetoothctl
[bluetooth]# agent off
[bluetooth]# agent NoInputNoOutput
```
## Building
The BBPTT is built using [CMake](https://cmake.org). Run the following commands from the project root to build the project executable:
```
cmake clean .
make
```
An executable called bluebornepentest will be created under the ./bin directory, and the unit test executable called check_bbptt will be created under the ./tests directory.

## Running
Usage: `./bluebornepentest [-h] [-a ./path/to/allowlist] [-p poll_interval]`

|Flag|Description|Default|
|----|-----------|-------|
|`-h`|Prints usage|N/A|
|`-a ./path/to/allowlist`|Full or relative path to an allowlist file.|allowlist.txt|
|`-p poll_interval`|Poll interval in seconds.  Must be a positive integer|30|

After running make from the root of the project, unit tests can be run as follows:
```
cd tests
./check_bbptt
```
## Docker
Dockerfiles are provided with the BBPTT in order to facilitate the creation and set up of test environments that are still vulnerable to the BlueBorne exploits.

### Prerequisites
- [Docker](https://www.docker.com/) - A set of Platform-as-a-Service products that use OS-level virtualization to deliver applications and environemnts.

### Linux / Ubuntu
In order to create an Ububtu testing environment, the bluetooth service on the host machine must be stopped.  It is important to stop the service directly using the `kill` command and not through systemctl or systemd.  Shutting down the service manager can shut down the Bluetooth adapter and make it unavailable to the container.  This can be done using the following commands:
```
# Find the PID of the Bluetooth service
sudo ps aux | grep bluetoothd
sudo kill -9 <bluetoothd pid>
```
Once the service has been terminated, the docker container can be built and run using the following commands:
```
cd ./docker/ubuntu

# Build the image
docker build -t bbptt-env-ubuntu --no-cache=true .

# Run the container in interactive mode
docker run --rm --net=host --privileged -it bbptt-env-ubuntu:latest

```
The `./docker/ubuntu/docker_entrypoint.sh` script starts the bluetooth service on the Ubuntu container.
