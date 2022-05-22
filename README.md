# Endpoint Security Demo

This is a complete Xcode project of the Endpoint Security Demo gist: <https://gist.github.com/Omar-Ikram/8e6721d8e83a3da69b31d4c2612a68ba>

## Building

To build the project the 'Signing & Capabilities' section of the target needs to have a Team specified, but doing so will only allow the program to run on a SIP disabled machine (best use a VM to be safe). 

To build the project to run on a SIP protected machine, you need to update the 'Signing & Capabilities' section of the target with with a Team and Provisioning Profile that has been granted the 'com.apple.developer.endpoint-security.client' entitlement from [Apple](https://developer.apple.com/contact/request/system-extension/).

- Note: Assigning the 'com.apple.developer.endpoint-security.client' entitlement to a Provisioning Profile cannot be done directly via Xcode. It must first be done through the [Apple Developer Account](https://developer.apple.com/account/resources/profiles) and then have Xcode import the Provisioning Profile into project.

The build produces a command line program packaged as bundle. This is required so that the program has the Provisioning Profile for the System to validate against during runtime. 

## Running

The program needs to be run as root from the Terminal, which has been granted Full Disk access (best use a VM to be safe).

The program is treated as a command line program, but running it requires launching the binary inside the bundle: 
```bash
sudo ./EndpointSecurityDemo.app/Contents/MacOS/EndpointSecurityDemo serial
```
