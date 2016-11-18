# Active Directory access to openvpn

An application to delegate logon rights via ActiveDirectory and domain credentials. Supports access group and reject group.

### Installation

Depends on:
* Installed Mono to compile/run the application
* Installed and configured OpenVPN

Compile C# code with:
```sh
xbuild openvpn_ldap.sln
```
You need to add this to OpenVPN configuration file:

```sh
auth-user-pass-verify '/usr/local/bin/mono /root/path/to/openvpn_ldap.exe' via-env
```
Place configuration file near exe to openvpn_ldap.exe.config

### Configuration file

An application supports these options:

`domain:`domain name, such as domain.name.com  
**Default**: none  
**Required**: true 

`accessGroups:`Names of ActiveDirectory groups to allow access.   
**Default**: none  
**Required**: false 

`deniedGroups:`Names of ActiveDirectory groups to deny access.  
**Default**: none  
**Required**: false

`domainController:`domain controller FQDN.  
**Default**: none  
**Required**: true 

`domainControllerPort:`domain controller port to connect.  
**Default**: 389  
**Required**: false 
 
`enableSSL:`enable to use SSL connection to LDAP.  
**Default**: false  
**Required**: false 
