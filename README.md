![](https://github.com/SergeyMi37/isc-apptools-lockdown/blob/master/doc/favicon.ico)
## isc-apptools-lockdown
[![Gitter](https://img.shields.io/badge/Available%20on-Intersystems%20Open%20Exchange-00b2a9.svg)](https://openexchange.intersystems.com/package/isc-apptools-lockdown)
[![GitHub all releases](https://img.shields.io/badge/Available%20on-GitHub-black)](https://github.com/SergeyMi37/isc-apptools-lockdown)
[![Habr](https://img.shields.io/badge/Available%20article%20on-Intersystems%20Community-orange)](https://community.intersystems.com/post/increasing-security-intersystems-iris-dbms)
[![license](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A program to enhance security and create users and add SQL privileges.

## Installation with ZPM

If ZPM the current instance is not installed, then in one line you can install the latest version of ZPM.
```
zn "%SYS" d ##class(Security.SSLConfigs).Create("z") s r=##class(%Net.HttpRequest).%New(),r.Server="pm.community.intersystems.com",r.SSLConfiguration="z" d r.Get("/packages/zpm/latest/installer"),$system.OBJ.LoadStream(r.HttpResponse.Data,"c")
```
If ZPM is installed, then can be set with the command
```
zpm:USER>install isc-apptools-lockdown
```
## Installation with Docker

## Prerequisites
Make sure you have [git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) and [Docker desktop](https://www.docker.com/products/docker-desktop) installed.

## Installation 
Clone/git pull the repo into any local directory

```
git clone https://github.com/SergeyMi37/isc-apptools-lockdown.git
```

Open the terminal in this directory and run:

```
docker-compose build
```

3. Run the IRIS container with your project:

```
docker-compose up -d
```

## How to Test it
Open IRIS terminal:

```
docker-compose exec iris iris session iris
```

## Increasing security settings
You can replace the shared password if the password of the predefined system users has been compromised
```
USER>do ##class(appmsw.security.lockdown).ChangePassword("NewPass231",##class(appmsw.security.lockdown).GetPreparedUsers())
```

Increase system security to LockDown
The method disables services and applications as in LockDown. Deletes the namespaces "DOCBOOK", "ENSDEMO", "SAMPLES"
The method enables auditing and configures registration of all events in the portal, except for switching the log
and modification of system properties
For all predefined users, change the password and change the properties as in LockDown
        newPassword - new single password instead of SYS. For LockDown security level, it has an 8.32ANP pattern
        sBindings = 1 Service% service_bindings enable
        sCachedirect = 1 Service% service_cachedirect enable
        InactiveLimit = 90
        DemoDelete = 0 Demoens, Samples namespaces are being deleted
		
        AuditOn = 1
        sECP = 1 Service% service_ecp enable
        sBindingsIP - list of ip addresses with a semicolon for which to allow CacheStudio connection.

For ECP configurations, you need to add the addresses of all servers and clients to allow connection on% Net.RemoteConnection to remove "abandoned" tasks
        sCachedirectIP - list of ip addresses with a semicolon for which to allow legacy applications connection.
        sECPIP - list of ip addresses with a semicolon for which to allow connection to the ECP server.
        AuthLDAP = 1 In addition to the password, also enable LDAP authentication

Apply Security settings to "LockDown"
```
USER>do ##class(appmsw.security.lockdown).Apply("NewPassword123",.msg,1,1,0,0)
```
or
```
USER>zpm "install isc-apptools-lockdown -Dzpm.newpasswd=NewPassword123"
```

All other features of the interface part of the software solution can be found in the 
[document](https://community.intersystems.com/post/increasing-security-intersystems-iris-dbms)
 or in an [article of a Russian resource](https://habr.com/en/post/436042/)
