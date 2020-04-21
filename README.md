![](https://github.com/SergeyMi37/isc-apptools-lockdown/blob/master/doc/favicon.ico)
## isc-apptools-lockdown
[![Gitter](https://img.shields.io/badge/Available%20on-Intersystems%20Open%20Exchange-00b2a9.svg)](https://openexchange.intersystems.com/package/isc-apptools-lockdown)

A program to enhance security and create users and add SQL privileges.

## Installation with ZPM

zpm:USER>install isc-apptools-lockdown

## Installation with Docker

## Prerequisites
Make sure you have [git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) and [Docker desktop](https://www.docker.com/products/docker-desktop) installed.

## Installation 
Clone/git pull the repo into any local directory

```
$ git clone https://github.com/SergeyMi37/isc-apptools-lockdown.git
```

Open the terminal in this directory and run:

```
$ docker-compose build
```

3. Run the IRIS container with your project:

```
$ docker-compose up -d
```

## How to Test it
Open IRIS terminal:

```
$ docker-compose exec iris iris session iris
```

## Increasing security settings
You can replace the shared password if the password of the predefined system users has been compromised
```
IRISAPP>do ##class(App.LockDown).ChangePassword("NewPass231",##class(App.LockDown).GetPreparedUsers())
```

Application to the LockedDown system, if it was installed with the initial security settings, minimum or normal.
You can get and study the description of the method parameters with such a command, like any other element of any other class.
```
IRISAPP>write ##class(App.msg).man("App.LockDown).Apply")

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
...
```

Apply Security settings to "LockDown"
```
IRISAPP>do ##class(App.LockDown).Apply("NewPassword123",.msg,1,1,0,0)

Applications and services will be authenticated by password
Password is reset to predefined users
Modification of service properties:
%service_cachedirect: Error=ERROR #787: Service %Service_CacheDirect not allowed by license
Passwords are created for all CSP applications.
There is a modification of the basic system settings
Event Setup AUDIT :
%System/%DirectMode/DirectMode changed
%System/%Login/Login changed
%System/%Login/Logout changed
%System/%Login/Terminate changed
%System/%Security/Protect changed
%System/%System/JournalChange changed
%System/%System/RoutineChange changed
%System/%System/SuspendResume changed

```

All other features of the interface part of the software solution can be found in the 
[document](https://github.com/SergeyMi37/isc-apptools-admin/blob/master/doc/Documentation%20AppTools.pdf)
 or in an [article of a Russian resource](https://habr.com/en/post/436042/)
