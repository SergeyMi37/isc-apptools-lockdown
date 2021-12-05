![](https://github.com/SergeyMi37/isc-apptools-lockdown/blob/master/doc/Screenshot_5.png)
## isc-apptools-lockdown
[![Gitter](https://img.shields.io/badge/Available%20on-Intersystems%20Open%20Exchange-00b2a9.svg)](https://openexchange.intersystems.com/package/isc-apptools-lockdown)
[![GitHub all releases](https://img.shields.io/badge/Available%20on-GitHub-black)](https://github.com/SergeyMi37/isc-apptools-lockdown)
[![Habr](https://img.shields.io/badge/Available%20article%20on-Intersystems%20Community-orange)](https://community.intersystems.com/post/increasing-security-intersystems-iris-dbms)

 [![Quality Gate Status](https://community.objectscriptquality.com/api/project_badges/measure?project=intersystems_iris_community%2Fisc-apptools-lockdown&metric=alert_status)](https://community.objectscriptquality.com/dashboard?id=intersystems_iris_community%2Fisc-apptools-lockdown)
 <img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/SergeyMi37/isc-apptools-lockdown"> 
 [![license](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)



Program for changing the security level of the system.

## What's new
The ability to change the security level not only to lockdown, but also to minimum and normal has been implemented.
Added methods for saving the custom security level to the global and applying these settings to other instances


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

### Apply Security settings to "LockDown"

USER>do ##class(appmsw.security.lockdown).SetSecurityLevel("lockdown","NewPassword123")

or equivalent

USER>zpm "install isc-apptools-lockdown -Dzpm.securitylevel=lockdown -Dzpm.newpasswd=NewPassword123"


### Apply Security settings to "normal"

USER>do ##class(appmsw.security.lockdown).SetSecurityLevel("normal","NewPassword123")

or equivalent

USER>zpm "install isc-apptools-lockdown -Dzpm.securitylevel=normal -Dzpm.newpasswd=NewPassword123"



### Apply Security settings to "minimum"

USER>do ##class(appmsw.security.lockdown).SetSecurityLevel("minimum","SYS")

or equivalent

USER>zpm "install isc-apptools-lockdown -Dzpm.securitylevel=minimum -Dzpm.newpasswd=SYS"


## Added methods for saving the current security level to the global and applying these settings to other instances.

To do this, you need to save the current applied security settings: the values ​​of the Enabled and AutheEnabled parameters in the predefined objects of the Security.Applications, Security.Services and Security.System classes in the global by running the command

do ##class(appmsw.security.lockdown).SaveSecLevel(1,"Custom",,"d:\!\Custom.xml")

Import this Custom.xml global to the target instance and apply this applied security level there with the command

do ##class(appmsw.security.lockdown).SetSecurityLevel("Custom","Custom321level")

or

zpm "install isc-apptools-lockdown -Dzpm.securitylevel=Custom -Dzpm.newpasswd=Custom321level"

