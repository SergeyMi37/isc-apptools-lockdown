/// Security utilities
Class appmsw.security.lockdown [ Abstract ]
{

Parameter GN = "^appmsw.security.lockdown";

Parameter GNcustom = "^appmsw.security.custom";

/// do ##class(appmsw.security.lockdown).SetSecurityLevel("minimum","SYS")
/// do ##class(appmsw.security.lockdown).SetSecurityLevel("normal","Normal321level")
/// do ##class(appmsw.security.lockdown).SetSecurityLevel("lockdown","Lockdown321level")
ClassMethod SetSecurityLevel(level, newPassword = "SYS", Warn, sBindings = "", sCachedirect = "", InactiveLimit = 90, DemoDelete = 0, AuditOn = 1, sECP = "", sBindingsIP = "", sCachedirectIP = "", sECPIP = "", AuthLDAP = 0) As %Status
{
	
	quit:"none"[level||("null"[newPassword) $$$OK
	if level="lockdown" quit ..Apply(newPassword, .Warn, sBindings, sCachedirect, InactiveLimit, DemoDelete, AuditOn, sECP, sBindingsIP, sCachedirectIP, sECPIP, AuthLDAP)
	set GN=..#GN
	if '$lf($lb("minimum","normal","lockdown"),level) set GN=..#GNcustom
	if '$DATA(@GN@(level)) write !,"Security level '"_level_"' not saved in "_GN,! quit $$$OK
	write !,"Start switching the security level to the '"_level_"'",!
	merge State=@GN@(level)
	set userlist=..GetPreparedUsers()

	new $namespace
	set $namespace="%SYS"

	write !,"Modification of service properties:"
	set result=##CLASS(%ResultSet).%New("%DynamicQuery:SQL")
	set tSC=result.Prepare("select NameLowerCase,Enabled,AutheEnabled FROM Security.Services")
	set:tSC tSC=result.Execute()
	if '$$$ISOK(tSC) {
		set text="Service configuration error :"_$SYSTEM.Status.GetErrorText(tSC) write !,text
		QUIT $$$ERROR(text)
	}
	else {
		while result.Next() {
			set name=result.Data("NameLowerCase")
			continue:'$DATA(State("Security.Services",name))
			kill prop
			if $DATA(State("Security.Services",name,"Enabled"),val) set:result.Data("Enabled")'=val prop("Enabled")=val
			if $DATA(State("Security.Services",name,"AutheEnabled"),val) set:result.Data("AutheEnabled")'=val prop("AutheEnabled")=val
			if $D(prop) {
				set tSC=##class(Security.Services).Modify(name,.prop)
				if '$$$ISOK(tSC) write !,name_": Error="_$SYSTEM.Status.GetErrorText(tSC)
			}
		}
		write !,"OK"
	}
	write !,"Passwords are created for all CSP applications."
	set result=##CLASS(%ResultSet).%New("%DynamicQuery:SQL")
	set tSC=result.Prepare("select Name,Enabled,AutheEnabled FROM Security.Applications")
	set:tSC tSC=result.Execute()
	if '$$$ISOK(tSC) {
		set text="Application setup error :"_$SYSTEM.Status.GetErrorText(tSC)  write !,text QUIT $$$ERROR(text)
	}
	else {
		while result.Next() {
			set name=$zconvert(result.Data("Name"),"L")
			continue:'$DATA(State("Security.Applications",name))
			kill prop
			if $DATA(State("Security.Applications",name,"Enabled"),val) set:result.Data("Enabled")'=val prop("Enabled")=val
			if $DATA(State("Security.Applications",name,"AutheEnabled"),val) set:result.Data("AutheEnabled")'=val prop("AutheEnabled")=val
			if $D(prop) {
				set tSC=##class(Security.Applications).Modify(name,.prop)
			}
		 	if '$$$ISOK(tSC) write !,csp_" : Error="_$SYSTEM.Status.GetErrorText(tSC)
		}
	write !,"OK"
	}
	if $d(State("Security.System")) {
		write !,"There is a modification of the basic system settings"
		#dim ss As Security.System  = ##class(Security.System).%OpenId("SYSTEM")
		if $d(State("Security.System","PasswordPattern"),val) set ss.PasswordPattern=val
		if $d(State("Security.System","AuditEnabled"),val) set ss.AuditEnabled=val
		if $d(State("Security.System","InactiveLimit"),val) set ss.InactiveLimit=val
		set tSC=ss.%Save()
		if '$$$ISOK(tSC) s text="Error setting basic security settings :"_$SYSTEM.Status.GetErrorText(tSC)  write !,text QUIT $$$ERROR(text)
		write !,"OK"
	}
	if newPassword'="" {
		write !,"Password is reset to predefined users"
		set tSC=..ChangePassword(newPassword, userlist, level)
		if '$$$ISOK(tSC) QUIT $$$ERROR(tSC)
		write !,"OK"
	}
	quit $$$OK
}

/// Increase system security to LockDown
/// The method disables services and applications as in LockDown. Deletes the namespaces "DOCBOOK", "ENSDEMO", "SAMPLES"
/// The method enables auditing and configures registration of all events in the portal, except for switching the log
/// and modification of system properties
/// For all predefined users, change the password and change the properties as in LockDown
/// 	newPassword - new single password instead of %SYS. For LockDown security level, it has an 8.32ANP pattern
/// 	sBindings = 1 Service %Service_bindings enable
/// 	sCachedirect = 1 Service %Service_cachedirect enable
/// 	InactiveLimit=90  
/// 	DemoDelete=0 Demoens,Samples namespaces are being deleted 
/// 	AuditOn=1 
/// 	sECP = 1 Service %Service_ecp enable
/// 	sBindingsIP - list of ip addresses with a semicolon for which to allow CacheStudio connection.
/// 
/// For ECP configurations, you need to add the addresses of all servers and clients to allow connection on %Net.RemoteConnection to remove "abandoned" tasks
/// 	sCachedirectIP - list of ip addresses with a semicolon for which to allow legacy applications connection.
/// 	sECPIP - list of ip addresses with a semicolon for which to allow connection to the ECP server.
/// 	AuthLDAP = 1 In addition to the password, also enable LDAP authentication
/// 	Application example:
/// 	d ##class(appmsw.security.lockdown).Apply("NewPassword123",.msg,1,1,0,0,0,0,"127.0.0.1","127.0.0.1")
/// 	d ##class(appmsw.security.lockdown).Apply("NewPassword123",.msg,1,1,0,0,1,0,"127.0.0.1","127.0.0.1",,1)
ClassMethod Apply(newPassword = "", Warn, sBindings = "", sCachedirect = "", InactiveLimit = 90, DemoDelete = 0, AuditOn = 1, sECP = "", sBindingsIP = "", sCachedirectIP = "", sECPIP = "", AuthLDAP = 0) As %Status
{
	quit:"null"[newPassword $$$OK
	if (newPassword="SYS") { 
		quit ..Minimum(newPassword,.Warn, sBindings, sCachedirect, InactiveLimit, DemoDelete, AuditOn, sECP, sBindingsIP, sCachedirectIP, sECPIP, AuthLDAP)
	}
	set userlist=..GetPreparedUsers()
	new $namespace
	set $namespace="%SYS"
#define AutheK5CCache		1
#define AutheK5Prompt		2
#define AutheK5API			4
#define AutheK5KeyTab		8
#define AutheOS				16
#define AutheCache			32
#define AutheUnauthenticated 64
#define AutheKB				 128
#define AutheKBEncryption	 256
#define AutheKBIntegrity	 512
#define AutheSystem			1024
#define AutheLDAP			2048
	write !,"Applications and services will be authenticated by "_$s('AuthLDAP:"password",1:"password and LDAP")
	set AutheEnabled=$s(AuthLDAP:$$$AutheLDAP,1:$$$AutheCache) ;password

	set serviceCSP = "%service_csp"
	if $zv["IRIS" {
		set:DemoDelete DemoDelete=0
		set serviceCSP = "%service_webgateway"
	}

	if newPassword'="" {
		if newPassword'?8.32ANP s text="Password does not match the pattern 8.32ANP" write !,text QUIT $$$ERROR(text)
		write !,"Password is reset to predefined users"
		set tSC=..ChangePassword(newPassword, userlist)
		if '$$$ISOK(tSC) QUIT $$$ERROR(tSC)
		write !,"OK"
	}
	write !,"Modification of service properties:"
	set result=##CLASS(%ResultSet).%New("%DynamicQuery:SQL")
	set tSC=result.Prepare("select NameLowerCase,ClientSystems FROM Security.Services")
	set:tSC tSC=result.Execute()
	if '$$$ISOK(tSC) {
		set text="Service configuration error :"_$SYSTEM.Status.GetErrorText(tSC) write !,text
		QUIT $$$ERROR(text)
	}
	else {
		while result.Next() {
			set name=result.Data("NameLowerCase")
			#;skipping network services
			continue:(name="%service_mirror")||(name="%service_shadow")||(name="%service_datacheck")
			kill prop
			set prop("Enabled")=0
			if name=serviceCSP||(name="%service_terminal")||(name="%service_console")||(name="%service_login") {
				set prop("Enabled")=1 ; turn on
				if name'=serviceCSP s prop("AutheEnabled")=AutheEnabled
				else  s prop("AutheEnabled")=$$$AutheCache + $$$AutheUnauthenticated
			}
			if $G(sBindings),name="%service_bindings" {
				set prop("Enabled")=1
				set prop("AutheEnabled")=AutheEnabled
				set Warn($i(Warn))="If the current system does not intend to develop or edit the source code in CacheStudio, then it is better to turn off the service "_name
				set prop("ClientSystems")=sBindingsIP
			}
			if $G(sCachedirect),name="%service_cachedirect" {
				set prop("Enabled")=1 ; turn on
				set prop("AutheEnabled")=$$$AutheCache + $$$AutheUnauthenticated
				set Warn($i(Warn))="If the current system does not intend to legacy utility, then it is better to turn off the service "_name
				set prop("ClientSystems")=sCachedirectIP
			}
			if $G(sECP),name="%service_ecp" {
				set prop("Enabled")=1
				set Warn($i(Warn))="If the ECP configuration is not enabled on the current system, it is better to turn off the service "_name
				set:$g(sECPIP)="" Warn($i(Warn))="If ECP configuration is enabled, it is best to limit the connection of ECP clients to the ECP server"
				set prop("ClientSystems")=sECPIP
			}
			set tSC=##class(Security.Services).Modify(name,.prop)
			if '$$$ISOK(tSC) write !,name_": Error="_$SYSTEM.Status.GetErrorText(tSC)
		}
		write !,"OK"
	}
	write !,"Passwords are created for all CSP applications."
	set result=##CLASS(%ResultSet).%New("%DynamicQuery:SQL")
	set tSC=result.Prepare("select Name FROM Security.Applications")
	set:tSC tSC=result.Execute()
	if '$$$ISOK(tSC) {
		set text="Application setup error :"_$SYSTEM.Status.GetErrorText(tSC)  write !,text QUIT $$$ERROR(text)
	}
	else {
		#; List of disconnected applications
		set appDisabled("/csp/ensdemo")=1
		set appDisabled("/csp/samples")=1
		set appDisabled("/csp/user")=1
		set appDisabled("/isc/studio/usertemplates")=1
		set appDisabled("/csp/docbook")=1  
		set appDisabled("/csp/documatic")=1
		set appDisabled("/isc/studio/rules")=1
		set appDisabled("/isc/studio/templates")=1
		while result.Next() {
			set CSP=result.Data("Name")
			set csp=$zconvert(CSP,"L")
			kill prop
			if $g(appDisabled(csp)) {
				set prop("Enabled")=0
			} else {
				  set prop("Enabled")=1
			}
		 set prop("AutheEnabled")=AutheEnabled 
		 set tSC=##class(Security.Applications).Modify(CSP,.prop)
		 if '$$$ISOK(tSC) write !,csp_" : Error="_$SYSTEM.Status.GetErrorText(tSC)
		}
	write !,"OK"
	}
	if DemoDelete {
		write !,"Demo namespaces are being deleted."
		for name="ENSDEMO","SAMPLES" {
			do:##class(%Dictionary.CompiledClass).%ExistsId("%Library.EnsembleMgr")
			set tSC = ##class(Config.Namespaces).Delete(name)
			if $$$ISERR(tSC) set text="Delete Error "_name_" :"_$system.Status.GetErrorText(tSC) w !,text
			if $$$ISOK(tSC) write !,"Deleted "_name
		}
		write !,"OK"
	}
	write !,"There is a modification of the basic system settings"
	#dim ss As Security.System  = ##class(Security.System).%OpenId("SYSTEM")
	set ss.PasswordPattern="8.32ANP"
	set ss.AuditEnabled=+AuditOn
	set ss.InactiveLimit=InactiveLimit
	set tSC=ss.%Save()
	if '$$$ISOK(tSC) s text="Error setting basic security settings :"_$SYSTEM.Status.GetErrorText(tSC)  write !,text QUIT $$$ERROR(text)
	write !,"OK"
	if AuditOn {
		write !,"Event Setup AUDIT :"
		Set rs = ##class(%ResultSet).%New("Security.Events:ListActivate")
		Set tSC = rs.Execute()
		if $$$ISERR(tSC) set text="Event setting error AUDIT:"_$system.Status.GetErrorText(tSC) write !,text QUIT $$$ERROR(text)
		set On("%Ensemble/%Message/ViewContents")=1
		set On("%System/%DirectMode/DirectMode")=1
		set On("%System/%Login/Login")=1
		set On("%System/%Login/LoginFailure")=1
		set On("%System/%Login/Logout")=1
		set On("%System/%Login/Terminate")=1
		set On("%System/%Security/ApplicationChange")=1
		set On("%System/%Security/AuditChange")=1
		set On("%System/%Security/AuditReport")=1
		set On("%System/%Security/DBEncChange")=1
		set On("%System/%Security/DomainChange")=1
		set On("%System/%Security/LoginRuleChange")=1
		set On("%System/%Security/Protect")=1
		set On("%System/%Security/ResourceChange")=1
		set On("%System/%Security/RoleChange")=1
		set On("%System/%Security/ServiceChange")=1
		set On("%System/%Security/SSLConfigChange")=1
		set On("%System/%Security/SystemChange")=1
		set On("%System/%Security/UserChange")=1
		set On("%System/%System/AuditRecordLost")=1
		set On("%System/%System/ConfigurationChange")=1
		set On("%System/%System/JournalChange")=0
		set On("%System/%System/RoutineChange")=1
		set On("%System/%System/Start")=1
		set On("%System/%System/Stop")=1
		set On("%System/%System/SuspendResume")=1
		set On("%System/%System/UserEventOverflow")=1
		While rs.Next() {
			set name = $G(rs.Data("Source"))_"/"_$G(rs.Data("Type"))_"/"_$G(rs.Data("Name"))
			if $DATA(On(name)) {
				kill pro
				do ##class(Security.Events).Get($g(rs.Data("Source")),$G(rs.Data("Type")),$G(rs.Data("Name")),.pro)
				if $d(pro) {
					if pro("Enabled")'=(+$G(On(name))) {
						if ##Class(Security.Events).Exists(name,,,.Event,.Status) {
							set Event.Enabled=+$G(On(name))
							set tSC=Event.%Save()
							if '$$$ISOK(tSC) w !,name_": Error="_$SYSTEM.Status.GetErrorText(tSC)
							else  write !,name_" changed"
						}
					}
				}
			}
		}
		do rs.Close()
	}
	write !,"Finish Lockdown SUCSESS"
	quit $$$OK
}

/// do ##class(appmsw.security.lockdown).GetPreparedUsers()
ClassMethod GetPreparedUsers() As %String
{
  quit "Admin,CSPSystem,IAM,SuperUser,UnknownUser,_Ensemble,_SYSTEM"
}

/// Change password for userlist
/// do ##class(appmsw.security.lockdown).ChangePassword("msw", ##class(appmsw.security.lockdown).GetPreparedUsers())
ClassMethod ChangePassword(newPassword = "", UsersList = "", level = "lockdown") As %Status
{
	new $namespace
	set $namespace="%SYS"
	set result=##CLASS(%ResultSet).%New("%DynamicQuery:SQL")
	set sql="select NameLowerCase FROM Security.Users where NameLowerCase in ('"_$replace($zconvert(UsersList,"L"),",","','")_"')"
	set tSC=result.Prepare(sql)
	set:tSC tSC=result.Execute()
	if '$$$ISOK(tSC) {
		set text="User configuration error :"_$SYSTEM.Status.GetErrorText(tSC) write !,text
		QUIT $$$ERROR(text)
	}
	else {
		while result.Next() {
			set name=result.Data("NameLowerCase")
			;w !,name continue
			kill prop
			if level="lockdown" {
				set prop("Password")=newPassword
				if name="_system" s prop("Enabled")=0
				if name="unknownuser" s prop("Roles")="" ; delete all roles
			}
			elseif level="normal" {
				set prop("Password")=newPassword
				if name="_system" s prop("Enabled")=1
				if name="unknownuser" s prop("Roles")="" ; delete all roles
			}
			elseif level="minimum" {
				set prop("Password")=newPassword
				if name="_system" s prop("Enabled")=1
				if name="unknownuser" s prop("Roles")="%All" ; delete all roles
			}
			set tSC=##class(Security.Users).Modify(name,.prop)
			if '$$$ISOK(tSC) w !,name_": Error="_$SYSTEM.Status.GetErrorText(tSC)
		}
	}
	quit tSC
}

/// Helper method to add privileges to users
/// select * from Security.SQLPrivileges where Grantee='test2' and SQLObject['ZPM'
ClassMethod addSQLPrivilege(pNamespace As %String, pSQLObject As %String, pPrivilege As %String, pGrantee As %String, pGrantable As %Boolean = 0, pGrantor As %String = "_system") As %Status
{
	new $namespace
	set $namespace="%SYS"
	Set tStatus = $$$OK
	Set tPrivilege = $e(pPrivilege,1)
	If '##class(Security.SQLPrivileges).IDKeyExists(pNamespace, pSQLObject, tPrivilege, pGrantee, pGrantor) {
		Set tSQLPriv = ##class(Security.SQLPrivileges).%New()
		Set tSQLPriv.Namespace = pNamespace
		Set tSQLPriv.SQLObject = pSQLObject
		Set tSQLPriv.Grantable = pGrantable
		Set tSQLPriv.Grantee = pGrantee
		Set tSQLPriv.Privilege = tPrivilege
		Set tSQLPriv.Grantor = pGrantor
		Set tStatus = tSQLPriv.%Save()
		If $$$ISERR(tStatus) Quit
	}
	Quit tStatus
}

/// Create a security user
/// w ##class(appmsw.security.lockdown).CreateUser("test3", "%DB_IRISSYS,%DB_"_$namespace, "test", "Test user", $namespace, "", "", 0, 1, "Test user")
ClassMethod CreateUser(pUsername As %String, pRoles As %String, pPassword As %String, pFullName As %String, pNamespace As %String, pRoutine As %String = "", pExpirationDate As %String = "", pChangePassword As %Boolean = 0, pEnabled As %Boolean = 1, pComment As %String = "", pFlags As %String = 1)
{
	new $namespace
	set $namespace="%SYS"
	#dim tSC As %Status
	Set tSC=$$$OK,$ZT="Trap"
	set pNamespace=$zcvt(pNamespace,"U")
	Do {
		#dim tExists As %Boolean
		Set tExists = ##class(Security.Users).Exists(pUsername)
		If 'tExists {
			// Create a new user
			Set tSC = ##class(Security.Users).Create(pUsername,
													 pRoles,
													 pPassword,
													 pFullName,
													 pNamespace,
													 pRoutine,
													 pExpirationDate,
													 pChangePassword,
													 pEnabled,
													 pComment,
													 pFlags)
		} Else {
			// User already exists, let's modify
			#dim tProperties
			Set tProperties("Roles")=pRoles
			Set tProperties("Password")=pPassword
			Set tProperties("FullName")=pFullName
			Set tProperties("NameSpace")=pNamespace
			Set tProperties("Routine")=pRoutine
			Set tProperties("ExpirationDate")=pExpirationDate
			Set tProperties("ChangePassword")=pChangePassword
			Set tProperties("Enabled")=pEnabled
			Set tProperties("Comment")=pComment

			// Now, modify this user
			Set tSC = ##class(Security.Users).Modify(pUsername, .tProperties)
		}

	} While (0)
Exit
	If $$$ISERR(tSC) Set $ZT="" q tSC
	Quit $$$OK
Trap
	Set $ZT="",tSC=$$$ERROR($$$ObjectScriptError,$ZE)
	Goto Exit
}

/// Create ZPM user from _system
/// w ##class(appmsw.security.lockdown).CreateZMPUserFrom("test2", "%DB_IRISSYS,%DB_REGISTRY", "test2", "ZMP registry user")
ClassMethod CreateZMPUserFrom(pUsername As %String, pRoles As %String, pPassword As %String, pFullName As %String, from As %String = "_system")
{
	new $namespace
	set $namespace="%SYS"
	Set tSC = ##class(Security.Users).Copy(from, pUsername, pFullName)
	If $$$ISERR(tSC) q tSC
	#dim tProperties
	Set tProperties("Roles")=pRoles
	Set tProperties("Password")=pPassword
	Set tProperties("ChangePassword")=0
	Set tProperties("Enabled")=1
	Set tSC = ##class(Security.Users).Modify(pUsername, .tProperties)
	quit tSC
}

/// Create new Role
ClassMethod CreateRole(dbName As %String) As %Status
{
   New $Namespace
   Set $Namespace = "%SYS"
   Set sc = $$$OK
   set nameR="%DB_"_dbName,desc="Role for "_nameR 
	set pResources=nameR_":RW" 
	if '##class(Security.Resources).Exists(nameR) {
		Set sc = $$$ADDSC(sc,##class(Security.Resources).Create(nameR,"Resources for "_nameR,"RW"))
		Quit:$$$ISERR(sc) sc
	}
	set pRolesGranted=""
	if '##class(Security.Roles).Exists(nameR) {
		Set sc = $$$ADDSC(sc,##class(Security.Roles).Create(nameR,desc,pResources,pRolesGranted))
		Quit:$$$ISERR(sc) sc
		write !,"Create new role "_nameR
	}
	Return sc
}

/// Create new Resource
ClassMethod CreateResource(dbName As %String, Permiss As %String = "RW") As %Status
{
   New $Namespace
   Set $Namespace = "%SYS"
   Set sc = $$$OK
   set nameR="%DB_"_dbName,desc="Resource for "_nameR 
	if '##class(Security.Resources).Exists(nameR) {
		Set sc = $$$ADDSC(sc,##class(Security.Resources).Create(nameR,desc,Permiss))
		Quit:$$$ISERR(sc) sc
		write !,"Create new Resource "_nameR
	}
	Return sc
}

/// Delete Resource
ClassMethod DeleteResource(dbName As %String) As %Status
{
 New $Namespace
 Set $Namespace = "%SYS"
 Set sc = $$$OK
   set nameR="%DB_"_dbName
	if ##class(Security.Resources).Exists(nameR) {
		Set sc = $$$ADDSC(sc,##class(Security.Resources).Delete(nameR))
		Quit:$$$ISERR(sc) sc
		write !,"Delete Resource "_nameR
	}
	Return sc
}

/// Delete Role
ClassMethod DeleteRole(dbName As %String) As %Status
{
 New $Namespace
 Set $Namespace = "%SYS"
 Set sc = $$$OK
   set nameR="%DB_"_dbName
	if ##class(Security.Roles).Exists(nameR) {
		Set sc = $$$ADDSC(sc,##class(Security.Roles).Delete(nameR))
		Quit:$$$ISERR(sc) sc
		write !,"Delete role "_nameR
	}
	Return sc
}

/// Save Current Security Level
/// do ##class(appmsw.security.lockdown).SaveSecLevel(1,"minimum",,"d:\_proj\!\minimum.xml")
/// do ##class(appmsw.security.lockdown).SaveSecLevel(1,"normal",,"d:\_proj\!\normal.xml")
/// do ##class(appmsw.security.lockdown).SaveSecLevel(1,"lockdown",,"d:\_proj\!\lock.xml")
/// do ##class(appmsw.security.lockdown).SaveSecLevel(1,"Custom",,"d:\_proj\!\Custom.xml")
ClassMethod SaveSecLevel(resave = 0, level = "minimum", GN = {..#GN}, pFileName = "") As %Status
{
	if '$lf($lb("minimum","normal","lockdown"),level) set GN=..#GNcustom
	KILL @GN@(level)
	do ##class(appmsw.security.lockdown).SaveProperties(resave,"Security.Services",.out,level,GN)
	do ##class(appmsw.security.lockdown).SaveProperties(resave,"Security.Applications",.out,level,GN)
	set cns=$namespace
	new $namespace
	set $namespace="%SYS"
	#dim ss As Security.System  = ##class(Security.System).%OpenId("SYSTEM")
	zn cns
	if resave {
		set @GN@(level,"Security.System","PasswordPattern")=ss.PasswordPattern
		set @GN@(level,"Security.System","AuditEnabled")=ss.AuditEnabled
		set @GN@(level,"Security.System","InactiveLimit")=ss.InactiveLimit
	}
	if pFileName'="" {
		kill list
		set list(GN_".GBL")=""
		set st=$SYSTEM.OBJ.Export(.list, pFileName)
		if st write !,pFileName

	}
}

/// Save Properties
/// do ##class(appmsw.security.lockdown).SaveProperties(0,"Security.Applications",.out)
ClassMethod SaveProperties(resave = 0, obj As %String = "Security.Services", out, level = "minimum", GN = {..#GN}) As %Status
{
	set cns=$namespace
	new $namespace
	set $namespace="%SYS"
	set sql="select NameLowerCase FROM "_obj
	write !,"Show properties: "_sql
	set tSC=$$$OK
	set result=##CLASS(%ResultSet).%New("%DynamicQuery:SQL")
	set tSC=result.Prepare(sql)
	set:tSC tSC=result.Execute()
	if '$$$ISOK(tSC) {
		set text="Service configuration error :"_$SYSTEM.Status.GetErrorText(tSC) write !,text
		QUIT $$$ERROR(text)
	}
	else {
		while result.Next() {
			set name=result.Data("NameLowerCase")
			set tSC=$classmethod(obj,"Get",name,.prop)
			set out(name,"Enabled")=prop("Enabled")
			set out(name,"AutheEnabled")=prop("AutheEnabled")
		}
	}
	set i=""
	for ii=1:1 { set i=$o(out(i)) quit:i=""
		write !
		zwrite out(i)
	}
	if resave, GN'="" zn cns merge @GN@(level,obj)=out write $na(@GN@(level,obj))
	quit tSC
}

/// Save this Project
/// do ##class(appmsw.security.lockdown).SaveProj("d:\_proj\_mygirhub\isc-apptools-lockdown-2\isc-apptools-lockdown\")
ClassMethod SaveProj(path) As %Status
{
 //	---------------- save
	zpm "generate "_path_"src\ -export 00000,appmsw"
	kill list
	set list("appmsw.security.lockdown.GBL")=""
	set st=$SYSTEM.OBJ.Export(.list, path_"src\gbl\appmsw.security.lockdown.xml")

 //------- load
 ;zn "%SYS" d ##class(Security.SSLConfigs).Create("z") s r=##class(%Net.HttpRequest).%New(),r.Server="pm.community.intersystems.com",r.SSLConfiguration="z" d r.Get("/packages/zpm/latest/installer"),$system.OBJ.LoadStream(r.HttpResponse.Data,"c")
 ;zpm "load d:\_proj\_mygirhub\isc-apptools-lockdown-2\isc-apptools-lockdown"
 ;do ##class(appmsw.security.lockdown).SaveSecLevel(1,"normal",,"d:\_proj\!\normal.xml")
}

}

