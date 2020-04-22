/// Security utilities
Class App.Security.LockDown [ Abstract ]
{

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
/// 	d ##class(App.Security.LockDown).Apply("NewPassword123",.msg,1,1,0,0,0,0,"127.0.0.1","127.0.0.1")
/// 	d ##class(App.Security.LockDown).Apply("NewPassword123",.msg,1,1,0,0,1,0,"127.0.0.1","127.0.0.1",,1)
ClassMethod Apply(newPassword = "", Warn, sBindings = "", sCachedirect = "", InactiveLimit = 90, DemoDelete = 0, AuditOn = 1, sECP = "", sBindingsIP = "", sCachedirectIP = "", sECPIP = "", AuthLDAP = 0) As %Status
{
	set userlist=..GetPreparedUsers()
	new $namespace
	set $namespace="%SYS"
	write !,"Applications and services will be authenticated by "_$s('AuthLDAP:"password",1:"password and LDAP")
	set AutheEnabled=$s(AuthLDAP:2080,1:32) ;password
	s serviceCSP = $Select($Select($ZVersion["IRIS":1,1:0):"%service_webgateway",1:"%service_csp")
	if DemoDelete,$zv["IRIS" set DemoDelete=0	
	zn "%sys"
	if newPassword'="" {
		if newPassword'?8.32ANP s text="Password does not match the pattern 8.32ANP" write !,text QUIT $$$ERROR(text)
		write !,"Password is reset to predefined users"
		set tSC=..ChangePassword(newPassword, userlist)
		if '$$$ISOK(tSC) QUIT $$$ERROR(tSC)
		w !,"OK"
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
			if name=serviceCSP||(name="%service_console")||(name="%service_login") {
				set prop("Enabled")=1 ; turn on
				if name'=serviceCSP s prop("AutheEnabled")=AutheEnabled
				else  s prop("AutheEnabled")=96
			}
			if $G(sBindings),name="%service_bindings" {
				set prop("Enabled")=1
				set prop("AutheEnabled")=AutheEnabled
				set Warn($i(Warn))="If the current system does not intend to develop or edit the source code in CacheStudio, then it is better to turn off the service "_name
				set prop("ClientSystems")=sBindingsIP
			}
			if $G(sCachedirect),name="%service_cachedirect" {
				set prop("Enabled")=1 ; turn on
				set prop("AutheEnabled")=96
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
		w !,"OK"
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
	w !,"OK"
	}
	if DemoDelete {
		write !,"Demo namespaces are being deleted."
		for name="ENSDEMO","SAMPLES" {
			do:##class(%Dictionary.CompiledClass).%ExistsId("%Library.EnsembleMgr")
			set tSC = ##class(Config.Namespaces).Delete(name)
			if $$$ISERR(tSC) set text="Delete Error "_name_" :"_$system.Status.GetErrorText(tSC) w !,text
			if $$$ISOK(tSC) write !,"Deleted "_name
		}
		w !,"OK"
	}
	write !,"There is a modification of the basic system settings"
	#dim ss As Security.System  = ##class(Security.System).%OpenId("SYSTEM")
	set ss.PasswordPattern="8.32ANP"
	set ss.AuditEnabled=+AuditOn
	set ss.InactiveLimit=InactiveLimit
	set tSC=ss.%Save()
	if '$$$ISOK(tSC) s text="Error setting basic security settings :"_$SYSTEM.Status.GetErrorText(tSC)  write !,text QUIT $$$ERROR(text)
	w !,"OK"
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
	w !,"SUCSESS"
	quit $$$OK
}

/// do ##class(App.Security.LockDown).GetPreparedUsers()
ClassMethod GetPreparedUsers() As %String
{
  q "Admin,CSPSystem,IAM,SuperUser,UnknownUser,_Ensemble,_SYSTEM"
}

/// Change password for userlist
/// do ##class(App.Security.LockDown).ChangePassword("msw", ##class(App.Security.LockDown).GetPreparedUsers())
ClassMethod ChangePassword(newPassword = "", UsersList = "") As %Status
{
	new $namespace
	set $namespace="%SYS"
	set result=##CLASS(%ResultSet).%New("%DynamicQuery:SQL")
	set sql="select NameLowerCase FROM Security.Users where NameLowerCase in ('"_$replace($zconvert(UsersList,"L"),",","','")_"')"
	;w !,sql
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
			set prop("Password")=newPassword
			if name="_system" s prop("Enabled")=0
			if name="unknownuser" s prop("Roles")="" ; delete all roles
			set tSC=##class(Security.Users).Modify(name,.prop)
			if '$$$ISOK(tSC) w !,name_": Error="_$SYSTEM.Status.GetErrorText(tSC)
		}
	}
	q tSC
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
/// w ##class(App.Security.LockDown).CreateUser("test3", "%DB_IRISSYS,%DB_"_$namespace, "test", "Test user", $namespace, "", "", 0, 1, "Test user")
ClassMethod CreateUser(pUsername As %String, pRoles As %String, pPassword As %String, pFullName As %String, pNamespace As %String, pRoutine As %String = "", pExpirationDate As %String = "", pChangePassword As %Boolean = 0, pEnabled As %Boolean = 1, pComment As %String = "", pFlags As %String = 1)
{
	new $namespace
	set $namespace="%SYS"
	#dim tSC As %Status
	Set tSC=$$$OK,$ZT="Trap"
	s pNamespace=$zcvt(pNamespace,"U")
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
/// w ##class(App.Security.LockDown).CreateZMPUserFrom("test2", "%DB_IRISSYS,%DB_REGISTRY", "test2", "ZMP registry user")
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
	q tSC
}

/// Create ZPM user and LockDown
/// w ##class(App.Security.LockDown).Implement("UserZPM","PasswordUserZMP2","IRISAPP","NewPasswordFofSysUsers123")
ClassMethod Implement(pUsername As %String, pPassword As %String, NamespaceRegistry, NewPassSys)
{
	// 1. Cteate user from _system
	set tSC= ##class(App.Security.LockDown).CreateUser(pUsername, "%DB_"_NamespaceRegistry, pPassword, "ZMP registry user",NamespaceRegistry)
	If $$$ISERR(tSC) q tSC
	w !,"Create user "_pUsername

	// 2. Add privelege
	set tSC=##class(App.Security.LockDown).addSQLPrivilege(NamespaceRegistry, "1,ZPM.Package", "s", pUsername)
	set tSC=##class(App.Security.LockDown).addSQLPrivilege(NamespaceRegistry, "1,ZPM.Package_dependencies", "s", pUsername)
	set tSC=##class(App.Security.LockDown).addSQLPrivilege(NamespaceRegistry, "1,ZPM_Analytics.Event", "s", pUsername)
	set tSC=##class(App.Security.LockDown).addSQLPrivilege(NamespaceRegistry, "9,ZPM.Package_Extent", "e", pUsername)
	set tSC=##class(App.Security.LockDown).addSQLPrivilege(NamespaceRegistry, "9,ZPM_Analytics.Event_Extent", "e", pUsername)
	If $$$ISERR(tSC) q tSC
	w !,"Add priveleges "
	
	// 4. LockDown 
	set tSC= ##class(App.Security.LockDown).Apply(NewPassSys)

	// 3. AutheEnabled = 96 ; Password,Unauthenticated
	set prop("AutheEnabled")=96
	set tSC=##class(Security.Applications).Modify("/registry",.prop)
	q tSC
}

}

