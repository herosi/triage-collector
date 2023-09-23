Description: System Basic Info
Author: hnashiwa
Version: 1.0
Id: 8da84227-2be4-43c1-92cb-fc70ae1f9e94
Keys:
#   SYSTEM hive
    -
        Description: Reg-SYSTEM-Setup\CloneTag
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Setup
        ValueName: CloneTag
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-Select
        HiveType: SYSTEM
        Category: System Info
        KeyPath: Select
        ValueName: Current
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-BAM
        HiveType: SYSTEM
        Category: Execution Artifact
        KeyPath: ControlSet*\Services\bam\State\UserSettings\*
        IncludeBinary: true
        BinaryConvert: FILETIME
        Recursive: true
        Comment:
    -
        Description: Reg-SYSTEM-EnvironmentVals
        HiveType: SYSTEM
        Category: System Setting
        KeyPath: ControlSet*\Control\Session Manager\Environment
        Recursive: true
        Comment:
    -
        Description: Reg-SYSTEM-UseLogonCredential
        HiveType: SYSTEM
        Category: System Setting
        KeyPath: ControlSet*\Control\SecurityProviders\WDigest
        ValueName: UseLogonCredential
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-LSA
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\LSA
        ValueName: Authentication Packages
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-LSA
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\LSA
        ValueName: Notification Packages
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-LSA
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\LSA
        ValueName: Security Packages
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-LSA
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\LSA\OsConfig
        ValueName: Security Packages
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-Print
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\Print\Monitors\*
        ValueName: Driver
        Recursive: true
        Comment:
    -
        Description: Reg-SYSTEM-Print
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\Print\Providers\*
        Recursive: true
        Comment:
    -
        Description: Reg-SYSTEM-Print
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Control\SecurityProviders
        ValueName: SecurityProviders
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-PortProxy\v4tov4\tcp
        HiveType: SYSTEM
        Category: System Setting
        KeyPath: ControlSet*\Services\PortProxy\v4tov4\tcp
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-PersistentRoutes
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services\Tcpip\Parameters\PersistentRoutes
        Recursive: true
        Comment:
    -
        Description: Reg-SYSTEM-Services
        HiveType: SYSTEM
        Category: ASEP
        KeyPath: ControlSet*\Services
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-BasicInfo
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\Windows
        ValueName: ShutdownTime
        Recursive: false
        IncludeBinary: true
        BinaryConvert: FILETIME
        Comment:
    -
        Description: Reg-SYSTEM-BasicInfo
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters
        ValueName: Hostname
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-BasicInfo
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Control\ComputerName\ComputerName
        ValueName: ComputerName
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-BasicInfo
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: EnableDHCP
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-BasicInfo
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: Domain
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-BasicInfo
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: NameServer
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-BasicInfo
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpServer
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-BasicInfo
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: IPAddress
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-BasicInfo
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: SubnetMask
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-BasicInfo
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DefaultGateway
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-BasicInfo
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpNameServer
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-BasicInfo
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpDomain
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-BasicInfo
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpIPAddress
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-BasicInfo
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpSubnetMask
        Recursive: false
        Comment:
    -
        Description: Reg-SYSTEM-BasicInfo
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        ValueName: DhcpDefaultGateway
        Recursive: false
        Comment:

#   SOFTWARE Hive
    -
        Description: Reg-SOFTWARE-CLSID-DLL
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\CLSID\*\InprocServer32
        ValueName: (default)
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-CLSID-DLL
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\CLSID\*\InprocServer32
        ValueName: Assembly
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-CLSID-EXE
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\CLSID\*\LocalServer32
        ValueName: (default)
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-CLSID-EXE
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\CLSID\*\LocalServer32
        ValueName: Assembly
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Wow64-CLSID-DLL
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\CLSID\*\InprocServer32
        ValueName: (default)
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Wow64-CLSID-DLL
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\CLSID\*\InprocServer32
        ValueName: Assembly
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Wow64-CLSID-EXE
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\CLSID\*\LocalServer32
        ValueName: (default)
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Wow64-CLSID-EXE
        HiveType: Software
        Category: ASEP
        KeyPath: Classes\Wow6432Node\CLSID\*\LocalServer32
        ValueName: Assembly
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-WindowsDefender
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows Defender
        ValueName: DisableAntiSpyware
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-WindowsDefender
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows Defender
        ValueName: DisableAntiVirus
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-WindowsDefender
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows Defender
        ValueName: ServiceStartStates
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-WindowsDefender\Exclusions
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows Defender\Exclusions\*
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-WindowsDefender\Real-Time
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows Defender\Real-Time Protection
        ValueName: DisableRealtimeMonitoring
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-WindowsDefender\Spyne
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows Defender\Spynet
        ValueName: SpyNetReporting
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-WindowsDefender\Spynet
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows Defender\Spynet
        ValueName: SubmitSamplesConsent
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Policies-WindowsDefender
        HiveType: Software
        Category: System Setting
        KeyPath: Policies\Microsoft\Windows Defender
        ValueName: DisableAntiSpyware
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Policies-WindowsDefender
        HiveType: Software
        Category: System Setting
        KeyPath: Policies\Microsoft\Windows Defender
        ValueName: DisableAntiVirus
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Policies-WindowsDefender
        HiveType: Software
        Category: System Setting
        KeyPath: Policies\Microsoft\Windows Defender
        ValueName: ServiceStartStates
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Policies-WindowsDefender\Exclusions\*
        HiveType: Software
        Category: System Setting
        KeyPath: Policies\Microsoft\Windows Defender\Exclusions
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-Policies-WindowsDefender\Real-Time
        HiveType: Software
        Category: System Setting
        KeyPath: Policies\Microsoft\Windows Defender\Real-Time Protection
        ValueName: DisableRealtimeMonitoring
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Policies-WindowsDefender\Spynet
        HiveType: Software
        Category: System Setting
        KeyPath: Policies\Microsoft\Windows Defender\Spynet
        ValueName: SpyNetReporting
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Policies-WindowsDefender\Spynet
        HiveType: Software
        Category: System Setting
        KeyPath: Policies\Microsoft\Windows Defender\Spynet
        ValueName: SubmitSamplesConsent
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-GroupPolicy\History
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows\CurrentVersion\Group Policy\History
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-GroupPolicy\History
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows\CurrentVersion\Group Policy\History\*\*
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-GroupPolicy\Scripts\Startup
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-Classes\Installer\Products
        HiveType: Software
        Category: Installed Application
        KeyPath: Classes\Installer\Products\*
        ValueName: ProductName
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Run
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Run
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-RunOnce
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Runonce
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-RunOnceEx
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\RunOnceEx
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-RunServices
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\RunServices
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-RunServicesOnce
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\RunServicesOnce
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-Wow64-Run
        HiveType: Software
        Category: ASEP
        KeyPath: WOW6432Node\Microsoft\Windows\CurrentVersion\Run
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-Wow64-RunOnce
        HiveType: Software
        Category: ASEP
        KeyPath: WOW6432Node\Microsoft\Windows\CurrentVersion\Runonce
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-Wow64-RunOnceEx
        HiveType: Software
        Category: ASEP
        KeyPath: WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-Wow64-RunServices
        HiveType: Software
        Category: ASEP
        KeyPath: WOW6432Node\Microsoft\Windows\CurrentVersion\RunServices
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-Wow64-RunServicesOnce
        HiveType: Software
        Category: ASEP
        KeyPath: WOW6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-Policies\Explorer\Run
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-Wow64-Policies\Explorer\Run
        HiveType: Software
        Category: ASEP
        KeyPath: WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-TerminalServer-Run
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-TerminalServer-RunOnce
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-TerminalServer-RunOnceEx
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-Explorer\StartupApproved\Run
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\StartupApproved\Run
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-Explorer\StartupApproved\Run32
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\StartupApproved\Run32
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-Explorer\StartupApproved\StartupFolder
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows\CurrentVersion\StartupApproved\StartupFolder
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-TaskCache
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{*}
        ValueName: Author
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-TaskCache
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{*}
        IncludeBinary: true
        ValueName: Actions
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-TaskCache
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{*}
        ValueName: Path
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-TaskCache
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{*}
        ValueName: Date
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-TaskCache
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{*}
        ValueName: URI
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-TaskCache
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*
        ValueName: Id
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-TaskCache
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*\*
        ValueName: Id
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-TaskCache
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\*\*
        ValueName: Id
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-TaskCache
        HiveType: Software
        Category: ASEP
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\*\*
        ValueName: Id
        Recursive: true
        Comment:
    -
        Description: Reg-SOFTWARE-Explorer\Advanced
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows\CurrentVersion\Explorer\Advanced
        ValueName: Start_TrackDocs
        Recursive: false
        Comment: default value = 1
    -
        Description: Reg-SOFTWARE-Policies\Explorer
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows\CurrentVersion\Policies\Explorer
        ValueName: NoRecentDocsHistory
        Recursive: false
        Comment: default value = 0
    -
        Description: Reg-SOFTWARE-Microsoft.Powershell
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell
        ValueName: ExecutionPolicy
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Wow64-Microsoft.Powershell
        HiveType: Software
        Category: System Setting
        KeyPath: WOW6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell
        ValueName: ExecutionPolicy
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Policies\System
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows\CurrentVersion\policies\system
        ValueName: EnableLUA
        Recursive: false
        Comment: default = 1
    -
        Description: Reg-SOFTWARE-Policies\System
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows\CurrentVersion\policies\system
        ValueName: EnableVirtualization
        Recursive: false
        Comment: default = 1
    -
        Description: Reg-SOFTWARE-Policies\System
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows\CurrentVersion\policies\system
        ValueName: FilterAdministratorToken
        Recursive: false
        Comment: default = 0
    -
        Description: Reg-SOFTWARE-Policies\System
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows\CurrentVersion\policies\system
        ValueName: ConsentPromptBehaviorAdmin
        Recursive: false
        Comment: default = 5
    -
        Description: Reg-SOFTWARE-Policies\System
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows\CurrentVersion\policies\system
        ValueName: ConsentPromptBehaviorUser
        Recursive: false
        Comment: default = 3
    -
        Description: Reg-SOFTWARE-ProfileList
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\ProfileList\*
        ValueName: ProfileImagePath
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-NetworkList\Profiles
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*
        ValueName: ProfileName
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-NetworkList\Profiles
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*
        ValueName: Description
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-NetworkList\Profiles
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*
        ValueName: Managed
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-NetworkList\Profiles
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*
        ValueName: Category
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-NetworkList\Profiles
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*
        ValueName: DataCreated
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-NetworkList\Profiles
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*
        ValueName: NameType
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-NetworkList\Profiles
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*
        ValueName: DataLastConnected
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-NetworkList\Signatures
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\*\*
        ValueName: ProfileGuid
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-NetworkList\Signatures
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\*\*
        ValueName: Description
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-NetworkList\Signatures
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\*\*
        ValueName: Source
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-NetworkList\Signatures
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\*\*
        ValueName: DndSuffix
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-NetworkList\Signatures
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\*\*
        ValueName: FirstNetwork
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-NetworkList\Signatures
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\*\*
        ValueName: DefaultGatewayMac
        IncludeBinary: true
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Tracing
        HiveType: Software
        Category: Execution Artifact
        KeyPath: Microsoft\Tracing\*
        ValueName: EnableFileTracing
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Wow64-Tracing
        HiveType: Software
        Category: Execution Artifact
        KeyPath: WOW6432Node\Microsoft\Tracing\*
        ValueName: EnableFileTracing
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Uninstall
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows\CurrentVersion\Uninstall\*
        ValueName: DisplayName
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Uninstall
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows\CurrentVersion\Uninstall\*
        ValueName: DisplayVersion
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Uninstall
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows\CurrentVersion\Uninstall\*
        ValueName: InstallDate
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Uninstall
        HiveType: Software
        Category: System Setting
        KeyPath: Microsoft\Windows\CurrentVersion\Uninstall\*
        ValueName: InstallSource
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Wow64-Uninstall
        HiveType: Software
        Category: System Setting
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
        ValueName: DisplayName
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Wow64-Uninstall
        HiveType: Software
        Category: System Setting
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
        ValueName: DisplayVersion
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Wow64-Uninstall
        HiveType: Software
        Category: System Setting
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
        ValueName: InstallDate
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-Wow64-Uninstall
        HiveType: Software
        Category: System Setting
        KeyPath: Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
        ValueName: InstallSource
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-ProductName
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: ProductName
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-BuildLabEx
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: BuildLabEx
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-InstallTime
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: InstallTime
        IncludeBinary: true
        BinaryConvert: FILETIME
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-BasicInfo
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: CompositionEditionID
        Recursive: false
        Comment:
    -
        Description: Reg-SOFTWARE-BasicInfo
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: ReleaseID
        Recursive: false
        Comment:

# NTUSER Hive
    -
        Description: Reg-NTUSER-RecentDocs
        HiveType: NtUser
        Category: System Info
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
        Recursive: true
        Comment:
    -
        Description: Reg-NTUSER-MountPoints2
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
        Recursive: true
        Comment:
    -
        Description: Reg-NTUSER-ComDlg32
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-ComDlg32
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\FirstFolder
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-ComDlg32
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-ComDlg32
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-ComDlg32
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-ComDlg32
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU
        Recursive: true
        Comment:
    -
        Description: Reg-NTUSER-ComDlg32
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
        Recursive: true
        Comment:
    -
        Description: Reg-NTUSER-EnvironmentVals
        HiveType: NtUser
        Category: System Setting
        KeyPath: Environment
        Recursive: true
        Comment:
    -
        Description: Reg-NTUSER-RecentFileList
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\*\*\Recent File List
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-RecentFolderList
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\*\*\Recent Folder List
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-RecentDocumentList
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\*\*\Settings\Recent Document List
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-MapNetworkDriveMRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software/Microsoft/Windows/CurrentVersion/Explorer/MapNetworkDriveMRU
        Recursive: true
        Comment:
    -
        Description: Reg-NTUSER-OfficeMRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Office\*\*\User MRU\*\File MRU
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-OfficeMRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Office\*\*\User MRU\*\Place MRU
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-AdobeMRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Adobe\Acrobat Reader\DC\AVGeneral\cRecentFiles\*
        ValueName: tDIText
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-AdobeMRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Adobe\Acrobat Reader\DC\AVGeneral\cRecentFolders\*
        ValueName: tDIText
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-AdobeMRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Adobe\Adobe Acrobat\DC\AVGeneral\cRecentFiles\*
        ValueName: tDIText
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-AdobeMRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Adobe\Adobe Acrobat\DC\AVGeneral\cRecentFolders\*
        ValueName: tDIText
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-PuTTY\SshHostKeys
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\SimonTatham\PuTTY\SshHostKeys
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-RecentApps
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Search\RecentApps
        Recursive: true
        Comment:
    -
        Description: Reg-NTUSER-Run
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-RunOnce
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-RunOnceEx
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunOnceEx
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-RunServices
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunServices
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-RunServicesOnce
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Wow64-Run
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Wow64-RunOnce
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Wow64-RunOnceEx
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Wow64-RunServices
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Wow64-RunServicesOnce
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-TerminalServer-Run
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-TerminalServer-RunOnce
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-TerminalServer-RunOnceEx
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Policies\Explorer\Run
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Wow64-Policies\Explorer\Run
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-GroupPolicy\Scripts\Logon
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\*
        ValueName: DisplayName
        Recursive: true
        Comment:
    -
        Description: Reg-NTUSER-Explorer\StartupApproved\Run
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\StartupApproved\Run
        Recursive: true
        Comment:
    -
        Description: Reg-NTUSER-Explorer\StartupApproved\Run32
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\StartupApproved\Run32
        Recursive: true
        Comment:
    -
        Description: Reg-NTUSER-Explorer\StartupApproved\StartupFolder
        HiveType: ntuser
        Category: ASEP
        KeyPath: Software\Microsoft\Windows\CurrentVersion\StartupApproved\StartupFolder
        Recursive: true
        Comment:
    -
        Description: Reg-NTUSER-Explorer\RunMRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-7-Zip
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\7-Zip\Compression
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Wow64-7-Zip
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Wow6432Node\7-Zip\Compression
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-SHC
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\UFH\SHC
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-SysInternals
        HiveType: NtUser
        Category: Execution Artifact
        KeyPath: SSOFTWARE\Sysinternals\*
        ValueName: EulaAccepted
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-TypedURLs
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Internet Explorer\TypedURLs
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-TypedURLsTime
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Internet Explorer\TypedURLsTime
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Uninstall
        HiveType: NtUser
        Category: Installed Software
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Uninstall\*
        ValueName: DisplayName
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Uninstall
        HiveType: NtUser
        Category: Installed Software
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Uninstall\*
        ValueName: DisplayVersion
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Uninstall
        HiveType: NtUser
        Category: Installed Software
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Uninstall\*
        ValueName: InstallDate
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Uninstall
        HiveType: NtUser
        Category: Installed Software
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Uninstall\*
        ValueName: InstallSource
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Wow64-Uninstall
        HiveType: NtUser
        Category: Installed Software
        KeyPath: Wow6432Node\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
        ValueName: DisplayName
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Wow64-Uninstall
        HiveType: NtUser
        Category: Installed Software
        KeyPath: Wow6432Node\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
        ValueName: DisplayVersion
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Wow64-Uninstall
        HiveType: NtUser
        Category: Installed Software
        KeyPath: Wow6432Node\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
        ValueName: InstallDate
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Wow64-Uninstall
        HiveType: NtUser
        Category: Installed Software
        KeyPath: Wow6432Node\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
        ValueName: InstallSource
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-UserAssist
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-WinRAR\ArcHistory
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\WinRar\ArcHistory
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-WinSCP
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Martin Prikryl\WinSCP 2
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-WinZip
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Nico Mak Computing\WinZip
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-MUICache
        HiveType: NTUSER
        Category: Execution Artifact
        KeyPath: Software\Microsoft\Windows\ShellNoRoam\MUICache
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Explorer\Advanced
        HiveType: NTUSER
        Category: System Setting
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
        ValueName: Start_TrackDocs
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-Policies\Explorer
        HiveType: NTUSER
        Category: System Setting
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
        ValueName: NoRecentDocsHistory
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-TerminalServerClient\Default
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Terminal Server Client\Default
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-TerminalServerClient\Servers
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Terminal Server Client\Servers\*
        ValueName: UsernameHint
        Recursive: false
        Comment:
    -
        Description: Reg-NTUSER-FirstLogon
        HiveType: NTUSER
        Category: User Activity
        KeyPath: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\LogonStats
        ValueName: FirstLogonTimeOnCurrentInstallation
        IncludeBinary: true
        Comment:
    -
        Description: Reg-NTUSER-FirstLogon
        HiveType: NTUSER
        Category: User Activity
        KeyPath: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\LogonStats
        ValueName: FirstLogonTime
        IncludeBinary: true
        Comment:

# UsrClass Hive
    -
        Description: Reg-UsrClass-CLSID-DLL
        HiveType: usrclass
        Category: ASEP
        KeyPath: CLSID\*\InprocServer32
        ValueName: (default)
        Recursive: false
        Comment:
    -
        Description: Reg-UsrClass-CLSID-DLL
        HiveType: usrclass
        Category: ASEP
        KeyPath: CLSID\*\InprocServer32
        ValueName: Assembly
        Recursive: false
        Comment:
    -
        Description: Reg-UsrClass-CLSID-EXE
        HiveType: usrclass
        Category: ASEP
        KeyPath: CLSID\*\LocalServer32
        ValueName: (default)
        Recursive: false
        Comment:
    -
        Description: Reg-UsrClass-CLSID-EXE
        HiveType: usrclass
        Category: ASEP
        KeyPath: CLSID\*\LocalServer32
        ValueName: Assembly
        Recursive: false
        Comment:
    -
        Description: Reg-UsrClass-Wow64-CLSID-DLL
        HiveType: usrclass
        Category: ASEP
        KeyPath: Wow6432Node\CLSID\*\InprocServer32
        ValueName: (default)
        Recursive: false
        Comment:
    -
        Description: Reg-UsrClass-Wow64-CLSID-DLL
        HiveType: usrclass
        Category: ASEP
        KeyPath: Wow6432Node\CLSID\*\InprocServer32
        ValueName: Assembly
        Recursive: false
        Comment:
    -
        Description: Reg-UsrClass-Wow64-CLSID-EXE
        HiveType: usrclass
        Category: ASEP
        KeyPath: Wow6432Node\CLSID\*\LocalServer32
        ValueName: (default)
        Recursive: false
        Comment:
    -
        Description: Reg-UsrClass-Wow64-CLSID-EXE
        HiveType: usrclass
        Category: ASEP
        KeyPath: Wow6432Node\CLSID\*\LocalServer32
        ValueName: Assembly
        Recursive: false
        Comment:
    -
        Description: Reg-UsrClass-MUICache
        HiveType: UsrClass
        Category: Execution Artifact
        KeyPath: Local Settings\Software\Microsoft\Windows\Shell\MuiCache
        Recursive: false
        Comment:






