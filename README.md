[comment]: # "Auto-generated SOAR connector documentation"
# Microsoft SCOM

Publisher: Splunk  
Connector Version: 2\.1\.1  
Product Vendor: Microsoft  
Product Name: SCOM  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app integrates with Microsoft System Center Operations Manager \(SCOM\) to execute investigative actions

[comment]: # "    File: README.md"
[comment]: # "    Copyright (c) 2017-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
Windows Remote Management(WinRM) should be enabled on the MS SCOM Server for the app to run commands
remotely. To allow HTTP communication, WinRM config parameter **AllowUnencrypted** should be changed
to true on SCOM server.

By default WinRM HTTP uses port 80. On Windows 7 and higher the default port is 5985.  
By default WinRM HTTPS uses port 443. On Windows 7 and higher the default port is 5986.

This app uses NTLM authorization. The use of the HTTP_PROXY and HTTPS_PROXY environment variables is
currently unsupported.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a SCOM asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server\_url** |  required  | string | Server URL
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**username** |  required  | string | Username
**password** |  required  | password | Password

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[list endpoints](#action-list-endpoints) - List all the endpoints/sensors configured on the device  
[list alerts](#action-list-alerts) - List all active alerts  
[get device info](#action-get-device-info) - Get information about device  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list endpoints'
List all the endpoints/sensors configured on the device

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  optional  | Domain | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.ActionAccountIdentity | string | 
action\_result\.data\.\*\.AuthenticationName | string | 
action\_result\.data\.\*\.CommunicationPort | string |  `port` 
action\_result\.data\.\*\.ComputerName | string |  `host name` 
action\_result\.data\.\*\.CreateListener | string | 
action\_result\.data\.\*\.DisplayName | string | 
action\_result\.data\.\*\.Domain | string |  `domain` 
action\_result\.data\.\*\.HealthState | string | 
action\_result\.data\.\*\.HeartbeatInterval | string | 
action\_result\.data\.\*\.HostComputer | string | 
action\_result\.data\.\*\.HostedHealthService | string | 
action\_result\.data\.\*\.IPAddress | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.Id | string | 
action\_result\.data\.\*\.InstallTime | string | 
action\_result\.data\.\*\.InstalledBy | string |  `user name` 
action\_result\.data\.\*\.LastModified | string | 
action\_result\.data\.\*\.ManagementGroup | string | 
action\_result\.data\.\*\.ManagementGroupId | string | 
action\_result\.data\.\*\.ManuallyInstalled | string | 
action\_result\.data\.\*\.MaximumQueueSizeBytes | string | 
action\_result\.data\.\*\.MaximumSizeOfAllTransferredFilesBytes | string | 
action\_result\.data\.\*\.Name | string |  `host name` 
action\_result\.data\.\*\.NetworkName | string | 
action\_result\.data\.\*\.PatchList | string | 
action\_result\.data\.\*\.PrimaryManagementServerName | string |  `host name` 
action\_result\.data\.\*\.PrincipalName | string | 
action\_result\.data\.\*\.ProxyingEnabled | string | 
action\_result\.data\.\*\.RequestCompression | string | 
action\_result\.data\.\*\.Version | string | 
action\_result\.summary\.total\_endpoints | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list alerts'
List all active alerts

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**computer\_name** |  optional  | Computer Name | string |  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.computer\_name | string |  `host name` 
action\_result\.data\.\*\.Category | string | 
action\_result\.data\.\*\.ClassId | string | 
action\_result\.data\.\*\.ConnectorId | string | 
action\_result\.data\.\*\.ConnectorStatus | string | 
action\_result\.data\.\*\.Context | string | 
action\_result\.data\.\*\.CustomField1 | string | 
action\_result\.data\.\*\.CustomField10 | string | 
action\_result\.data\.\*\.CustomField2 | string | 
action\_result\.data\.\*\.CustomField3 | string | 
action\_result\.data\.\*\.CustomField4 | string | 
action\_result\.data\.\*\.CustomField5 | string | 
action\_result\.data\.\*\.CustomField6 | string | 
action\_result\.data\.\*\.CustomField7 | string | 
action\_result\.data\.\*\.CustomField8 | string | 
action\_result\.data\.\*\.CustomField9 | string | 
action\_result\.data\.\*\.Description | string | 
action\_result\.data\.\*\.Id | string | 
action\_result\.data\.\*\.IsMonitorAlert | string | 
action\_result\.data\.\*\.LastModified | string | 
action\_result\.data\.\*\.LastModifiedBy | string | 
action\_result\.data\.\*\.LastModifiedByNonConnector | string | 
action\_result\.data\.\*\.MaintenanceModeLastModified | string | 
action\_result\.data\.\*\.ManagementGroup | string | 
action\_result\.data\.\*\.ManagementGroupId | string | 
action\_result\.data\.\*\.MonitoringClassId | string | 
action\_result\.data\.\*\.MonitoringObjectDisplayName | string | 
action\_result\.data\.\*\.MonitoringObjectFullName | string | 
action\_result\.data\.\*\.MonitoringObjectHealthState | string | 
action\_result\.data\.\*\.MonitoringObjectId | string | 
action\_result\.data\.\*\.MonitoringObjectInMaintenanceMode | string | 
action\_result\.data\.\*\.MonitoringObjectName | string | 
action\_result\.data\.\*\.MonitoringObjectPath | string | 
action\_result\.data\.\*\.MonitoringRuleId | string | 
action\_result\.data\.\*\.Name | string | 
action\_result\.data\.\*\.NetbiosComputerName | string |  `host name` 
action\_result\.data\.\*\.NetbiosDomainName | string |  `domain` 
action\_result\.data\.\*\.Owner | string | 
action\_result\.data\.\*\.Parameters | string | 
action\_result\.data\.\*\.PrincipalName | string | 
action\_result\.data\.\*\.Priority | string | 
action\_result\.data\.\*\.ProblemId | string | 
action\_result\.data\.\*\.RepeatCount | string | 
action\_result\.data\.\*\.ResolutionState | string | 
action\_result\.data\.\*\.ResolvedBy | string | 
action\_result\.data\.\*\.RuleId | string | 
action\_result\.data\.\*\.Severity | string | 
action\_result\.data\.\*\.SiteName | string | 
action\_result\.data\.\*\.StateLastModified | string | 
action\_result\.data\.\*\.TfsWorkItemId | string | 
action\_result\.data\.\*\.TfsWorkItemOwner | string | 
action\_result\.data\.\*\.TicketId | string | 
action\_result\.data\.\*\.TimeAdded | string | 
action\_result\.data\.\*\.TimeRaised | string | 
action\_result\.data\.\*\.TimeResolutionStateLastModified | string | 
action\_result\.data\.\*\.TimeResolved | string | 
action\_result\.data\.\*\.UnformattedDescription | string | 
action\_result\.summary\.total\_alerts | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get device info'
Get information about device

Type: **investigate**  
Read only: **True**

Either <b>ip</b> or <b>computer\_name</b> needs to be specified\. If <b>ip</b> is provided <b>computer\_name</b> is ignored\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  optional  | IP address | string |  `ip`  `ipv6` 
**computer\_name** |  optional  | Computer name | string |  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.computer\_name | string |  `host name` 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.ActionAccountIdentity | string | 
action\_result\.data\.\*\.AuthenticationName | string | 
action\_result\.data\.\*\.CommunicationPort | string |  `port` 
action\_result\.data\.\*\.ComputerName | string |  `host name` 
action\_result\.data\.\*\.CreateListener | string | 
action\_result\.data\.\*\.DisplayName | string | 
action\_result\.data\.\*\.Domain | string |  `domain` 
action\_result\.data\.\*\.HealthState | string | 
action\_result\.data\.\*\.HeartbeatInterval | string | 
action\_result\.data\.\*\.HostComputer | string | 
action\_result\.data\.\*\.HostedHealthService | string | 
action\_result\.data\.\*\.IPAddress | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.Id | string | 
action\_result\.data\.\*\.InstallTime | string | 
action\_result\.data\.\*\.InstalledBy | string |  `user name` 
action\_result\.data\.\*\.LastModified | string | 
action\_result\.data\.\*\.ManagementGroup | string | 
action\_result\.data\.\*\.ManagementGroupId | string | 
action\_result\.data\.\*\.ManuallyInstalled | string | 
action\_result\.data\.\*\.MaximumQueueSizeBytes | string | 
action\_result\.data\.\*\.MaximumSizeOfAllTransferredFilesBytes | string | 
action\_result\.data\.\*\.Name | string |  `host name` 
action\_result\.data\.\*\.NetworkName | string | 
action\_result\.data\.\*\.PatchList | string | 
action\_result\.data\.\*\.PrimaryManagementServerName | string |  `host name` 
action\_result\.data\.\*\.PrincipalName | string | 
action\_result\.data\.\*\.ProxyingEnabled | string | 
action\_result\.data\.\*\.RequestCompression | string | 
action\_result\.data\.\*\.Version | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 