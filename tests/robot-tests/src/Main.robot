*** Settings ***
Library         Collections
Library         OperatingSystem
Library         String
Library		Process
Library		BuiltIn
Library         SysrepoLibrary
Library 	XML

Resource 	PluginInit.resource

Test Setup 	Startup
Test Teardown 	Cleanup

*** Test Cases ***
Test Get External Interface Name
	[Documentation] 	Check if it's possible to get data values from the snabb config
	Log To Console     ${Connection} ${Session Running}
	${Interface Name}= 	Get Datastore Data 	${Connection} 	
	... 	${Session Running} 	/softwire-config/instance/external-device 	xml
	Element Text Should Be 	${Interface Name}   aftrv4 	xpath=*/external-device

Test Add softwire
	[Documentation] 	Creates a new softwire entry to the datastore and check if it has been added to the snabb lwaftr config
	${New softwire}= 	catenate 	SEPARATOR=
	...	<softwire> 
	...		<ipv4>0.0.0.0</ipv4>
	...		<psid>1</psid>
	... 		<padding>0</padding>
	...		<br-address>1e:1:1:1:1:1:1:af</br-address>
	...		<b4-ipv6>127:24:35:46:57:68:79:128</b4-ipv6>
	...		<port-set>
	...			<psid-length>16</psid-length>
	...			<reserved-ports-bit-count>0</reserved-ports-bit-count>
	...		</port-set>
	...	</softwire>

	${New softwire entry}= 	catenate 	SEPARATOR=
	...	<softwire-config xmlns="snabb:softwire-v3">
	...		<binding-table>
	... 			${New softwire}
	...		</binding-table>
	...	</softwire-config>
	Edit Datastore Config 	${Connection} 	${Session Running} 	${New softwire entry} 	xml
	${Datastore state}= 	Get Datastore Data 	${Connection} 	${Session Running}
	... 	* 	xml
	${Softwire Elements}= 	Get Elements 	${Datastore state} 	xpath=*/softwire
	${tmp}=    Element to String  ${Softwire Elements}[1]
	Elements Should Be Equal   ${New softwire}	${Softwire Elements}[1]
