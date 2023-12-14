** Settings ***
Library         OperatingSystem
Library         SysrepoLibrary


*** Variables ***
${CONFIG_FILE_PATH} 	 	config/lwaftr-start.conf
${SNABB_LWAFTR_INSTANCE_NAME}   sysrepo-snabb-plugin-test

*** Keywords ***

Start Plugin
	${Plugin}=    Start Process    sysrepo-snabb-plugin
	Set Global Variable    ${Plugin}
	Wait For Process    ${Plugin}    timeout=0.5s    on_timeout=continue

Stop Plugin
	Terminate Process    ${Plugin}

Connect To Softwire
	${Connection}=         Open Sysrepo Connection
	Set Global Variable    ${Connection}
	${Session Running}=    Open Datastore Session    ${Connection}    running
	Set Global Variable    ${Session Running}

Start Snabb
	${Snabb}=    Start Process    snabb     lwaftr run --config ${CONFIG_FILE_PATH} --name ${SNABB_LWAFTR_INSTANCE_NAME}
	Set Global Variable    ${Snabb}
	Wait For Process    ${Plugin}    timeout=0.5s    on_timeout=continue

Stop Snabb
	Terminate Process    ${Snabb}

Startup
	Start Plugin
	Start Snabb
	Set Global Variable    ${SNABB_LWAFTR_INSTANCE_NAME}
	Connect To Softwire

Cleanup
	Stop Plugin
	Stop Snabb
