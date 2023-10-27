# Integration tests for sysrepo-snabb-plugin

# Requirements
* Sysrepo 
* Snabb
* Libyang
* Python packages inside of "requirements.txt"
* Robot framework

# Running
Before running the tests for the first time run the as ```setup.sh``` script
as root, also make sure that you have built the the plugin and have snabb installed.
The script will fetch the configuration file for the tests and 
create the virtual interfaces needed for execution of the tests.
It will also create a python virtual environment with the needed 
python packages.

Activate virtual python environment with
```
source ./test-venv/bin/activate
```

After you have done all that, you may run the tests with
```
robot ./src/Main.robot
```
