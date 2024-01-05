# Summary

1. [Description](#description)
2. [Installation](#installation)
3. [Hello command (discovery)](#hello-command-discovery)
4. [Server_config command](#server_config-command)
5. [Read_data command] (#read_data-command)
6. [Write_data command] (#write_data-command)

<br>

# Description

This tool is based on the metasploit module [msf-opcua](https://github.com/COMSYS/msf-opcua), so we would like to thank their author : Linus Roepert, Markus Dahlmanns, Ina Berenice Fink, Jan Pennekamp and Martin Henze.

During OPC UA security assessments, this tool can be used to detect OPC UA instances, and gather information about the endpoint configurations and on the access control of the nodes.

# Installation

1. If not already installed, install `python3`.
2. Then, run the command

```
pip3 install -r requirements.txt
```

You can either use "python3" or "./" to execute the script.

<br>

# Display global help

```
./opcua_scan.py -h
```

<br>

# Hello command (discovery)

**The hello command sends HEL/ACK messages in order to locate OPC UA instances.**

<br>

## Display hello command help

```
./opcua_scan.py hello -h
```

## Scan

One target :

```
./opcua_scan.py hello -i 127.0.0.1 -p 53530
```

Multiple ports :

```
./opcua_scan.py hello -i 127.0.0.1 -p '5060-5065, 53530'
```

Multiple IPs :

```
./opcua_scan.py hello -i '127.0.0.1-5, 127.0.0.9' -p 80
```

You can scan multiple IPs, on multiple ports. IPs are parsed thanks to [ipparser](https://github.com/m8sec/ipparser), thus, you can use any syntax accepted by this library to choose your targets.

<br>

### Options

- Name (`-n, --name`) : Configure the name of the server in the URL opc:tcp://IP:PORT/NAME. You can use a file containing a list of names to test (each name separated with a new line)

```
./opcua_scan.py hello -i '127.0.0.1' -p 4840 -n UADiscovery

./opcua_scan.py hello -i '127.0.0.1' -p 4840 -n /path/to/name_list.txt
```

<br>

- Output (`-o, --output`) : store data about all the server detected in a file. This file can then be parsed by the server_config command

```
./opcua_scan.py hello -i '127.0.0.1-5' -p 4840 -o ./file_output.json
```

<br>

- Timeout (`-t, --timeout`) : change the timeout to consider a connection as failed in milliseconds (Default: 500)

```
./opcua_scan.py hello -i 127.0.0.1 -p 53530 -t 200
```

<br>

- Verbose (`-v, --verbose`) : display each target tested, even if there is no OPC UA server detected

```
./opcua_scan.py hello -i 127.0.0.1 -p '5060-5065' -v
```

<br>

- Table format (`-tfmt, --table_format`) : change the format of the generated summary table (see tabulate documentation for the list of accepted formats, e.g. outline, grid...). Default value is "outline".

```
./opcua_scan.py hello -i 127.0.0.1 -p '5060-5065' -tfmt plain
```

<br>

# Server_config command

The server_config command can be used to gather security related information about OPC UA servers. Some data does not require to be authenticated to be gathered, such as the endpoint descriptions. But an access is required to retrieve information on the server's nodes.

<br>

## Display server_config command help

```
./opcua_scan.py server_config -h
```

## Scan

One target :

```
./opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer'
```

Multiple targets :

```
./opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer, opc.tcp://127.0.0.1:4840/ServerName'
```

Targets detected by the hello command :

```
./opcua_scan.py server_config -t 'path/to/hello_output.json'
```

<br>

### Options

- Authentication (`-a, --authentication`) : The authentication method to be used (default: Anonymous)

```
./opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Anonymous
```

<br>

- Username (`-u, --username`) and password (`-p, --password`) : The username and password for the authentication

```
./opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password
```

<br>

- Security mode (`-m, --mode`) and policy (`-po, --policy`) : The security mode and associated policy of the targeted endpoint
- Certificate (`-c, --certificate`) and private key (`-pk, --private_key`) : The certificate and the associated private key for the authentication and/or encryption

```
./opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password -m SignAndEncrypt -po Basic256Sha256 -c certificate.pem -pk private_key.pem

./opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Certificate -c certificate.pem -pk private_key.pem

```

<br>

- Find writable nodes (`-nw, nodes_writable`) and executable methods (`ne, nodes_executable`) (successful authentication is required) :

```
./opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password -nw -ne
```

<br>

- Change root node (`-r, root_node`) : the search for writable nodes and executable methods will start from the selected root node

```
./opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password -nw -ne -r 2253

opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password -nw -ne -r 'i=2253'

opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password -nw -ne -r 'ns=6;s=MyObjectsFolder'

opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password -nw -ne -r 'ns=3;i=1001'c
```

<br>

- Output (`-o, --output`) : store more information about the scanned servers in a file (JSON format)

```
./opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -nw -o ./file_output.json
```

<br>

- Retrieves additional node attributes (`-na, node_attributes`) (successful authentication is required, and a file output must be configured). The list of valid attributes that can be retrieved is:
  - NodeId, NodeClass, BrowseName, DisplayName, Description, WriteMask, UserWriteMask, IsAbstract, Symmetric, InverseName, ContainsNoLoops, EventNotifier, Value, DataType, ValueRank, ArrayDimensions, AccessLevel, UserAccessLevel, MinimumSamplingInterval, Historizing, Executable, UserExecutable, DataTypeDefinition, RolePermissions, UserRolePermissions, AccessRestrictions, AccessLevelEx

```
./opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password -na Historizing -na Description -o file_output.json
```

<br>

- Servers (`-s, --servers`) : retrieve the application descriptions of the servers known by the targeted server

```
./opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -s
```

<br>

- Table format (`-tfmt, --table_format`) : change the format of the generated summary table (see tabulate documentation for the list of accepted formats, e.g. outline, grid...). Default value is "outline".

```
./opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -tfmt latex
```

<br>

# Read_data command

**This command allows to read data from an OPC-UA server**

<br>

## Display read_data command help

```
./opcua_scan.py read_data -h
```

## How to read data

Read at the root

```
./opcua_scan.py read_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer'
```

Browse a location ('ns=2;s=XXX.YYY') and read data :

```
./opcua_scan.py read_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -r 'ns=2;s=XXX.YYY'
```

Read data at a specific location without browsing :

```
./opcua_scan.py read_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -r 'ns=2;s=XXX.YYY' --single True
```

<br>

### Options

- Authentication (`-a, --authentication`) : The authentication method to be used (default: Anonymous)

```
./opcua_scan.py read_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Anonymous
```

<br>

- Username (`-u, --username`) and password (`-p, --password`) : The username and password for the authentication

```
./opcua_scan.py read_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password
```

<br>

- Security mode (`-m, --mode`) and policy (`-po, --policy`) : The security mode and associated policy of the targeted endpoint
- Certificate (`-c, --certificate`) and private key (`-pk, --private_key`) : The certificate and the associated private key for the authentication and/or encryption

```
./opcua_scan.py read_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password -m SignAndEncrypt -po Basic256Sha256 -c certificate.pem -pk private_key.pem

./opcua_scan.py read_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Certificate -c certificate.pem -pk private_key.pem

```

<br>

- Find writable nodes (`-nw, nodes_writable`) and executable methods (`ne, nodes_executable`) (successful authentication is required) :

```
./opcua_scan.py read_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password -nw -ne
```

<br>

- Change root node (`-r, root_node`) : the search for writable nodes and executable methods will start from the selected root node

```
./opcua_scan.py read_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password -nw -ne -r 2253

opcua_scan.py read_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password -nw -ne -r 'i=2253'

opcua_scan.py read_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password -nw -ne -r 'ns=6;s=MyObjectsFolder'

opcua_scan.py read_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password -nw -ne -r 'ns=3;i=1001'
```

<br>

- Output (`-o, --output`) : store more information about the scanned servers in a file (JSON format)

```
./opcua_scan.py read_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -nw -o ./file_output.json
```

<br>

- Retrieves additional node attributes (`-na, node_attributes`) (successful authentication is required, and a file output must be configured). The list of valid attributes that can be retrieved is:
  - NodeId, NodeClass, BrowseName, DisplayName, Description, WriteMask, UserWriteMask, IsAbstract, Symmetric, InverseName, ContainsNoLoops, EventNotifier, Value, DataType, ValueRank, ArrayDimensions, AccessLevel, UserAccessLevel, MinimumSamplingInterval, Historizing, Executable, UserExecutable, DataTypeDefinition, RolePermissions, UserRolePermissions, AccessRestrictions, AccessLevelEx

```
./opcua_scan.py read_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password -na Historizing -na Description -o file_output.json
```

<br>

- Single mode (`--single`) : Just read the data at the address without browsing

```
./opcua_scan.py read_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -r 'ns=3;i=1001' --single True
```

<br>

# Write_data command

**This command allows to write data to an OPC-UA server**

<br>

## Display write_data command help

```
./opcua_scan.py write_data -h
```

## How to write data

Browse a location ('ns=2;s=XXX.YYY') and write data (for boolean, no need to specify datatype) :

```
./opcua_scan.py write_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -r 'ns=2;s=XXX.YYY' --data True
```

Write integer data (must add -dt or --dtype argument) :

```
./opcua_scan.py write_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -r 'ns=2;s=XXX.YYY' --data 1 -dt UInt16
```

<br>

### Options

- Authentication (`-a, --authentication`) : The authentication method to be used (default: Anonymous)

```
./opcua_scan.py write_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Anonymous
```

<br>

- Username (`-u, --username`) and password (`-p, --password`) : The username and password for the authentication

```
./opcua_scan.py write_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password
```

<br>

- Security mode (`-m, --mode`) and policy (`-po, --policy`) : The security mode and associated policy of the targeted endpoint
- Certificate (`-c, --certificate`) and private key (`-pk, --private_key`) : The certificate and the associated private key for the authentication and/or encryption

```
./opcua_scan.py write_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Username -u john -p password -m SignAndEncrypt -po Basic256Sha256 -c certificate.pem -pk private_key.pem

./opcua_scan.py write_data -t 'opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer' -a Certificate -c certificate.pem -pk private_key.pem

```

<br>

- Node address node (`-r, root_node`) : Write at this adress

<br>

- Data (`--data`) : Data to be written
  `Only works with BOOL ("True" or "False") at the moment`
