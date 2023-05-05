#!/usr/bin/env python3
# -*- coding: utf-8 -

# pylint: disable=broad-exception-caught, protected-access, global-statement
# pylint: disable=too-many-lines

"""
OPC UA Scanner: Detect OPC UA servers, and retrieve security related
information about them
"""


##############################################################################
#                               Import Section                               #
##############################################################################

import argparse
import logging
import asyncio
import json
import base64
import dataclasses
import os
import os.path
from tabulate import tabulate
from asyncua import ua, Client
from asyncua.common import ua_utils
from asyncua.crypto import security_policies, uacrypto
from ipparser import ipparser
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

os.system("")  # enables ansi escape characters in terminal for Windows


##############################################################################
#                          Global variables section                          #
##############################################################################

application_types = ["SERVER", "CLIENT", "CLIENTANDSERVER", "DISCOVERYSERVER"]
valid_auth_methods = ["Anonymous", "Username", "Certificate", "Issued"]
valid_security_modes = {
    "None": ua.MessageSecurityMode.None_,
    "Sign": ua.MessageSecurityMode.Sign,
    "SignAndEncrypt": ua.MessageSecurityMode.SignAndEncrypt
}
valid_security_policies = {
    "None": None,
    "Basic128Rsa15": security_policies.SecurityPolicyBasic128Rsa15,
    "Basic256": security_policies.SecurityPolicyBasic256,
    "Basic256Sha256": security_policies.SecurityPolicyBasic256Sha256,
    "Aes128Sha256RsaOaep": security_policies.SecurityPolicyAes128Sha256RsaOaep
}
valid_node_attributes = {
    "NodeId": ua.AttributeIds.NodeId,
    "NodeClass": ua.AttributeIds.NodeClass,
    "BrowseName": ua.AttributeIds.BrowseName,
    "DisplayName": ua.AttributeIds.DisplayName,
    "Description": ua.AttributeIds.Description,
    "WriteMask": ua.AttributeIds.WriteMask,
    "UserWriteMask": ua.AttributeIds.UserWriteMask,
    "IsAbstract": ua.AttributeIds.IsAbstract,
    "Symmetric": ua.AttributeIds.Symmetric,
    "InverseName": ua.AttributeIds.InverseName,
    "ContainsNoLoops": ua.AttributeIds.ContainsNoLoops,
    "EventNotifier": ua.AttributeIds.EventNotifier,
    "Value": ua.AttributeIds.Value,
    "DataType": ua.AttributeIds.DataType,
    "ValueRank": ua.AttributeIds.ValueRank,
    "ArrayDimensions": ua.AttributeIds.ArrayDimensions,
    "AccessLevel": ua.AttributeIds.AccessLevel,
    "UserAccessLevel": ua.AttributeIds.UserAccessLevel,
    "MinimumSamplingInterval": ua.AttributeIds.MinimumSamplingInterval,
    "Historizing": ua.AttributeIds.Historizing,
    "Executable": ua.AttributeIds.Executable,
    "UserExecutable": ua.AttributeIds.UserExecutable,
    "DataTypeDefinition": ua.AttributeIds.DataTypeDefinition,
    "RolePermissions": ua.AttributeIds.RolePermissions,
    "UserRolePermissions": ua.AttributeIds.UserRolePermissions,
    "AccessRestrictions": ua.AttributeIds.AccessRestrictions,
    "AccessLevelEx": ua.AttributeIds.AccessLevelEx
}
valid_table_formats = {
    "plain",
    "simple",
    "github",
    "grid",
    "simple_grid",
    "rounded_grid",
    "heavy_grid",
    "mixed_grid",
    "double_grid",
    "fancy_grid",
    "outline",
    "simple_outline",
    "rounded_outline",
    "heavy_outline",
    "mixed_outline",
    "double_outline",
    "fancy_outline",
    "pipe",
    "orgtbl",
    "asciidoc",
    "jira",
    "presto",
    "pretty",
    "psql",
    "rst",
    "mediawiki",
    "moinmoin",
    "youtrack",
    "html",
    "unsafehtml",
    "latex",
    "latex_raw",
    "latex_booktabs",
    "latex_longtable",
    "textile",
    "tsv"
}

MSG_PREFIX = ""

TARGET_COUNTER = 0
DETECTED_SERVER_COUNTER = 0
WRITABLE_NODE_COUNTER = 0
EXECUTABLE_NODE_COUNTER = 0


##############################################################################
#                            Hello script section                            #
##############################################################################

async def run_hello(args):
    """
    Sends an Hello message to all the given hosts on all the given ports.
    """
    pretty_log("Start hello scan...")
    try:
        hosts = ipparser(args.ip_addresses)
        port_ranges = [port_rng.strip() for port_rng in args.ports.split(",")]
        output_object = [] if args.output else False

        # Retrieve list of server name to test
        server_names = []
        if os.path.isfile(args.name):
            with open(args.name, "r", encoding="utf-8") as names_file:
                server_names = [
                    name.strip() for name in names_file.readlines()
                ]
        else:
            server_names.append(args.name)

        for server_name in server_names:
            for host in hosts:
                for port_rng in port_ranges:
                    # Handle port range
                    if "-" in port_rng:
                        start_port, last_port = port_rng.split("-")
                        port_range = range(
                            int(start_port), int(last_port) + 1
                        )

                    # Handle single port
                    else:
                        port_range = range(int(port_rng), int(port_rng) + 1)

                    for port in port_range:
                        await hello_scan_target(
                            args, host, port, server_name, output_object
                        )

        generate_hello_report(args, TARGET_COUNTER, DETECTED_SERVER_COUNTER)

        # Write in output file if configured
        if output_object is not False:
            with open(args.output, "w", encoding="utf-8") as outfile:
                json.dump(output_object, outfile)

    except Exception as err:
        pretty_log("Invalid hosts or ports format: " + str(err), lvl="error")


async def hello_scan_target(args, host, port, server_name, output_object):
    """
    Sends an OPC UA Hello Message to the target
    """
    global MSG_PREFIX, TARGET_COUNTER, DETECTED_SERVER_COUNTER
    MSG_PREFIX = f"{host}:{port}/{server_name} - "

    # Send Hello to target
    connection_str = f"opc.tcp://{host}:{port}/{server_name}"
    client = Client(connection_str, timeout=int(args.timeout) / 1000)
    TARGET_COUNTER += 1

    if await precheck_connection(client):
        DETECTED_SERVER_COUNTER += 1
        pretty_log("Success: OPC UA Server Discovered", lvl="success")
        server_descriptions = await get_server_descriptions(client)
        iterate_server_descriptions(server_descriptions)

        if output_object is not False:
            output_object.append({
                "target": connection_str,
                "known_servers": list(
                    map(dataclasses.asdict, server_descriptions)
                )
            })
    elif args.verbose:
        pretty_log("Failure: no OPC UA server", lvl="error")


def generate_hello_report(args, target_counter, detected_server_counter):
    """
    Displays a summary of the hello scan results
    """

    table = [
        ["Targets scanned", f"{target_counter} target(s) scanned"],
        [
            "Servers detected",
            f"{detected_server_counter} OPC UA server(s) detected"
        ]
    ]
    print("\n")
    print(
        tabulate(table, tablefmt=args.table_format, headers=["", "Results"])
    )


##############################################################################
#                        read_data script section                        #
##############################################################################

async def read_data(args):
    """
    Starts reading data
    """
    # Init
    targets = build_targets(args)
    targets_report_object = []
    # If there is more than one target, raise an error
    if len(targets)>1:
        pretty_log(
            f"Only one target is supported for read_data",
               lvl="error"
            )
        return False
    print(str(targets))

    # Start scan
    for target in targets:
        client = Client(target)
        global MSG_PREFIX
        MSG_PREFIX = f"{target} - "

        if await precheck_connection(client):
            print("\n")
            pretty_log(
                "Valid OPC UA response, starting analysis",
                lvl="success"
            )

            target_report = {"target": target, "endpoints": [], "tree": []}
            targets_report_object.append(target_report)

            endpoints = await get_endpoints(client)
            iterate_endpoints(endpoints, target_report)
            
            if await check_authentication(client, args, target_report):
                try:
                    await read_server_nodes(client, args, target_report)
                except Exception:
                    continue

        else:
            print("\n")
            pretty_log("No OPC UA response, stop scan", lvl="error")



    # Write the scan results in the verbose file
    if args.output_verbose:
        with open(args.output_verbose, "w", encoding="utf-8") as outfile:
            json.dump(targets_report_object, outfile)



##############################################################################
#                        Server_config script section                        #
##############################################################################

async def run_server_config(args):
    """
    Starts the server_config scan
    """
    # Init
    targets = build_targets(args)
    targets_report_object = []

    # Start scan
    for target in targets:
        client = Client(target)
        global MSG_PREFIX
        MSG_PREFIX = f"{target} - "

        if await precheck_connection(client):
            print("\n")
            pretty_log(
                "Valid OPC UA response, starting analysis",
                lvl="success"
            )

            target_report = {"target": target, "endpoints": [], "tree": []}
            targets_report_object.append(target_report)

            endpoints = await get_endpoints(client)
            iterate_endpoints(endpoints, target_report)

            if args.servers:
                # Ask for all known servers
                server_descriptions = await get_server_descriptions(client)
                pretty_log("Found Servers:")
                iterate_server_descriptions(server_descriptions)

            if await check_authentication(client, args, target_report):
                if (
                    args.nodes_writable or
                    args.nodes_executable or
                    args.node_attributes
                ):
                    try:
                        await get_server_nodes(client, args, target_report)
                    except Exception:
                        continue

        else:
            print("\n")
            pretty_log("No OPC UA response, stop scan", lvl="error")

    generate_config_report(
        args,
        WRITABLE_NODE_COUNTER,
        EXECUTABLE_NODE_COUNTER,
        targets_report_object
    )

    # Write the scan results in the verbose file
    if args.output_verbose:
        with open(args.output_verbose, "w", encoding="utf-8") as outfile:
            json.dump(targets_report_object, outfile)


def generate_config_report(
    args,
    writable_node_counter,
    executable_node_counter,
    targets_report_object
):
    """
    Displays a summary of the server_config scan results
    """
    # Allowed anonymous connection
    anonymous_connection_allowed_counter = 0
    for target in targets_report_object:
        next_target = False
        for endpoint in target["endpoints"]:
            if next_target:
                break

            for accepted_token in endpoint["UserIdentityTokens"]:
                if accepted_token["TokenType"] == ua.UserTokenType.Anonymous:
                    anonymous_connection_allowed_counter += 1
                    next_target = True
                    break

    anonymous_connection_msg = ""
    if anonymous_connection_allowed_counter > 0:
        anonymous_connection_msg += "\033[93m\033[1m" + "ALLOWED" + "\033[0m"
        anonymous_connection_msg += (
            f" (for {anonymous_connection_allowed_counter} targets)"
        )
    else:
        anonymous_connection_msg += (
            "\033[92m\033[1m" + "NOT ALLOWED" + "\033[0m"
        )

    # Security mode
    none_counter, sign_and_encrypt_only = 0, True
    for target in targets_report_object:
        for endpoint in target["endpoints"]:
            if (
                endpoint["SecurityMode"] == 1 and
                endpoint["EndpointUrl"].startswith("opc.tcp")
            ):
                none_counter += 1

            if sign_and_encrypt_only and endpoint["SecurityMode"] != 3:
                sign_and_encrypt_only = False

    security_mode_msg = ""
    if none_counter > 0:
        security_mode_msg += (
            "Mode None " + "\033[93m\033[1m" + "ALLOWED" + "\033[0m"
        )
        security_mode_msg += f" (for {none_counter} targets)"
    else:
        security_mode_msg += (
            "Mode None " + "\033[92m\033[1m" + "NOT ALLOWED" + "\033[0m"
        )
        if sign_and_encrypt_only:
            security_mode_msg += " (SignAndEncrypt only)"
        else:
            security_mode_msg += " (Sign or SignAndEncrypt)"

    # Authentication
    successful_auth_counter = 0
    for target in targets_report_object:
        if target["authentication"] == "Successful":
            successful_auth_counter += 1
    auth_msg = f" {successful_auth_counter} successful authentication(s)"

    table = [
        ["Targets scanned", f"{len(targets_report_object)} target(s)"],
        ["Anonymous connection", anonymous_connection_msg],
        ["Security mode", security_mode_msg],
        ["Authentication", auth_msg]
    ]

    # Nodes
    if args.nodes_writable:
        writable_nodes_msg = f"{writable_node_counter} nodes can be modified"
        table.append(["Writable nodes", writable_nodes_msg])

    if args.nodes_executable:
        editable_nodes_msg = (
            f"{executable_node_counter} methods can be executed"
        )
        table.append(["Executable methods", editable_nodes_msg])

    print("\n")
    print(
        tabulate(table, tablefmt=args.table_format, headers=["", "Results"])
    )

def generate_reading_report(
    args,
    targets_report_object
):
    """
    Displays a summary of the read_data scan results
    """

    table = []

    # Nodes & values
    for node in targets_report_object:
        table.append([node["NodeId"], node["Value"]])

    print("\n")
    print(
        tabulate(table, tablefmt='outline', headers=["Node", "Value"])
    )



def build_targets(args):
    """
    Returns a list of URL to scan from the args input
    """
    if os.path.isfile(args.targets):
        targets = []
        with open(args.targets, "r", encoding="utf-8") as targets_file:
            file_data = json.load(targets_file)
            for detected_server in file_data:
                for known_server in detected_server["known_servers"]:
                    for discovery_url in known_server["DiscoveryUrls"]:
                        # HTTPS not supported yet
                        if discovery_url.startswith("opc.tcp"):
                            if discovery_url not in targets:
                                targets.append(discovery_url)
    else:
        targets = [target.strip() for target in args.targets.split(",")]
    return targets


async def check_authentication(client, args, target_report):
    """
    Tries to make an authentication to an OPC UA server.
    Returns True if it is successful, False otherwise.
    """
    target_report["authentication"] = "Failed"
    if await setup_client_for_authentication(client, args):
        try:
            await client.connect()
            await client.disconnect()
            pretty_log(
                f"Successful {args.authentication} authentication",
                lvl="success"
            )
            target_report["authentication"] = "Successful"
            return True

        except asyncio.exceptions.TimeoutError:
            pretty_log(
                f"{args.authentication} authentication failed : Timeout error"
                ", no response from the server",
                lvl="error"
            )
            return False
        except Exception as err:
            pretty_log(
                f"{args.authentication} authentication failed : {err}",
                lvl="error"
            )
            return False
        finally:
            try:
                await client.disconnect()
            except Exception:
                pass

    else:
        pretty_log("Client setup failed", lvl="error")
        return False


async def read_server_nodes(client, args, target_report):
    """
    Tries to retrieves server nodes
    """
    try:
        await client.connect()
        root = (
            client.get_root_node() if not args.root_node
            else client.get_node(args.root_node)
        )

        # Iterate over all nodes and check permissions
        pretty_log("List of nodes and values:")
        await read_node_values(args, root, target_report["tree"])
        await client.disconnect()

    except Exception as err:
        pretty_log(f"Could not obtain information: {err}", lvl="error")
        try:
            await client.disconnect()
        except Exception:
            pass
        raise err

async def get_server_nodes(client, args, target_report):
    """
    Tries to retrieves server nodes
    """
    try:
        await client.connect()
        root = (
            client.get_root_node() if not args.root_node
            else client.get_node(args.root_node)
        )

        # Iterate over all nodes and check permissions
        pretty_log("Interesting Nodes:")
        await traverse_tree(args, root, target_report["tree"])
        await client.disconnect()

    except Exception as err:
        pretty_log(f"Could not obtain information: {err}", lvl="error")
        try:
            await client.disconnect()
        except Exception:
            pass
        raise err


async def setup_client_for_authentication(client, args):
    """
    Configure the client for the authentication and the encryption of the
    channel
    """
    certpath, keypath = args.certificate, args.private_key
    mode, policy = args.mode, args.policy

    if certpath != "" and not os.path.isfile(certpath):
        pretty_log("Certificate not found", lvl="error")
        return False

    if keypath != "" and not os.path.isfile(keypath):
        pretty_log("Key not found", lvl="error")
        return False

    if args.authentication == valid_auth_methods[1]:  # Username
        client.set_user(args.username)
        client.set_password(args.password)

    elif args.authentication == valid_auth_methods[2]:  # Certificate
        await client.load_client_certificate(certpath)
        await client.load_private_key(keypath)
        set_application_uri_from_cert(client, client.user_certificate)

    if mode != "None":
        # Check policy if mode is not None
        if policy == "None":
            pretty_log(
                "Security mode other than 'None' is used thus security policy"
                " needs to be one of the following: "
                f"{list(valid_security_policies.keys())[1:]}",
                lvl="error"
            )
            return False

        security_policy = valid_security_policies[policy]
        security_mode = valid_security_modes[mode]

        try:
            await client.set_security(
                security_policy, certpath, keypath, None, None, security_mode
            )
            cert = uacrypto.x509_from_der(
                client.security_policy.host_certificate
            )
            set_application_uri_from_cert(client, cert)
        except Exception as err:
            pretty_log(
                f"Failed to set security mode and policy: {err}",
                lvl="error"
            )
            return False

    return True


def set_application_uri_from_cert(client, cert):
    """
    The application URI provided by the client should match the subject
    name extension of the certificate. This set up the client accordingly.
    """
    alt_name_extension = cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    client.application_uri = alt_name_extension.value.get_values_for_type(
        x509.UniformResourceIdentifier
    )[0]


def iterate_endpoints(endpoints, target_report):
    """
    Iterates all endpoints and logs relevant information
    """
    pretty_log("Available Endpoints:")

    for endpoint in endpoints:
        # URL
        pretty_log("-" * 40)
        pretty_log(f"Endpoint: {endpoint.EndpointUrl}")

        # Security mode
        if endpoint.SecurityMode == ua.MessageSecurityMode.None_:
            pretty_log(
                f"Security mode: {str(endpoint.SecurityMode)[20:]}",
                lvl="critical"
            )
        else:
            pretty_log(
                f"Security mode: {str(endpoint.SecurityMode)[20:]} "
                f"with {endpoint.SecurityPolicyUri[43:]}"
            )

        # Supported authentication
        supported_authentication = []
        anonymous_accepted = False
        for token in endpoint.UserIdentityTokens:
            if token.TokenType not in supported_authentication:
                supported_authentication.append(token.TokenType)
                if token.TokenType == ua.UserTokenType.Anonymous:
                    anonymous_accepted = True

        msg = "Authentication type accepted: "
        for token_type in supported_authentication:
            msg += str(token_type)[14:] + ", "
        pretty_log(msg[:-2], lvl="critical" if anonymous_accepted else "")

        # Convert certificate in base64 (easier to read in the output file)
        if target_report:
            endpoint.ServerCertificate = base64.b64encode(
                endpoint.ServerCertificate
            ).decode("utf-8")
            target_report["endpoints"].append(dataclasses.asdict(endpoint))

    pretty_log("-" * 40)


async def traverse_tree(args, root, targets_report_object_tree):
    """
    Recursively iterates all nodes in subtree from given root and logs
    relevant information
    """
    # Init default attributes
    parent_node = {
        "NodeId": "BadNodeIdUnknown",
        "NodeClass": "BadNodeIdUnknown",
        "BrowseName": "BadNodeIdUnknown",
        "Value": "BadAttributeIdInvalid",
        "UserRolePermissions": "BadAttributeIdInvalid",
    }

    # Handle additional attributes configured
    for attr in args.node_attributes:
        try:
            parent_node[attr] = str(
                await root.read_attribute(valid_node_attributes[attr])
            )
        except Exception as err:
            parent_node[attr] = str(err)

    targets_report_object_tree.append(parent_node)

    # Retrieve default attributes
    try:
        parent_node["NodeId"] = root.nodeid.to_string()
        browse_name = await root.read_browse_name()
        parent_node["BrowseName"] = browse_name.to_string()
        node_class = int_to_node_class(await root.read_node_class())
        parent_node["NodeClass"] = node_class.name

        # Value
        try:
            parent_node["Value"] = ua_utils.val_to_string(
                await root.read_value(), truncate=True
            )
        except ua.uaerrors._auto.BadAttributeIdInvalid:
            pass
        except Exception as err:
            parent_node["Value"] = str(err)

        # UserRolePermissions
        try:
            user_role_permissions = await root.read_attribute(
                ua.AttributeIds.UserRolePermissions
            )
            parent_node["UserRolePermissions"] = (
                user_role_permissions.Value.Value
            )
        except ua.uaerrors._auto.BadAttributeIdInvalid:
            pass
        except Exception as err:
            parent_node["UserRolePermissions"] = str(err)

        # UserWriteMask
        try:
            user_write_mask = await root.read_attribute(
                ua.AttributeIds.UserWriteMask
            )
            parent_node["UserWriteMask"] = [
                mask.name for mask in ua.WriteMask.parse_bitfield(
                    user_write_mask.Value.Value
                )
            ]
        except ua.uaerrors._auto.BadAttributeIdInvalid:
            pass
        except Exception as err:
            parent_node["UserWriteMask"] = str(err)

        # Check if the node is relevant to print and retrieve other attributes
        relevant = False
        if node_class == ua.NodeClass.Variable:
            # UserAccessLevel
            try:
                user_access_level = await root.get_user_access_level()
                if args.nodes_writable:
                    for access in user_access_level:
                        # CurrentWrite or HistoryWrite
                        if (
                            access == ua.AccessLevel(3) or
                            access == ua.AccessLevel(1)
                        ):
                            relevant = True
                            break

                parent_node["UserAccessLevel"] = [
                    x.name for x in user_access_level
                ]
            except ua.uaerrors._auto.BadAttributeIdInvalid:
                pass
            except Exception as err:
                parent_node["UserAccessLevel"] = str(err)

        elif node_class == ua.NodeClass.Method:
            # UserExecutable
            try:
                user_executable = (
                    await root.read_attribute(ua.AttributeIds.UserExecutable)
                ).Value.Value
                if args.nodes_executable:
                    relevant = user_executable
                parent_node["UserExecutable"] = user_executable
            except ua.uaerrors._auto.BadAttributeIdInvalid:
                pass
            except Exception as err:
                parent_node["UserExecutable"] = str(err)

        # Display node if relevant
        if relevant:
            global WRITABLE_NODE_COUNTER, EXECUTABLE_NODE_COUNTER
            pretty_log(
                f"Name: {browse_name.to_string()} - "
                f"Id: {root.nodeid.to_string()}"
            )
            if args.nodes_writable and node_class == ua.NodeClass.Variable:
                WRITABLE_NODE_COUNTER += 1
                pretty_log(str([x.name for x in user_access_level]))
            if args.nodes_executable and node_class == ua.NodeClass.Method:
                EXECUTABLE_NODE_COUNTER += 1
                pretty_log("UserExecutable: True")

        parent_node["children"] = []
        children = await root.get_children()
        for child in children:
            await traverse_tree(args, child, parent_node["children"])

    except ua.uaerrors._auto.BadNodeIdUnknown:
        pass

async def read_node_values(args, root, targets_report_object_tree):
    """
   Get all nodes in subtree from given root and logs
    relevant information
    """

    # Init default attributes
    node = {
        "NodeId": "BadNodeIdUnknown",
        "NodeClass": "BadNodeIdUnknown",
        "BrowseName": "BadNodeIdUnknown",
        "Value": "BadAttributeIdInvalid",
        "UserRolePermissions": "BadAttributeIdInvalid",
    }

    child_nodes = await root.get_children()

    for child_node in child_nodes:
              
        # Retrieve default attributes
        try:
            node["NodeId"] = child_node.nodeid.to_string()
            browse_name = await child_node.read_browse_name()
            node["BrowseName"] = browse_name.to_string()
            node_class = int_to_node_class(await child_node.read_node_class())
            node["NodeClass"] = node_class.name

            # Description, not working as expected
            #desc = await child_node.read_attribute(ua.AttributeIds.Description)

            # Value
            try:
                node["Value"] = ua_utils.val_to_string(
                    await child_node.read_value(), truncate=True
                )
            
            except ua.uaerrors._auto.BadAttributeIdInvalid:
                pass
            except Exception as err:
                node["Value"] = str(err)
            targets_report_object_tree.append(node)

            # UserRolePermissions
            try:
                user_role_permissions = await child_node.read_attribute(
                    ua.AttributeIds.UserRolePermissions
                )
                node["UserRolePermissions"] = (
                    user_role_permissions.Value.Value
                )
            except ua.uaerrors._auto.BadAttributeIdInvalid:
                pass
            except Exception as err:
                node["UserRolePermissions"] = str(err)

            
            # Display nodes
            pretty_log(
                f"Name: {browse_name.to_string()} - "
                f"Id: {child_node.nodeid.to_string()} - "
                f"""Value: \033[92m\033[1m{node["Value"]}\033[0m"""
            )

        except ua.uaerrors._auto.BadNodeIdUnknown:
            pass
    generate_reading_report(
        args,
        targets_report_object_tree
    )
        
        


##############################################################################
#                                Main section                                #
##############################################################################

async def main():
    """
    Opcua_scan main function
    """
    # Disable asyncua logger
    logging.getLogger("asyncua").addHandler(logging.NullHandler())
    logging.getLogger("asyncua").propagate = False

    parser = init_arg_parser()
    args = parser.parse_args()

    if args.command == "hello":
        await run_hello(args)

    elif args.command == "read_data":
               
        if args.root_node:
            # Converts root_id to int if possible
            try:
                root_id = int(args.root_node)
                args.root_node = root_id
            except Exception:
                pass
        
        await read_data(args)

    elif args.command == "server_config":
        # Handle warning if additional node attributes are badly configured
        if args.node_attributes:
            if not args.output_verbose:
                pretty_log(
                    "Warning: No output file configured, the additional "
                    "targeted node attributes will not be retrieved",
                    lvl="critical"
                )
            else:
                old_attrs = args.node_attributes
                args.node_attributes = [
                    attr for attr in old_attrs if attr in valid_node_attributes
                ]
                for attr in old_attrs:
                    if attr not in args.node_attributes:
                        pretty_log(
                            f"Warning: The attribute {attr} is not valid and "
                            "thus, ignored.",
                            lvl="critical"
                        )

        if args.root_node:
            # Converts root_id to int if possible
            try:
                root_id = int(args.root_node)
                args.root_node = root_id
            except Exception:
                pass

        await run_server_config(args)


def init_arg_parser():
    """
    Init opcua_scan argparser
    """
    parser = argparse.ArgumentParser(
        prog="opcua_scan",
        description="Scan OPC UA servers",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "./opcua_scan.py hello -h\n"
            "./opcua_scan.py hello -i 127.0.0.1\n"
            "./opcua_scan.py hello -i 127.0.0.1 -p '5060, 53530' -o "
            "hello_output.json\n"
            "./opcua_scan.py server_config -t hello_output.json\n"
            "./opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530"
            "/OPCUA/SimulationServer' -a Username -u user -p pass -nw\n"
        )
    )
    subparsers = parser.add_subparsers(dest="command")

    # Creating the parser for the "hello" command
    init_hello_arg_parser(subparsers)

    # Creating the parser for the "server_config" command
    init_server_config_arg_parser(subparsers)

    # Creating the parser for the "read_data" command
    init_read_data_arg_parser(subparsers)

    return parser


def init_hello_arg_parser(subparsers):
    """
    Init hello command subparser
    """
    parser_hello = subparsers.add_parser(
        "hello",
        help="Scan multiple targets to detect OPC UA servers"
    )
    parser_hello.add_argument(
        "-i",
        "--ip_addresses",
        help="The target IP addresses (e.g. 127.0.0.1, 192.0.0.1-5)",
        required=True
    )
    parser_hello.add_argument(
        "-p",
        "--ports",
        help="The target ports (e.g. 4840, 80-85). The default port is 4840",
        default="4840"
    )
    parser_hello.add_argument(
        "-n",
        "--name",
        help=(
            "The name/path of the server (e.g opc:tcp://<IP>:<PORT>/<NAME>). "
            "Can be a string or a path to a file containing a list of names"
        ),
        default=""
    )
    parser_hello.add_argument(
        "-o",
        "--output",
        help=(
            "The path to a file where the server information will be written "
            "(JSON format)"
        )
    )
    parser_hello.add_argument(
        "-t",
        "--timeout",
        help=(
            "The timeout to consider a connection as failed in milliseconds "
            "(Default: 500)"
        ),
        default="500"
    )
    parser_hello.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Display each tested connection"
    )
    parser_hello.add_argument(
        "-tfmt",
        "--table_format",
        choices=valid_table_formats,
        default="outline",
        metavar='FORMAT',
        help=(
            "The format of the summary table (see tabulate documentation "
            "for the list of accepted formats, e.g. outline, grid...)"
        )
    )


def init_server_config_arg_parser(subparsers):
    """
    Init server_config  command subparser
    """
    parser_server_config = subparsers.add_parser(
        "server_config",
        help=(
            "Retrieves information about the configuration of discovered OPC "
            "UA servers"
        )
    )
    parser_server_config.add_argument(
        "-t",
        "--targets",
        help=(
            "The target urls (e.g. opc.tcp://127.0.01:4840/ServerName, "
            "opc.tcp://127.0.01:4841/). It can be a path to the output file "
            "generated by the opcua_scan hello command. (e.g "
            "/path/to/hello_output.json)"
        ),
        required=True
    )
    parser_server_config.add_argument(
        "-a",
        "--authentication",
        help="The authentication method to be used (default: Anonymous)",
        choices=valid_auth_methods,
        default=valid_auth_methods[0]  # Anonymous
    )
    parser_server_config.add_argument(
        "-u",
        "--username",
        help="The username for the authentication",
        default=""
    )
    parser_server_config.add_argument(
        "-p",
        "--password",
        help="The password for the authentication",
        default=""
    )
    parser_server_config.add_argument(
        "-c",
        "--certificate",
        help="The certificate for the authentication and/or encryption",
        default=""
    )
    parser_server_config.add_argument(
        "-pk",
        "--private_key",
        help="The private key used for the authentication and/or encryption",
        default=""
    )
    parser_server_config.add_argument(
        "-m",
        "--mode",
        choices=list(valid_security_modes.keys()),
        default="None",
        help=(
            "The security mode of the endpoint to which to connect "
            "(default: None)"
        )
    )
    parser_server_config.add_argument(
        "-po",
        "--policy",
        choices=list(valid_security_policies.keys()),
        default="None",
        help=(
            "The security policy of the endpoint to which to connect "
            "(default: None)"
        )
    )
    parser_server_config.add_argument(
        "-nw",
        "--nodes_writable",
        action="store_true",
        help=(
            "Iterate all nodes from the chosen root and check for write "
            "permission"
        )
    )
    parser_server_config.add_argument(
        "-ne",
        "--nodes_executable",
        action="store_true",
        help=(
            "Iterate all nodes from the chosen root and look for executable "
            "methods"
        )
    )
    parser_server_config.add_argument(
        "-na",
        "--node_attributes",
        action='append',
        default=[],
        help=(
            "Specify an additional node attribute to retrieves in the file "
            "output. (Default attributes retrievied: NodeId, NodeClass, "
            "BrowseName, Value, UserRolePermissions, UserWriteMask, "
            "UserAccessLevel)"
        )
    )
    parser_server_config.add_argument(
        "-r",
        "--root_node",
        help=(
            "The ID of the node from which iterations will start "
            "(e.g. 2253, 'i=2253', 'ns=6;s=MyObjectsFolder')"
        )
    )
    parser_server_config.add_argument(
        "-o",
        "--output_verbose",
        help=(
            "The path to a file where more information about the server will "
            "be written (JSON format)"
        )
    )
    parser_server_config.add_argument(
        "-s",
        "--servers",
        action="store_true",
        help="Try to find other servers this server knows about"
    )
    parser_server_config.add_argument(
        "-tfmt",
        "--table_format",
        choices=valid_table_formats,
        default="outline",
        metavar='FORMAT',
        help=(
            "The format of the summary table (see tabulate documentation "
            "for the list of accepted formats, e.g. outline, grid...)"
        )
    )

def init_read_data_arg_parser(subparsers):
    """
    Init read_data  command subparser
    """
    parser_read_data = subparsers.add_parser(
        "read_data",
        help=(
            "Retrieves information about the configuration of discovered OPC "
            "UA servers"
        )
    )
    parser_read_data.add_argument(
        "-t",
        "--targets",
        help=(
            "The target urls (e.g. opc.tcp://127.0.01:4840/ServerName, "
            "opc.tcp://127.0.01:4841/). It can be a path to the output file "
            "generated by the opcua_scan hello command. (e.g "
            "/path/to/hello_output.json)"
        ),
        required=True
    )
    parser_read_data.add_argument(
        "-a",
        "--authentication",
        help="The authentication method to be used (default: Anonymous)",
        choices=valid_auth_methods,
        default=valid_auth_methods[0]  # Anonymous
    )
    parser_read_data.add_argument(
        "-u",
        "--username",
        help="The username for the authentication",
        default=""
    )
    parser_read_data.add_argument(
        "-p",
        "--password",
        help="The password for the authentication",
        default=""
    )
    parser_read_data.add_argument(
        "-c",
        "--certificate",
        help="The certificate for the authentication and/or encryption",
        default=""
    )
    parser_read_data.add_argument(
        "-pk",
        "--private_key",
        help="The private key used for the authentication and/or encryption",
        default=""
    )
    parser_read_data.add_argument(
        "-m",
        "--mode",
        choices=list(valid_security_modes.keys()),
        default="None",
        help=(
            "The security mode of the endpoint to which to connect "
            "(default: None)"
        )
    )
    parser_read_data.add_argument(
        "-po",
        "--policy",
        choices=list(valid_security_policies.keys()),
        default="None",
        help=(
            "The security policy of the endpoint to which to connect "
            "(default: None)"
        )
    )
    parser_read_data.add_argument(
        "-r",
        "--root_node",
        help=(
            "The ID of the node from which iterations will start "
            "(e.g. 2253, 'i=2253', 'ns=6;s=MyObjectsFolder')"
        )
    )
    parser_read_data.add_argument(
        "-o",
        "--output_verbose",
        help=(
            "The path to a file where more information about the server will "
            "be written (JSON format)"
        )
    )


##############################################################################
#                            Common utils section                            #
##############################################################################

def int_to_node_class(node_class):
    """
    Returns the security mode corresponding to the given string
    """
    return {
        1: ua.NodeClass.Object,
        2: ua.NodeClass.Variable,
        4: ua.NodeClass.Method,
        8: ua.NodeClass.ObjectType,
        16: ua.NodeClass.VariableType,
        32: ua.NodeClass.ReferenceType,
        64: ua.NodeClass.DataType,
        128: ua.NodeClass.View
    }.get(node_class) or ua.NodeClass.Unspecified


async def get_server_descriptions(client):
    """
    Retrieves the list of known servers by the server to which the client
    is connected
    """
    try:
        server_descriptions = await client.connect_and_find_servers()
        return server_descriptions
    except Exception:
        return []


def iterate_server_descriptions(server_descriptions):
    """
    Iterates all servers_descriptions and prints the relevant information
    """
    for server_description in server_descriptions:
        pretty_log("-" * 40)
        pretty_log(f"Server: {server_description.ApplicationName.Text}")
        pretty_log(f"Product URI: {server_description.ProductUri}")
        pretty_log(
            "Application Type: "
            f"{application_types[server_description.ApplicationType]}"
        )

        for url in server_description.DiscoveryUrls:
            pretty_log(f"Discovery url: {url}")
    if len(server_descriptions) > 0:
        pretty_log("-" * 40)


async def precheck_connection(client):
    """
    Sends an OPC UA Hello message to the server to which the client is
    connected.
    Returns True if the response is an OPCUA Acknowledge message, False
    otherwise.
    """
    try:
        await client.connect_socket()
        await client.send_hello()
        client.disconnect_socket()
    except Exception:
        try:
            client.disconnect_socket()
        except Exception:
            pass
        return False
    return True


async def get_endpoints(client):
    """
    Retrieves the endpoints of the server to which the client is connected
    """
    try:
        endpoints = await client.connect_and_get_server_endpoints()
        return endpoints
    except Exception:
        return []


def pretty_log(message, lvl=""):
    """
    Prints the message and mimic metasploit output
    """
    if lvl == "error":
        full_message = "\033[91m\033[1m" + "[-] " + "\033[0m"
    elif lvl == "success":
        full_message = "\033[92m\033[1m" + "[+] " + "\033[0m"
    elif lvl == "critical":
        full_message = "\033[93m\033[1m" + "[!] " + "\033[0m"
    else:
        full_message = "\033[94m\033[1m" + "[*] " + "\033[0m"

    full_message += MSG_PREFIX + message
    print(full_message)


##############################################################################
#                                Run section                                 #
##############################################################################

if __name__ == "__main__":
    asyncio.run(main())
