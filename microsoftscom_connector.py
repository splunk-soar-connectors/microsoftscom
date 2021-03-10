# File: microsoftscom_connector.py
# Copyright (c) 2017-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Standard library imports
import json
from winrm.protocol import Protocol
from winrm.exceptions import InvalidCredentialsError
from winrm.exceptions import WinRMTransportError
from requests import exceptions

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from microsoftscom_consts import *


class MicrosoftScomConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(MicrosoftScomConnector, self).__init__()

        self._state = None

        # Configuration variables
        self._server_url = None
        self._username = None
        self._password = None
        self._verify_server_cert = False

    def _handle_test_connectivity(self, param):
        """ This function tests the connectivity of an asset with given credentials.

        :param param: (not used in this method)
        :return: status success/failure
        """

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(MSSCOM_CONNECTING_ENDPOINT_MSG)
        # Execute power shell command
        status, response = self._execute_ps_command(action_result, MSSCOM_PS_COMMAND.format(command="ls"))

        # Something went wrong
        if phantom.is_fail(status):
            self.debug_print(action_result.get_message())
            self.save_progress(MSSCOM_TEST_CONNECTIVITY_FAIL)
            return action_result.get_status()

        # Return success
        self.save_progress(MSSCOM_TEST_CONNECTIVITY_PASS)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _execute_ps_command(self, action_result, ps_command):
        """ This function is used to execute power shell command.

        :param action_result: object of ActionResult
        :param ps_command: power shell command
        :return: output of executed power shell command
        """

        resp_output = None

        # In case of verify server certificate is false
        if not self._verify_server_cert:
            protocol = Protocol(endpoint=MSSCOM_SERVER_URL.format(url=self._server_url), transport='ntlm',
                                username=self._username, password=self._password,
                                server_cert_validation='ignore')
        else:
            protocol = Protocol(endpoint=MSSCOM_SERVER_URL.format(url=self._server_url), transport='ntlm',
                                username=self._username, password=self._password,
                                server_cert_validation='validate')

        try:
            shell_id = protocol.open_shell()
        except InvalidCredentialsError as credentials_err:
            # In case of invalid credentials
            self.debug_print(MSSCOM_INVALID_CREDENTIAL_ERR, credentials_err)
            return action_result.set_status(phantom.APP_ERROR, MSSCOM_INVALID_CREDENTIAL_ERR,
                                            credentials_err), resp_output
        except exceptions.SSLError as ssl_err:
            # In case of SSL error
            self.debug_print(MSSCOM_ERR_BAD_HANDSHAKE, ssl_err)
            return action_result.set_status(phantom.APP_ERROR, MSSCOM_ERR_BAD_HANDSHAKE,
                                            ssl_err), resp_output
        except exceptions.ConnectionError as conn_err:
            # In case of connection error
            self.debug_print(MSSCOM_ERR_SERVER_CONNECTION, conn_err)
            return action_result.set_status(phantom.APP_ERROR, MSSCOM_ERR_SERVER_CONNECTION,
                                            conn_err), resp_output
        except WinRMTransportError as transport_err:
            self.debug_print(MSSCOM_TRANSPORT_ERR, transport_err)
            return action_result.set_status(phantom.APP_ERROR, MSSCOM_TRANSPORT_ERR,
                                            transport_err), resp_output
        except Exception as e:
            self.debug_print(MSSCOM_EXCEPTION_OCCURRED, e)
            return action_result.set_status(phantom.APP_ERROR, MSSCOM_EXCEPTION_OCCURRED,
                                            e), resp_output

        try:
            # Execute command
            command_id = protocol.run_command(shell_id, ps_command)
            resp_output, resp_err, status_code = protocol.get_command_output(shell_id, command_id)
            protocol.cleanup_command(shell_id, command_id)
            protocol.close_shell(shell_id)
        except Exception as err:
            self.debug_print(MSSCOM_EXCEPTION_OCCURRED, err)
            return action_result.set_status(phantom.APP_ERROR, MSSCOM_EXCEPTION_OCCURRED,
                                            err), resp_output

        # In case of error in command execution
        if status_code:
            return action_result.set_status(phantom.APP_ERROR, MSSCOM_EXCEPTION_OCCURRED,
                                            resp_err), resp_output

        return action_result.set_status(phantom.APP_SUCCESS), resp_output

    def _handle_list_endpoints(self, param):
        """ This function is used to list all endpoints.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Optional values should use the .get() function
        domain = param.get(MSSCOM_PARAM_DOMAIN, "*")

        # Prepare power shell command
        command = "{cmd} -DNSHostName *.{domain} | {json}".format(cmd=MSSCOM_GET_SCOM_AGENT_COMMAND, domain=domain,
                                                                  json=MSSCOM_CONVERT_TO_CSV_JSON_COMMAND)

        # Execute power shell command
        status, response = self._execute_ps_command(action_result, MSSCOM_PS_COMMAND.format(command=command))

        # Something went wrong while executing power shell command
        if phantom.is_fail(status):
            self.debug_print(action_result.get_message())
            return action_result.get_status()

        try:
            if response:
                response = json.loads(response)
                # Add data to action_result
                if type(response) is dict:
                    action_result.add_data(response)
                else:
                    for item in response:
                        action_result.add_data(item)
        except Exception as e:
            self.debug_print(MSSCOM_JSON_FORMAT_ERROR)
            return action_result.set_status(phantom.APP_ERROR, MSSCOM_JSON_FORMAT_ERROR, e)

        # Update summary
        summary = action_result.update_summary({})
        summary['total_endpoints'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_alerts(self, param):
        """ This function is used to get system's health information.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Optional values should use the .get() function
        computer_name = param.get(MSSCOM_PARAM_COMPUTER_NAME)

        # Prepare power shell command to execute
        if computer_name:
            command = "{cmd} -ComputerName \"{computer_name}\" | {json}".format(cmd=MSSCOM_GET_SCOM_ALERT_COMMAND,
                                                                                computer_name=computer_name,
                                                                                json=MSSCOM_CONVERT_TO_CSV_JSON_COMMAND)
        else:
            command = "{cmd} | {json}".format(cmd=MSSCOM_GET_SCOM_ALERT_COMMAND,
                                              json=MSSCOM_CONVERT_TO_CSV_JSON_COMMAND)

        # Execute power shell command
        status, response = self._execute_ps_command(action_result, MSSCOM_PS_COMMAND.format(command=command))

        # Something went wrong
        if phantom.is_fail(status):
            self.debug_print(action_result.get_message())
            return action_result.get_status()

        # Add data to action_result
        try:
            if response:
                response = json.loads(response)
                for item in response:
                    if item["ResolutionState"] != "255":
                        action_result.add_data(item)
        except Exception as e:
            self.debug_print(MSSCOM_JSON_FORMAT_ERROR)
            return action_result.set_status(phantom.APP_ERROR, MSSCOM_JSON_FORMAT_ERROR, e)

        # Update summary
        summary = action_result.update_summary({})
        summary['total_alerts'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_device_info(self, param):
        """ This function is used to list all endpoints.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Optional values should use the .get() function
        ip_address = param.get("ip")
        computer_name = param.get("computer_name")

        if not (ip_address or computer_name):
            self.debug_print(MSSCOM_PARAM_NOT_SPECIFIED.format("ip", "computer_name"))
            return action_result.set_status(phantom.APP_ERROR, MSSCOM_PARAM_NOT_SPECIFIED.format("ip", "computer_name"))

        # Prepare power shell command
        command = "{cmd} -DNSHostName *.* | {json}".format(cmd=MSSCOM_GET_SCOM_AGENT_COMMAND,
                                                           json=MSSCOM_CONVERT_TO_CSV_JSON_COMMAND)

        # Execute power shell command
        status, response = self._execute_ps_command(action_result, MSSCOM_PS_COMMAND.format(command=command))

        # Something went wrong while executing power shell command
        if phantom.is_fail(status):
            self.debug_print(action_result.get_message())
            return action_result.get_status()

        try:
            if response:
                response = json.loads(response)
                # Add data to action_result
                if type(response) is dict:
                    if ip_address:
                        ip_list = response["IPAddress"].replace(" ", "").split(",")
                        for value in ip_list:
                            if ip_address == value:
                                action_result.add_data(response)
                                break
                    elif computer_name == response["ComputerName"]:
                        action_result.add_data(response)
                else:
                    for item in response:
                        # If both parameters are present, priority is given to IP
                        if ip_address:
                            ip_list = item["IPAddress"].replace(" ", "").split(",")
                            for value in ip_list:
                                if ip_address == value:
                                    action_result.add_data(item)
                                    break
                        elif computer_name == item["ComputerName"]:
                            action_result.add_data(item)
                            break
        except Exception as e:
            self.debug_print(MSSCOM_JSON_FORMAT_ERROR)
            return action_result.set_status(phantom.APP_ERROR, MSSCOM_JSON_FORMAT_ERROR, e)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_ERROR, "Device not found")

        return action_result.set_status(phantom.APP_SUCCESS, "Device found")

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'list_endpoints': self._handle_list_endpoints,
            'list_alerts': self._handle_list_alerts,
            'get_device_info': self._handle_get_device_info
        }
        action = self.get_action_identifier()
        try:
            run_action = action_mapping[action]
        except Exception as e:
            self.debug_print(e)
            raise ValueError("action {action} is not supported".format(action=action))

        return run_action(param)

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        self._state = self.load_state()

        # Get the asset config
        config = self.get_config()

        # Required config parameter
        self._server_url = config[MSSCOM_CONFIG_SERVER_URL].strip("/")
        self._username = config[MSSCOM_CONFIG_USERNAME]
        self._password = config[MSSCOM_CONFIG_PASSWORD]

        # Optional config parameter
        self._verify_server_cert = config.get(MSSCOM_CONFIG_VERIFY_SSL, False)

        return phantom.APP_SUCCESS

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.
        """

        # Save the state
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import sys
    import pudb

    pudb.set_trace()

    if len(sys.argv) < 2:
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = MicrosoftScomConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
