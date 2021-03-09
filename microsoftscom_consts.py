# File: microsoftscom_consts.py
# Copyright (c) 2017-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
# Define your constants here
MSSCOM_CONFIG_SERVER_URL = "server_url"
MSSCOM_CONFIG_USERNAME = "username"
MSSCOM_CONFIG_PASSWORD = "password"
MSSCOM_CONFIG_VERIFY_SSL = "verify_server_cert"
MSSCOM_SERVER_URL = "{url}/wsman"
MSSCOM_CONNECTING_ENDPOINT_MSG = "Connecting to endpoint"
MSSCOM_ERR_SERVER_CONNECTION = "Connection failed"
MSSCOM_TRANSPORT_ERR = "Connection error: Bad configuration in SCOM"
MSSCOM_ERR_BAD_HANDSHAKE = "Bad Handshake"
MSSCOM_INVALID_CREDENTIAL_ERR = "Invalid Credentials"
MSSCOM_EXCEPTION_OCCURRED = "Exception occurred"
MSSCOM_TEST_CONNECTIVITY_FAIL = "Test Connectivity Failed."
MSSCOM_TEST_CONNECTIVITY_PASS = "Test Connectivity Passed"
MSSCOM_PS_COMMAND = 'powershell -command "{command}"'
MSSCOM_PARAM_DOMAIN = "domain"
MSSCOM_GET_SCOM_AGENT_COMMAND = "Get-SCOMAgent"
MSSCOM_GET_SCOM_ALERT_COMMAND = "Get-SCOMAlert"
MSSCOM_CONVERT_TO_CSV_JSON_COMMAND = "ConvertTo-Csv | ConvertFrom-Csv | ConvertTo-Json"
MSSCOM_PARAM_COMPUTER_NAME = "computer_name"
MSSCOM_JSON_FORMAT_ERROR = "JSON format error"
MSSCOM_PARAM_NOT_SPECIFIED = "Neither {0} nor {1} specified. Please specify at least one of them."
