[comment]: # "    File: README.md"
[comment]: # "    Copyright (c) 2017-2024 Splunk Inc."
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
