# --
# File: microsoftscom_view.py
#
# Copyright (c) Phantom Cyber Corporation, 2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --


def _get_ctx_result(provides, result):
    """  This function get's called for every result object. The result object represents every ActionResult object that
    you've added in the action handler. Usually this is one per action. This function converts the result object into a
    context dictionary.

    :param provides: action name
    :param result: ActionResult object
    :return: context dictionary
    """
    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result['param'] = param

    if summary:
        ctx_result['summary'] = summary

    if not data:
        ctx_result['data'] = {}
        return ctx_result

    if provides == "list endpoints" or provides == "get device info":
        for item in data:
            item['IPAddress'] = item['IPAddress'].replace(' ', '').split(',')

    if provides == "list alerts":
        for item in data:
            if item['ResolutionState'] == "0":
                item['ResolutionState'] = "New"
            elif item['ResolutionState'] == "247":
                item['ResolutionState'] = "Awaiting Evidence"
            elif item['ResolutionState'] == "248":
                item['ResolutionState'] = "Assigned to Engineering"
            elif item['ResolutionState'] == "249":
                item['ResolutionState'] = "Acknowledged"
            elif item['ResolutionState'] == "250":
                item['ResolutionState'] = "Scheduled"
            elif item['ResolutionState'] == "254":
                item['ResolutionState'] = "Resolved"
            elif item['ResolutionState'] == "255":
                item['ResolutionState'] = "Closed"

    ctx_result['data'] = data

    return ctx_result


def display_action_details(provides, all_app_runs, context):
    """  This function is used to create the context dictionary that the template code can use to render the data.

    :param provides: action name
    :param all_app_runs: app runs
    :param context: context dictionary
    :return: custom view page
    """
    context['results'] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(provides, result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    if provides == "list alerts":
        return_page = 'microsoftscom_list_alerts.html'
    else:
        return_page = 'microsoftscom_list_endpoints.html'

    return return_page
