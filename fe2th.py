#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import getopt
import argparse
import datetime
from io import BytesIO
import base64
import logging
import html2text

from FireEye.api import FireEyeApi
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

from config import FireEye, TheHive


class monitoring():
    
    def __init__(self, file):
        self.monitoring_file = file

    def touch(self):
        
        """
        touch status file when successfully terminated
        """
        if os.path.exists(self.monitoring_file):
            os.remove(self.monitoring_file)
        open(self.monitoring_file, 'a').close()

def add_tags(tags, content):
    
    """
    add tag to tags

    :param tags: existing tags
    :type tags: list
    :param content: string, mainly like taxonomy
    :type content: string
    """

    t = tags
    for newtag in content:
        t.append("FE:{}".format(newtag))
    return t

def th_alert_tags(incident, ignored_tags=None):
    
    """
    Convert FE incident tags into TH tags

    :param incident: FE incident
    :type incident: dict
    :return: TH tags
    :rtype:  list
    """

    tags = []
    add_tags(tags, ["id={}".format(incident.get('reportId')), "type={}".format(incident.get('type'))])
    tag_section = incident.get('tagSection', {}).get('main', {})
    for section in tag_section.keys():
        for k, v in tag_section[section].items():
            for sv in v:
                if ignored_tags and section in [x.strip() for x in ignored_tags.split(',')]:
                    continue
                if type(sv) == str:
                    add_tags(tags, ["{}={}".format(k, sv)])
                elif type(v) == dict:
                    add_tags(tags, ["{}={}".format(k, sv.get('name', 'None') )])
    return tags

def description_to_markdown(content):

    """
    Convert FE html tag into markdown

    :param content: json response
    :return: markdown description
    :rtype:  string
    """

    h = html2text.HTML2Text()
    h.ignore_tables = True
    return "{0} {1} {2} {3} {4}".format(
        "**Type:** {0}\n\n**Published:** {1}\n\n**Identifier:** {2}\n\n".format(
            content.get('intelligenceType', "None"),
            content.get('publishedDate',"None"),
            content.get('reportId',"None")
        ),
        "----\n\n#### Summary ####  \n\n{}\n\n".format(h.handle(content.get('execSummary'))) if content.get('execSummary') else '',
        "----\n\n#### Analysis ####  \n\n{}\n\n".format(h.handle(content.get('analysis'))) if content.get('analysis') else '',
        "----\n\n#### Overview ####  \n\n{}\n\n".format(h.handle(content.get('overview'))) if content.get('overview') else '',
        "----\n\n#### Mitigation ####  \n\n{}: {}\n\n".format(h.handle(content.get('mitigation')), content.get('mitigationDetails', '')) if content.get('mitigation') else ''
    )

def th_severity(sev):
    
    """
    convert FireEye severity in TH severity

    :param sev: FE severity
    :type sev: string
    :return TH severity
    :rtype: int
    """

    severities = {
        'NONE': 1,
        'LOW': 1,
        'MEDIUM': 2,
        'HIGH': 3,
        'CRITICAL': 3
    }
    return severities[sev]

def add_alert_artefact(artefacts, dataType, data, tags, tlp):
    
    """
    :type artefacts: array
    :type dataType: string
    :type data: string
    :type tags: array
    :type tlp: int
    :rtype: array
    """

    return artefacts.append(AlertArtifact(tags=tags,
                             dataType=dataType,
                             data=data,
                             message="From FireEye",
                             tlp=tlp)
                            )

def build_observables(observables):
    
    """
    Convert FE observables into TheHive observables

    :param observables: observables from FE
    :type observables: dict
    :return: AlertArtifact
    :rtype: thehive4py.models AlertArtifact
    """

    artefacts = []
    if len(observables) > 0:

        for ioc in observables:
            a = AlertArtifact(
                data=ioc[0],
                dataType=ioc[1],
                message="Observable from FireEye.",
                tlp=2,
                tags=["src:FireEye"]
            )
            artefacts.append(a)

    return artefacts

def build_alert(incident, observables, ignored_tags=None):
    
    """
    Convert FireEye alert into a TheHive Alert

    :param incident: Incident from FE
    :type incident: dict
    :param observables: observables from FE
    :type observables: dict
    :return: Thehive alert
    :rtype: thehive4py.models Alerts
    """

    a = Alert(title="{}".format(incident.get('title')),
                 tlp=2,
                 severity=th_severity(incident.get('riskRating', 'NONE')),
                 description=description_to_markdown(incident),
                 type=incident.get('intelligenceType', None),
                 tags=th_alert_tags(incident, ignored_tags),
                 caseTemplate=TheHive['template'],
                 source="FireEye",
                 sourceRef=incident.get('reportId'),
                 artifacts=build_observables(observables)
                 )
    logging.debug("build_alert: alert built for FE id #{}".format(incident.get('reportId')))
    return a

def find_incidents(feapi, since, ignored_tags=None):
    
    """
    :param feapi: FireEye.api.FireEyeApi
    :param since: number of minutes
    :type since: int
    :return: list of  thehive4py.models Alerts
    :rtype: array
    """

    response = feapi.find_incidents(since)

    if response.get('status') == "success":
        all_data = response.get('data').get('message', [])
        report_ids = [x['reportId'] for x in all_data]
        logging.debug('find_incidents(): {} FE incident(s) downloaded'.format( len(report_ids) ))

        for report_id in report_ids:
            report_response = feapi.get_incident(report_id)
            report_data = report_response.get('data').get('message', {}).get('report', {})
            logging.debug('find_incidents(): {} FE incident downloaded'.format( report_id ))
            observables = get_observables(report_data)
            yield build_alert(report_data, observables, ignored_tags)
    else:
        logging.debug("find_incidents(): Error while fetching incident #{}: {}".format(id, response.get('data')))
        sys.exit("find_incidents(): Error while fetching incident #{}: {}".format(id, response.get('data')))

def get_incidents(feapi, id_list, ignored_tags=None):
    
    """
    :type feapi: FireEye.api.FireEyeApi
    :param id_list: list of incident id
    :type id_list: array
    :return: TheHive alert
    :rtype: thehive4py.models Alert
    """

    while id_list:
        id = id_list.pop()
        response = feapi.get_incident(id)
        if response.get('status') == 'success':
            data = response.get('data').get('message', {}).get('report', {})
            logging.debug('get_incidents(): {} FE incident downloaded'.format( id ))
            observables = get_observables(data)
            yield build_alert(data, observables, ignored_tags)
        else:
            logging.debug("get_incidents(): Error while fetching incident #{}: {}".format(id, response.get('data')))
            sys.exit("get_incidents: Error while fetching incident #{}: {}".format(id, response.get('data')))

def get_observables(data):

    """
    :type data: json
    :param data: json report
    :return: list of tuple with description and type of observables
    :rtype: list
    """

    observables = []
    observables_network = data.get('tagSection', {}).get('networks', {}).get('network', [])
    observables_files = data.get('tagSection', {}).get('files', {}).get('file', [])
    observables_email = data.get('tagSection', {}).get('emails', {}).get('email', [])

    for obj in observables_network:
        if obj.get('ip'):
            observables.append( (obj.get('ip'), 'ip') )
        if obj.get('domain'):
            observables.append( (obj.get('domain'), 'domain') )
        if obj.get('url'):
            observables.append( (obj.get('url'), 'url') )

    for obj in observables_files:
        if obj.get('sha256'):
            observables.append( (obj.get('sha256'), 'hash') )

    for obj in observables_email:
        if obj.get('senderAddress'):
            observables.append( (obj.get('senderAddress'), 'email') )            

    return observables

def create_thehive_alerts(config, alerts):
    
    """
    :param config: TheHive config
    :type config: dict
    :param alerts: List of alerts
    :type alerts: list
    :return: create TH alert
    """

    thapi = TheHiveApi(config.get('url', None), config.get('key'), config.get('password', None),
                       config.get('proxies'))
    for a in alerts:
        thapi.create_alert(a)

def run():
    
    """
        Download FireEye incident and create a new alert in TheHive
    """

    def find(args, ignored_tags=None):
        if 'last' in args and args.last is not None:
            last = args.last.pop()
            
        incidents = find_incidents(feapi, last, ignored_tags)
        create_thehive_alerts(TheHive, incidents)
        
        if args.monitor:
            mon = monitoring("{}/fe2th.status".format(
                os.path.dirname(os.path.realpath(__file__))))
            mon.touch()
 
    def inc(args, ignored_tags=None):
        if 'incidents' in args and args.incidents is not None:
            incidents = get_incidents(feapi, args.incidents, ignored_tags)
            create_thehive_alerts(TheHive, incidents)

    parser = argparse.ArgumentParser(description="Get FE incidents and create alerts in TheHive")
    parser.add_argument("-d", "--debug",
                        action='store_true',
                        default=False,
                        help="generate a log file and active debug logging")
    subparsers = parser.add_subparsers(help="subcommand help")

    parser_incident = subparsers.add_parser('inc', help="fetch incidents by ID")
    parser_incident.add_argument("-i", "--incidents",
                                 metavar="ID",
                                 action='store',
                                 type=str,
                                 nargs='+',
                                 help="Get FE incidents by ID")
    parser_incident.set_defaults(func=inc)

    parser_find = subparsers.add_parser('find',
                                        help="find incidents in time")
    parser_find.add_argument("-l", "--last",
                             metavar="M",
                             nargs=1,
                             type=int,required=True,
                             help="Get all incidents published during\
                              the last [M] minutes")
    parser_find.add_argument("-m", "--monitor",
                             action='store_true',
                             default=False,
                             help="active monitoring")
    parser_find.set_defaults(func=find)

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()
    args = parser.parse_args()
   
    if args.debug:
        logging.basicConfig(filename='{}/fe2th.log'.format(
            os.path.dirname(os.path.realpath(__file__))),
                            level='DEBUG',
                            format='%(asctime)s %(levelname)s %(message)s')
    feapi = FireEyeApi(FireEye)
    args.func(args, FireEye['ignored_tags'])

if __name__ == '__main__':
    run()

