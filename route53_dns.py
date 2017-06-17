# -*- coding: utf-8 -*-

import boto3

from botocore.config import Config
from botocore.exceptions import ClientError
from time import sleep

# this is the entry point
def route53_update_dns(logger, event, context):
    logger.debug("[route53] Updating DNS configuration")

    sourceIp = event['sourceIp']
    previousIp = event['previousIp']
    domain = event['domain']
    subDomain = event['name']

    zone_id = _get_route53_zone_id(logger, domain)

    r = _reset_route53_record(logger, zone_id, domain, '{0}.{1}'.format(subDomain, domain))
    if r != True:
        logger.warning("[route53] Failed to delete DNS record")

    r = _create_route53_record(logger, zone_id, domain, '{0}.{1}'.format(subDomain, domain), 'A', sourceIp)
    if r == None:
        logger.error("[route53] Failed to create DNS entry '{0}.{1}' with value '{2}'.".format(subDomain, domain, sourceIp))
        return {
            'error': "Failed to create DNS entry '{0}.{1}' with value '{2}'.".format(subDomain, domain, sourceIp),
            'sourceIp': event['sourceIp'],
            'previousIp': previousIp
        }

    # since this is a lambda function, it may not be a good idea to wait for DNS sync
    # especially when hooked to API Gateway as the gateway timeout is 30 seconds
    # _wait_route53_record_insync(logger, r)

    return True


def _reset_route53_record(logger, zone_id, zone_name, rr_fqdn):
    """
    Remove previous entry from the hosted zone
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4'))

    if rr_fqdn.endswith('.') is not True:
        rr_fqdn += '.'

    rr_list = []
    results = r53.list_resource_record_sets(
                HostedZoneId=zone_id,
                StartRecordType='A',
                StartRecordName=rr_fqdn,
                MaxItems='100')

    while True:
        rr_list = rr_list + results['ResourceRecordSets']
        if results['IsTruncated'] == False:
            break

        results = r53.list_resource_record_sets(
            HostedZoneId=zone_id,
            StartRecordType='A',
            StartRecordName=results['NextRecordName'])

    r53_changes = { 'Changes': []}
    for rr in rr_list:
        if rr['Name'] == rr_fqdn and rr['Type'] == 'A':
            r53_changes['Changes'].append({
                'Action': 'DELETE',
                'ResourceRecordSet': {
                    'Name': rr['Name'],
                    'Type': rr['Type'],
                    'TTL': rr['TTL'],
                    'ResourceRecords': rr['ResourceRecords']
                }
            })
            try:
                res = r53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=r53_changes)
                logger.info("[route53] Removed resource record '{0}' from hosted zone '{1}'".format(rr_fqdn, zone_name))
                return True

            except ClientError as e:
                logger.error("[route53] Failed to remove resource record '{0}' from hosted zone '{1}'".format(rr_fqdn, zone_name))
                logger.error("[route53] Error: {0}".format(e))
                return None

            break

    logger.debug("[route53] No Resource Record to delete.")
    return False

def _create_route53_record(logger, zone_id, zone_name, rr_fqdn, rr_type, rr_value):
    """
    Create the required dns record for letsencrypt to verify
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4', ))

    if rr_fqdn.endswith('.') is not True:
        rr_fqdn += '.'

    r53_changes = { 'Changes': [{
        'Action': 'CREATE',
        'ResourceRecordSet': {
            'Name': rr_fqdn,
            'Type': rr_type,
            'TTL': 60,
            'ResourceRecords': [{
                'Value': rr_value
            }]
        }
    }]}

    try:
        res = r53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=r53_changes)
        logger.info("[route53] Create letsencrypt verification record '{0}' in hosted zone '{1}'".format(rr_fqdn, zone_name))
        return res

    except ClientError as e:
        logger.error("[route53] Failed to create resource record '{0}' in hosted zone '{1}'".format(rr_fqdn, zone_name))
        logger.error("[route53] Error: {0}".format(e))
        return None

def _wait_route53_record_insync(logger, r53_status):
    """
    Wait until the new record set has been created
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4'))

    logger.info("[route53] Waiting for DNS to synchronize with new value")
    timeout = 60

    status = r53_status['ChangeInfo']['Status']
    while status != 'INSYNC':
        sleep(1)
        timeout = timeout-1
        try:
            r53_status = r53.get_change(Id=r53_status['ChangeInfo']['Id'])
            status = r53_status['ChangeInfo']['Status']

            if timeout == -1:
                return False

        except ClientError as e:
            logger.error("[route53] Failed to retrieve record creation status.")
            logger.error("[route53] Error: {0}".format(e))
            return None

    logger.debug("[route53] Route53 synchronized in {0:d} seconds.".format(60-timeout))
    return True

def _get_route53_zone_id(logger, zone_name):
    r53 = boto3.client('route53', config=Config(signature_version='v4'))

    if zone_name.endswith('.') is not True:
        zone_name += '.'

    try:
        dn = ''
        zi = ''
        zone_list = r53.list_hosted_zones_by_name(DNSName=zone_name)
        while True:
            for zone in zone_list['HostedZones']:
                if zone['Name'] == zone_name:
                    return zone['Id']

            if zone_list['IsTruncated'] is not True:
                return None

            dn = zone_list['NextDNSName']
            zi = zone_list['NextHostedZoneId']

            logger.debug("[route53] Continuing to fetch mode Route53 hosted zones...")
            zone_list = r53.list_hosted_zones_by_name(DNSName=dn, HostedZoneId=zi)

    except ClientError as e:
        logger.error("[route53] Failed to retrieve Route53 zone Id for '{0}'".format(zone_name))
        logger.error("[route53] Error: {0}".format(e))
        return None

    return None

