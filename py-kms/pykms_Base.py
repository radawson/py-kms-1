#!/usr/bin/env python3

import binascii
import logging
import time
import uuid
import socket

from pykms_Structure import Structure
from pykms_DB2Dict import kmsDB2Dict
from pykms_PidGenerator import epidGenerator
from pykms_Filetimes import filetime_to_dt
from pykms_Misc import logger_create, KmsParserException, KmsParserHelp, kms_parser_get
from pykms_Format import justify, byterize, enco, deco, pretty_printer

#--------------------------------------------------------------------------------------------------------------------------------------------------------

loggersrv = logging.getLogger('logsrv')
loggerclt = logging.getLogger('logclt')

class UUID(Structure):
        commonHdr = ()
        structure = (
                ('raw', '16s'),
        )

        def get(self):
                return uuid.UUID(bytes_le = enco(str(self), 'latin-1'))

class kmsBase:
        def __init__(self, data, srv_config):
                self.data = data
                self.srv_config = srv_config
                
        class kmsRequestStruct(Structure):
                commonHdr = ()
                structure = (
                        ('versionMinor',            '<H'),
                        ('versionMajor',            '<H'),
                        ('isClientVm',              '<I'),
                        ('licenseStatus',           '<I'),
                        ('graceTime',               '<I'),
                        ('applicationId',           ':', UUID),
                        ('skuId',                   ':', UUID),
                        ('kmsCountedId' ,           ':', UUID),
                        ('clientMachineId',         ':', UUID),
                        ('requiredClientCount',     '<I'),
                        ('requestTime',             '<Q'),
                        ('previousClientMachineId', ':', UUID),
                        ('machineName',             'u'),
                        ('_mnPad',                  '_-mnPad', '126-len(machineName)'),
                        ('mnPad',                   ':'),
                )

                def getMachineName(self):
                        return self['machineName'].decode('utf-16le')
                
                def getLicenseStatus(self):
                        return kmsBase.licenseStates[self['licenseStatus']] or "Unknown"

        class kmsResponseStruct(Structure):
                commonHdr = ()
                structure = (
                        ('versionMinor',         '<H'),
                        ('versionMajor',         '<H'),
                        ('epidLen',              '<I=len(kmsEpid)+2'),
                        ('kmsEpid',              'u'),
                        ('clientMachineId',      ':', UUID),
                        ('responseTime',         '<Q'),
                        ('currentClientCount',   '<I'),
                        ('vLActivationInterval', '<I'),
                        ('vLRenewalInterval',    '<I'),
                )

        class GenericRequestHeader(Structure):
                commonHdr = ()
                structure = (
                        ('bodyLength1',  '<I'),
                        ('bodyLength2',  '<I'),
                        ('versionMinor', '<H'),
                        ('versionMajor', '<H'),
                        ('remainder',    '_'),
                )

        licenseStates = {
                0 : "Unlicensed",
                1 : "Activated",
                2 : "Grace Period",
                3 : "Out-of-Tolerance Grace Period",
                4 : "Non-Genuine Grace Period",
                5 : "Notifications Mode",
                6 : "Extended Grace Period",
        }

        licenseStatesEnum = {
                'unlicensed' : 0,
                'licensed' : 1,
                'oobGrace' : 2,
                'ootGrace' : 3,
                'nonGenuineGrace' : 4,
                'notification' : 5,
                'extendedGrace' : 6
        }

        
        def getPadding(self, bodyLength):
                ## https://forums.mydigitallife.info/threads/71213-Source-C-KMS-Server-from-Microsoft-Toolkit?p=1277542&viewfull=1#post1277542
                return 4 + (((~bodyLength & 3) + 1) & 3)

        def serverLogic(self, kmsRequest):
                pretty_printer(num_text = 15, where = "srv")
                kmsRequest = byterize(kmsRequest)
                loggersrv.debug("KMS Request Bytes: \n%s\n" % justify(deco(binascii.b2a_hex(enco(str(kmsRequest), 'latin-1')), 'latin-1')))                         
                loggersrv.debug("KMS Request: \n%s\n" % justify(kmsRequest.dump(print_to_stdout = False)))
                                        
                clientMachineId = kmsRequest['clientMachineId'].get()
                applicationId = kmsRequest['applicationId'].get()
                skuId = kmsRequest['skuId'].get()
                requestDatetime = filetime_to_dt(kmsRequest['requestTime'])
                                
                # Localize the request time, if module "tzlocal" is available.
                try:
                        from tzlocal import get_localzone
                        from pytz.exceptions import UnknownTimeZoneError
                        try:
                                tz = get_localzone()
                                local_dt = requestDatetime.astimezone(tz)
                        except UnknownTimeZoneError:
                                pretty_printer(log_obj = loggersrv.warning,
                                               put_text = "{reverse}{yellow}{bold}Unknown time zone ! Request time not localized.{end}")
                        except ImportError:
                                pretty_printer(log_obj = loggersrv.warning,
                                               put_text = "{reverse}{yellow}{bold}Module 'tzlocal' not available ! Request time not localized.{end}")
                                local_dt = requestDatetime
                # *** Add generic exception handler to catch any localization errors ***
                except Exception as e:
                        loggersrv.error("Error during timezone localization: %s", str(e), exc_info=True)
                        pretty_printer(log_obj = loggersrv.error, 
                                       put_text = "{reverse}{red}{bold}Timezone localization failed unexpectedly! Using UTC time.{end}")
                        local_dt = requestDatetime # Fallback to original UTC time

                # Activation threshold.
                # https://docs.microsoft.com/en-us/windows/deployment/volume-activation/activate-windows-10-clients-vamt                
                MinClients = kmsRequest['requiredClientCount'] 
                RequiredClients = MinClients * 2
                if self.srv_config["clientcount"] != None:
                        if 0 < self.srv_config["clientcount"] < MinClients:
                                # fixed to 6 (product server) or 26 (product desktop)
                                currentClientCount = MinClients + 1
                                pretty_printer(log_obj = loggersrv.warning,
                                               put_text = "{reverse}{yellow}{bold}Not enough clients ! Fixed with %s, but activated client \
could be detected as not genuine !{end}" %currentClientCount)
                        elif MinClients <= self.srv_config["clientcount"] < RequiredClients:
                                currentClientCount = self.srv_config["clientcount"]
                                pretty_printer(log_obj = loggersrv.warning,
                                               put_text = "{reverse}{yellow}{bold}With count = %s, activated client could be detected as not genuine !{end}" %currentClientCount)
                        elif self.srv_config["clientcount"] >= RequiredClients:
                                # fixed to 10 (product server) or 50 (product desktop)
                                currentClientCount = RequiredClients
                                if self.srv_config["clientcount"] > RequiredClients:
                                        pretty_printer(log_obj = loggersrv.warning,
                                                       put_text = "{reverse}{yellow}{bold}Too many clients ! Fixed with %s{end}" %currentClientCount)
                else:
                        # fixed to 10 (product server) or 50 (product desktop)
                        currentClientCount = RequiredClients     

                        # *** Log calculated client count ***
                        loggersrv.debug("Calculated currentClientCount: %d (Required: %d, Configured: %s)", 
                                        currentClientCount, MinClients, str(self.srv_config.get("clientcount", "Default")))

                        
                # Get a name for SkuId, AppId.        
                kmsdb = kmsDB2Dict()
                app_id_str = str(applicationId)
                sku_id_str = str(skuId)

                # Initialize with raw IDs as default
                determined_app_name = app_id_str
                determined_sku_name = sku_id_str

                try:
                    # 1. Determine Application Name
                    if app_id_str in kmsdb['appItems']:
                        determined_app_name = kmsdb['appItems'][app_id_str].get('DisplayName', app_id_str)
                    else:
                        # Fallback for older KmsDataBase structure or if AppID not directly in appItems top level
                        for app_item_data in kmsdb['appItems'].values():
                            if app_item_data.get('Id') == app_id_str:
                                determined_app_name = app_item_data.get('DisplayName', app_id_str)
                                break

                    # 2. Determine SKU Name (and potentially refine App Name if SKU implies a specific App Group)
                    # Iterate through AppItems, then KmsItems, then SkuItems
                    found_sku_within_app = False
                    for app_item_key, app_item_data in kmsdb['appItems'].items():
                        for kms_item_key, kms_item_data in app_item_data.get('KmsItems', {}).items():
                            if sku_id_str in kms_item_data.get('SkuItems', {}):
                                sku_data = kms_item_data['SkuItems'][sku_id_str]
                                determined_sku_name = sku_data.get('DisplayName', sku_id_str)
                                # If SKU is found, the AppItem it belongs to is the definitive Application Group
                                if app_item_key == app_id_str: # Prioritize if current AppItem matches request AppID
                                     determined_app_name = app_item_data.get('DisplayName', app_id_str)
                                elif not found_sku_within_app: # Otherwise, take the AppItem where SKU was found
                                     # This handles cases where SkuID might be under a different AppID in XML than requested
                                     # but it is less common.
                                     determined_app_name = app_item_data.get('DisplayName', app_id_str)
                                found_sku_within_app = True
                                break # SKU found
                        if found_sku_within_app:
                            break # SKU found, no need to check other AppItems
                
                except Exception as e:
                    loggersrv.error("Unexpected error during product name lookup: %s", e, exc_info=True)

                if determined_sku_name == sku_id_str:
                     pretty_printer(log_obj = loggersrv.warning,
                                    put_text = "{reverse}{yellow}{bold}Can't find a name for this product SKU! (SkuID: %s){end}" % sku_id_str)
                if determined_app_name == app_id_str and not found_sku_within_app:
                     # Only warn about app name if we didn't find the SKU under *any* app that might have refined it.
                     # If an SKU is found, its parent app is considered the correct one.
                     pretty_printer(log_obj = loggersrv.warning,
                                    put_text = "{reverse}{yellow}{bold}Can't find a name for this application group! (AppID: %s){end}" % app_id_str)

                # *** Log product name lookup results ***
                loggersrv.debug("Product Name Lookup: AppName='%s', SkuName='%s'", determined_app_name, determined_sku_name)

                infoDict = {
                        "machineName" : kmsRequest.getMachineName(),
                        "clientMachineId" : str(clientMachineId), 
                        "appId" : app_id_str,             
                        "applicationName": determined_app_name,               
                        "skuId" : sku_id_str,                   
                        "skuName": determined_sku_name,                     
                        "licenseStatus" : kmsRequest.getLicenseStatus(),
                        "requestTime" : int(time.time()),
                        "kmsEpid" : None,
                        "ipAddress" : self.srv_config.get('raddr', ('Unknown', 0))[0]
                }

                # Log client info
                loggersrv.info("Machine Name: %s" % infoDict['machineName'])
                loggersrv.info("Client Machine ID: %s" % infoDict["clientMachineId"])
                loggersrv.info("Application ID: %s" % infoDict["appId"])
                loggersrv.info("SKU ID: %s" % infoDict["skuId"])
                loggersrv.info("License Status: %s" % infoDict["licenseStatus"])
                loggersrv.info("Request Time: %s" % local_dt.strftime('%Y-%m-%d %H:%M:%S %Z (UTC%z)'))
                loggersrv.info("Client IP: %s" % infoDict["ipAddress"])
                
                if self.srv_config['loglevel'] == 'MININFO':
                        loggersrv.mininfo("", extra = {'host': str(self.srv_config['raddr']),
                                                       'status' : infoDict["licenseStatus"],
                                                       'product' : infoDict["skuId"]})
                # Update database.
                if self.srv_config.get('db_instance'):
                        try:
                             self.srv_config['db_instance'].update_client(infoDict)
                             loggersrv.debug("Database updated for client %s", infoDict["clientMachineId"])
                        except Exception as e:
                             loggersrv.error("Failed to update database for client %s: %s", infoDict["clientMachineId"], e, exc_info=True)
                # else:
                     # Legacy database handling (commented out)
                     # if self.srv_config['sqlite']:
                     #         sql_initialize(self.srv_config['sqlite'])
                     #         sql_update(self.srv_config['sqlite'], infoDict)

                # *** Log before calling createKmsResponse ***
                loggersrv.debug("Calling createKmsResponse with currentClientCount: %d", currentClientCount)

                # Pass the looked-up applicationName (descriptive name) to createKmsResponse for the update_epid call
                return self.createKmsResponse(kmsRequest, currentClientCount, infoDict['applicationName'])

        def createKmsResponse(self, kmsRequest, currentClientCount, appNameForDb): # Renamed param for clarity
                # *** Wrap in try/except to catch errors during response creation ***
                try:
                        response = self.kmsResponseStruct()
                        response['versionMinor'] = kmsRequest['versionMinor']
                        response['versionMajor'] = kmsRequest['versionMajor']
                        
                        if not self.srv_config.get("epid"): # Use .get() for safer access
                                response["kmsEpid"] = epidGenerator(kmsRequest['kmsCountedId'].get(), kmsRequest['versionMajor'],
                                                                    self.srv_config.get("lcid", 1033)).encode('utf-16le') # Provide default LCID
                        else:
                                response["kmsEpid"] = self.srv_config["epid"].encode('utf-16le')

                        response['clientMachineId'] = kmsRequest['clientMachineId']
                        # rule: timeserver - 4h <= timeclient <= timeserver + 4h, check if is satisfied (TODO).
                        response['responseTime'] = kmsRequest['requestTime']
                        response['currentClientCount'] = currentClientCount
                        response['vLActivationInterval'] = self.srv_config.get("activation", 120) # Use .get() and provide defaults
                        response['vLRenewalInterval'] = self.srv_config.get("renewal", 10080)

                        # Update database if enabled
                        if self.srv_config.get('db_instance'):
                                # Pass the original AppID (UUID string) from the request for the database query
                                original_app_id_str = str(kmsRequest['applicationId'].get())
                                self.srv_config['db_instance'].update_epid(kmsRequest, response, original_app_id_str)
                        # else:
                                # Update legacy sqlite if enabled
                                # if self.srv_config['sqlite']:
                                #      sql_update_epid(self.srv_config['sqlite'], kmsRequest, response, appNameForDb)

                        loggersrv.info("Server ePID: %s" % response["kmsEpid"].decode('utf-16le'))

                        # *** Log the fully populated response structure before returning ***
                        loggersrv.debug("Populated kmsResponseStruct before returning:\n%s", response.dump(print_to_stdout=False))
                                
                        return response
                except Exception as e:
                        loggersrv.error("Error during createKmsResponse: %s", str(e), exc_info=True)
                        # Optionally return None or raise a specific exception to indicate failure
                        return None # Indicate failure to the caller


import pykms_RequestV4, pykms_RequestV5, pykms_RequestV6, pykms_RequestUnknown

def generateKmsResponseData(data, srv_config):
        version = kmsBase.GenericRequestHeader(data)['versionMajor']
        currentDate = time.strftime("%a %b %d %H:%M:%S %Y")

        if version == 4:
                loggersrv.info("Received V%d request on %s." % (version, currentDate))
                messagehandler = pykms_RequestV4.kmsRequestV4(data, srv_config)     
        elif version == 5:
                loggersrv.info("Received V%d request on %s." % (version, currentDate))
                messagehandler = pykms_RequestV5.kmsRequestV5(data, srv_config)
        elif version == 6:
                loggersrv.info("Received V%d request on %s." % (version, currentDate))
                messagehandler = pykms_RequestV6.kmsRequestV6(data, srv_config)
        else:
                loggersrv.info("Unhandled KMS version V%d." % version)
                messagehandler = pykms_RequestUnknown.kmsRequestUnknown(data, srv_config)
                
        return messagehandler.executeRequestLogic()
