#!/usr/bin/env python3

import os
import xml.etree.ElementTree as ET

#---------------------------------------------------------------------------------------------------------------------------------------------------------

def kmsDB2Dict():
        path = os.path.join(os.path.dirname(__file__), 'KmsDataBase.xml')
        root = ET.parse(path).getroot()

        kmsdb_dict = {}  # Initialize as a dictionary

        # Get winbuilds.
        win_builds_list = []
        for winbuild in root.iter('WinBuild'):
                win_builds_list.append(winbuild.attrib)
        kmsdb_dict['winBuilds'] = win_builds_list
        
        # Get csvlkitem data.
        csvlk_items_list = []
        for csvlk in root.iter('CsvlkItem'):
                current_csvlk_activates = []
                for activ in csvlk.iter('Activate'):
                        current_csvlk_activates.append(activ.attrib['KmsItem'])
                
                # Make a copy of attrib to modify it
                csvlk_data = dict(csvlk.attrib)
                if current_csvlk_activates: # Only add Activate key if there are items
                    csvlk_data['Activate'] = current_csvlk_activates
                csvlk_items_list.append(csvlk_data)
        kmsdb_dict['csvlkItems'] = csvlk_items_list

        # Get appitem data.
        app_items_dict = {} # This will be a dictionary keyed by AppID
        for app in root.iter('AppItem'):
                app_id = app.attrib.get('Id')
                if not app_id:
                    # Skip AppItem if it doesn't have an Id, or log a warning
                    print(f"Warning: AppItem found without an Id in KmsDataBase.xml: {app.attrib}")
                    continue

                kms_items_dict_for_app = {}
                for kms in app.iter('KmsItem'):
                        kms_id = kms.attrib.get('Id')
                        if not kms_id:
                            # Skip KmsItem if it doesn't have an Id
                            print(f"Warning: KmsItem found without an Id in AppItem '{app_id}': {kms.attrib}")
                            continue

                        sku_items_dict_for_kms = {}
                        for sku in kms.iter('SkuItem'):
                                sku_id = sku.attrib.get('Id')
                                if not sku_id:
                                    # Skip SkuItem if it doesn't have an Id
                                    print(f"Warning: SkuItem found without an Id in KmsItem '{kms_id}' (App '{app_id}'): {sku.attrib}")
                                    continue
                                sku_items_dict_for_kms[sku_id] = dict(sku.attrib)
                        
                        # Make a copy of kms.attrib to modify it
                        kms_data = dict(kms.attrib)
                        if sku_items_dict_for_kms: # Only add SkuItems key if there are items
                            kms_data['SkuItems'] = sku_items_dict_for_kms
                        kms_items_dict_for_app[kms_id] = kms_data
                
                # Make a copy of app.attrib to modify it
                app_data = dict(app.attrib)
                if kms_items_dict_for_app: # Only add KmsItems key if there are items
                    app_data['KmsItems'] = kms_items_dict_for_app
                app_items_dict[app_id] = app_data
                
        kmsdb_dict['appItems'] = app_items_dict

        return kmsdb_dict
