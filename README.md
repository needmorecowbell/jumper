# Jumper


![jumper](res/jumper.gif)


### Requirements

- Digital Ocean api token
- Firewalled Client with SSH, python2/3, and wget
- Remote Client with python3


### Installation
 
 1. **Create Key**
  
     - `cd keys/ && ssh-keygen`
    
   ```
   Enter file in which to save the key (/root/.ssh/id_rsa): digitalOceanKey
   Enter passphrase (empty for no passphrase): 
   Enter same passphrase again: 
   Your identification has been saved in digitalOceanKey.
   Your public key has been saved in digitalOceanKey.pub.
   ``` 

 2. **Fill in Config** 
      
    Add your Digital Ocean token to config.py using a text editor.
      - [How to Get Access Token](https://www.digitalocean.com/community/tutorials/how-to-use-the-digitalocean-api-v2)
       
 3. **Install requirements** 

     - `pip install -r requirements.txt`
 
 4. **Run createMaster.py**
        
    - `python3 createMaster.py`

 5. **Inject command into slave computer** 

    Slave computer must have slaver_singlefile.py in current directory when executing. Either python version will work for this step.
    
    -  `python3 slaver_singlefile.py -m <master-ip> -t 127.0.0.1:22`
    -  `python slaver_singlefile.py -m <master-ip> -t 127.0.0.1:22`
 
 6. **Connect to Tunnelled Client**

    -  `ssh <user>@<master-ip> -p 10022`


