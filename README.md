# Reverse TCP Connection


 1. Create Key

    ```bash
    cd keys/ && ssh-keygen
    Enter file in which to save the key (/root/.ssh/id_rsa): digitalOceanKey
    Enter passphrase (empty for no passphrase): 
    Enter same passphrase again: 
    Your identification has been saved in digitalOceanKey.
    Your public key has been saved in digitalOceanKey.pub.
    ```

 2. Fill in Config 

   Add your digitalocean token to config.py
  
 3. Run createMaster.py
        
    `python3 createMaster.py`

 4. Inject command into slave computer 
