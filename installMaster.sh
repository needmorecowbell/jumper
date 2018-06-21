git clone https://github.com/aploium/shootback && cd shootback

screen -dm python3 master.py -m 0.0.0.0:10000 -c 0.0.0.0:10022
