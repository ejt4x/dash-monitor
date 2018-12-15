# dash-monitor
Monitor for Amazon dash button pushes and trigger an IFTTT webhook event. 

## Setup
```bash
sudo apt-get install python3-requests scapy
cd /opt
git clone https://github.com/ejt4x/dash-monitor.git
cd dash-monitor
cp config.py.example config.py
sudo cp dash.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable dash-monitor
sudo systemctl start dash-monitor
```

## config.py
This script requires configuration of a few variables to work

```python
# IFTTT maker API key
ifttt_key='17s8239848gi9394ot'

# Dictionary of dash button MAC addresses and desired IFTTT webhook IDs
macs={
       '00:12:34:56:78:99': 'event1',
       '00:12:34:5h:7r:9a': 'event2'
     }
```
