# dash-monitor
Monitor for Amazon dash button pushes and trigger an IFTTT webhook event. 

## config.py
This script requires a configuration file named config.py to be present in the same directory
```python
# IFTTT maker API key
ifttt_key='17s8239848gi9394ot'

# Dictionary of dash button MAC addresses and desired IFTTT webhook IDs
macs={
       '00:12:34:56:78:99': 'event1',
       '00:12:34:5h:7r:9a': 'event2'
     }
```
