
import json
from venv import create
from cv2 import pencilSketch
from stix2 import Infrastructure,Relationship,IPv4Address,Bundle
from yaml import serialize

#create STIX object
infrastructure = Infrastructure(type='infrastructure',
spec_version='2.1',
id='infrastructure--78cc7b4b-c6ab-40d1-82eb-95a3059641da',
name='Malware test created',
created="2022-06-03T03:55:54.700597Z",
modified="2022-06-03T03:55:54.700597Z",
)
realationship= Relationship( type= "relationship",
   
    spec_version= "2.1",
   
    id="relationship--7aebe2f0-28d6-48a2-9c3e-b0aaa60266ef",
   
    created= "2017-03-16T10:19:23.000Z",
   
    modified= "2017-03-16T10:19:23.000Z",
   
    relationship_type="consists-of",
   
    source_ref="infrastructure--78cc7b4b-c6ab-40d1-82eb-95a3059641da",
   
    target_ref="ipv4-addr--4d22aae0-2bf9-5427-8819-e4f6abf20a53")
ip=IPv4Address( id= "ipv4-addr--4d22aae0-2bf9-5427-8819-e4f6abf20a53",
    type="ipv4-addr",
   
    value="192.168.0.41")
bundle = Bundle(objects=[infrastructure, realationship, ip])
# test output stix object
print(bundle.serialize(pretty=True))
for obj in bundle.objects:
    if obj==infrastructure:
        msg=obj.name
    if obj==ip:
        address=obj.value
    if obj==realationship:
        sid=obj.id
#Test output         
# print(address)
# print(msg)
# print(sid)


#create snort rule from stix object
output="D:\Temp\snort.rule"
snort_temp = 'alert {{src}} <> {{dst}} (msg:\"OpenSource Intelligence {{msg}}\"; {{other}} priority:5;)'
sig = snort_temp.replace('{{src}}','ip $HOME_NET any') \
				.replace('{{dst}}',address+' any') \
				.replace('{{msg}}','IP: '+address+' '+msg) \
				.replace('{{other}}','sid:'+sid+';')
print(sig)
file = open(output, "w")
file.write(sig + "\r\n")
file.close





