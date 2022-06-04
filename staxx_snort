from stix2 import parse
import json
#path file json
#Ip Homenet
#path output
output="D:\Temp\snort.rule"
with open("export1.json") as file:
    data=json.load(file)
for i in data:
    if i=='indicator':
        address=data[i]
    if i=="source":
        msg=data[i]
    if i=='detail':
        detail=data[i]
    if i=="date_last":
        date=data[i]
snort_temp = 'drop {{src}} <> {{dst}} (msg:\"{{msg}}\"; {{other}} priority:5;)'
sig = snort_temp.replace('{{src}}','ip $HOME_NET any') \
				.replace('{{dst}}',address+' any') \
				.replace('{{msg}}','IP: '+detail+' '+msg) \
				.replace('{{other}}','date_last:'+date+';')
print(sig)
file = open(output, "a")
file.write(sig + "\r\n")
file.close


