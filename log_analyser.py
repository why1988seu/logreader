#coding:utf-8
import os
import time
import re
import MySQLdb
#import socket
import optparse
import hashlib
import httplib, mimetypes
import urllib
import urllib2
import requests
import geoip2.database
from mpl_toolkits.basemap import Basemap
import matplotlib.pyplot as plt
import numpy as np
import hmac
import base64
import csv
import json
import demjson


fo=open('originresult.txt','w') 
flogread=open('logread.txt','w')
logdir='log'
proxyreg=r'proxy8008-access_log'
datareg=r'[0-9]+/[a-zA-Z]+/[0-9]+'
datadic={'Jan':'01','Feb':'02','Mar':'03','Apr':'04','May':'05','Jun':'06','Jul':'07','Aug':'08','Sep':'09','Oct':'10','Nov':'11','Dec':'12'}
x=1
tstart=time.time()
print 'logfile read module'
for path,d,filelist in os.walk(logdir):
	for filename in filelist:
		if re.search(proxyreg,filename):
			logfilename=os.path.join(path,filename)
			logfile=open(logfilename,'r')
			for s in logfile.readlines():
				s=s.replace('- - ','')
				s=s.replace(' +0800]','')
				s=s.replace('[','')
				s=s.replace('\"','')
				t=re.search(datareg,s).group()
				tt=t.split('/')
				temp=datadic[tt[1]]
				tt[1]=temp
				s=s.replace(t,tt[2]+'-'+tt[1]+'-'+tt[0])
				fo.write(s)
			logfile.close()
			flogread.write(logfilename+'\n')
			x+=1
fo.close()
flogread.close()

print 'MySQL module'
conn=MySQLdb.connect()
cur=conn.cursor()
conn.select_db('test')
sqli1='insert into log(ip,date,method,operation,protocal,status,length) values(%s,%s,%s,%s,%s,%s,%s)'
sqli2='select count(*) from log'
fo=open('result.txt','r') 
foerror=open('logdberror.txt','a+') 
for w in fo.readlines():
	w=w.replace('\n','')
	v=w.split(' ')
	if len(v)<7:
		print v
		foerror.write(w+'\n')
		continue
	cur.execute(sqli1,v)
conn.commit()
print cur.execute(sqli2)
fo.close()
cur.close()
conn.close()

print 'Analyze module'
getshell='eval|execute|binsert|makewebtaski|div.asp|1.asp|1.jsp|1.php|1.aspx|xiaoma.jsp|tom.jsp|py.jsp|k8cmd|ver007|ver008|if|aar'
xss='<script|javascript|onerror|oneclick|onload|<img|alert|document|cookie'
sqlin='select|and 1=1|and 1=2|exec|information_schematables|where|union|SELECT|table_name|cmdshell|table_schema'
scan='sqlmap|acunetix|Netsparker|nmap|HEAD'
filescan='zip|rar|mdb|inc|sql|config|bak|login.inc.php|svn|mysql|config.inc.php|bak|wwwroot|gf_admin|DataBackup|Webconfig|webconfig|1.txt|test.txt'
exp='struts|jmx-console|ajax_membergroup.php|iis.txt|phpMyAdmin|getWriter|dirContext|phpmyadmin|acunetix.txt|SouthidcEditor|DatePicker'
LFI='passwd|%00|win.ini|my.ini|MetaBase.xml|ServUDaemon.ini|cmd.exe'
explist=[getshell,xss,sqlin,scan,filescan,exp,LFI]
expname=['getshell','xss','sqlin','scan','filescan','exp','LFI']
def findexp(expstr,expn):
	myreg=expstr.split('|')
	for expreg in myreg:
		oscmd='type result.txt | findstr '+'\"'+expreg+'\"'+' > result/'+expn+'.txt'
		print oscmd
		os.system(oscmd)
for i in range(len(expname)):
	findexp(explist[i],expname[i])

print 'MySQL analyze module'
conn=MySQLdb.connect()
cur=conn.cursor()
conn.select_db('test')
#sqli1='insert into log(ip,date,method,operation,protocal,status,length) values(%s,%s,%s,%s,%s,%s,%s)'
sqli0='delete from logsum'
sqli1='select distinct ip from log'
sqli2='select count(*) from log where ip=%s'
sqli3='insert into logsum(ip,reqsum,iserror) values(%s,%s,%s)'
cur.execute(sqli0)
cur.execute(sqli1)
iplist = cur.fetchall()
print len(iplist)
x=''
for ip in iplist:
	for path,d,filelist in os.walk('result'):
		for filename in filelist:
			logfile=open(os.path.join(path,filename),'r')
			logexpres=logfile.read()
			if re.search(str(ip),logexpres):
				filename=filename.replace('.txt')
				x=x+filename+','
	cur.execute(sqli2,ip)
	ipreq=cur.fetchone()
	list1=(ip[0],ipreq[0],x)
	cur.execute(sqli3,list1)
conn.commit()
cur.close()
conn.close()


print 'GIS module'
#百度热力图 http://developer.baidu.com/map/jsdemo.htm#c1_15 AK：6vP37S6rqXVPdMzLMBGrYtRGRYcQ8lNQ
reader = geoip2.database.Reader('GeoLite2-City.mmdb')
conn=MySQLdb.connect()
cur=conn.cursor()
conn.select_db('test')
sqli0='delete from logsum'
sqli1='select ip,reqsum from logsum'
sqli2='insert into logsum(ip,reqsum,country,city,lat,lon) values(%s,%s,%s,%s,%s,%s)'
sqli3='select distinct city from logsum'
sqli4="select SUM(reqsum),lat,lon from logsum where city=%s"
cur.execute(sqli1)
iplist = cur.fetchall()
cur.execute(sqli0)
loggis=open('loggis.txt','w')
names = []
atts  = []
lats  = []
lons  = []
cous = []
for ip in iplist:
	#print ip
	response = reader.city(ip[0])
	cou=response.country.iso_code
	city=response.subdivisions.most_specific.name
	lat=response.location.latitude
	lon=response.location.longitude
	reqnum=ip[1]
	cous.append(cou)
	names.append(city)
	atts.append(reqnum)
	lats.append(lat)
	lons.append(lon)
	loggis.write(ip[0]+' '+str(ip[1])+' '+str(city)+' '+str(lat)+'N '+str(lon)+'E '+str(cou)+'\n')
	list1=(ip[0],reqnum,cou,city,lat,lon)
	cur.execute(sqli2,list1)
	#loggis.write(latitude+ip[0]+str(ip[1])+str(city)+'\n')
	#loggis.write(latitude)
reader.close()
loggis.close()
#生成访问次数百度热力图数据
names = []
atts  = []
lats  = []
lons  = []
cur.execute(sqli3)
citylist = cur.fetchall()
for cy in citylist:
	#print cy[0]
	if cy[0]==None:continue
	else:
		cur.execute(sqli4,cy[0])
		totalreq=cur.fetchall()
	#print totalreq
		names.append(cy[0])
		atts.append(int(totalreq[0][0]))
		lats.append(totalreq[0][1])
		lons.append(totalreq[0][2])
conn.commit()
cur.close()
conn.close()
# {"lng":116.418261,"lat":39.921984,"count":50},
baidugis=open('baidugis.txt','w')
for i in range(len(lons)):
	baidugis.write("{lng:"+str(lons[i])+',"lat":'+str(lats[i])+',"count":'+str(atts[i])+'},\n')
baidugis.close()
#GIS画图
map = Basemap(projection='cyl',lat_0=90,lon_0=-180,resolution='l')
map.drawcoastlines(linewidth=0.25)
map.drawcountries(linewidth=0.25)
map.drawmapboundary(fill_color='#689CD2')
map.drawmeridians(np.arange(0,360,30))
map.drawparallels(np.arange(-90,90,30))
map.fillcontinents(color='#BF9E30',lake_color='#689CD2',zorder=0)
x, y = map(lons, lats)
max_att = max(atts)
att_factor = 80.0
y_offset    = 15.0
rotation    = 30
for i,j,k,name in zip(x,y,atts,names):
    size = att_factor*k/max_att
    cs = map.scatter(i,j,s=size,marker='o',color='#FF5600')
    plt.text(i,j+y_offset,name,rotation=rotation,fontsize=10)
plt.title('Major Attacks')
plt.show()
'''
#IP138在线查

	url = "http://www.ip138.com/ips138.asp?ip=%s&action=2" %ip[0]
	response = requests.get(url)
	loggis.write(ip[0]+' ')
	result = re.findall(r'<td align="center"><ul class="ul1"><li>(.*?)</li>',response.content)
	loggis.write(result[0][10:])
	loggis.write('\n')
loggis.close()
cur.close()
conn.close()
loggis=open('loggis.txt','r')
loggisnew=open('loggisnew.txt','w')
for i in loggis.readlines():
	result=i.split(' ')
	#print result
	if len(result)==4:
		i=result[0]+' '+result[1]+' '+result[-1]
		loggisnew.write(i)
	else:
		loggisnew.write(i)
loggis.close()
loggisnew.close()
'''

print 'Odd access time analyzer module'
conn=MySQLdb.connect()
cur=conn.cursor()
conn.select_db('test')
sqli1='select ip,maxtime,mintime,lat,lon from logsum'
sqli2='select ip from logsum'
sqli3='select max(date),min(date) from log where ip=%s'
sqli4='update logsum set mintime=%s,maxtime=%s where ip=%s'
cur.execute(sqli1)
timelist = cur.fetchall()
oddtime=open('oddtime.txt','w')
for i in timelist:
	#print i
	mindate=i[1].split(':')
	maxdate=i[2].split(':')
	if mindate[1]<='07' or maxdate[1]>='23':
		oddtime.write(i[0]+' '+i[1]+' '+i[2]+' '+str(i[3])+' '+str(i[4])+'\n')
cur.execute(sqli2)
timelist = cur.fetchall()
for i in timelist:
	cur.execute(sqli3,i[0])
	mmlist = cur.fetchall()
	#print mmlist
	list1=(mmlist[0][0],mmlist[0][1],i[0])
	cur.execute(sqli4,list1)
conn.commit()
oddtime.close()
cur.close()
conn.close()
#生成异常时间百度热力图数据
ips  = []
lats  = []
lons  = []
oddtime=open('oddtime.txt','r')
for odtime in oddtime.readlines():
	odtime=odtime.strip()
	odtimebdgis=odtime.split(' ')
	ips.append(odtimebdgis[0])
	lats.append(odtimebdgis[3])
	lons.append(odtimebdgis[4])
# {"lng":116.418261,"lat":39.921984,"count":50},
odtimebdgis=open('odtimebdgis.txt','w')
for i in range(len(ips)):
	odtimebdgis.write('{"lng":'+str(lons[i])+',"lat":'+str(lats[i])+',"count":'+'50'+'},\n')
oddtime.close()
odtimebdgis.close()

'''
print 'Saas Threat Intelligence module'
tstart=time.time()
key='gLTL9RPzEdHb9mO5bqQtG3XUcqR4GdWE'
#key=gLTL9RPzEdHb9mO5bqQtG3XUcqR4GdWE
#token=e312c2776eb0441086bcf9b481ebbc46
w1='\"type\":\"IP\",'
w3='\"scene\":\"login\",'
w4='\"token\":\"e312c2776eb0441086bcf9b481ebbc46\"'
loggis=open('loggis.txt','w')
saasti=open('saasti.txt','w')
for i in loggis.readlines():
	saasip=i.split(' ')
	w2='\"value\":\"'+saasip[0]+'\",'
	data='{'+w1+w2+w3+w4+'}'
	s=hmac.new(key,data,hashlib.sha1).digest().encode('base64').rstrip()
	postdata = "{\n" +w1+"\n" +w2+"\n" +w3+"\n" +w4+",\n" +"\"sign\":\""+s+"\"\n" +"}\n"
	postdataencode=postdata.encode('utf-8')
	url = 'http://api-security.ctrip.com/secsaas-service/services/risk'
	req = urllib2.Request(url,postdataencode)
	req.add_header('Content-Type','application/json')
	r = urllib2.urlopen(req)
	html = r.read()
	print html
	htmldic=json.loads(html)
	saasrisk=htmldic["risk"]
	if saasrisk>=3:
		saasti.write(i[0]+' '+i[1]+' '+i[2]+' '+str(saasrisk)+'\n')
loggis.close()
saasti.close()
tend=time.time()
print (tend-tstart)*1.0/60
'''


print 'ThreatBook Threat Intelligence module'
API_KEY = "7a40164e629f44839a2f9a54aec609dd261454d3158d4436a610ba08b8919ff2"
loggis=open('loggis.txt','r')
tbti=open('tbti.txt','w')
for i in loggis.readlines():
	mode=0
	conf=0
	tbip=i.split(' ')
	url = "https://x.threatbook.cn/api/v1/ip/query"
	parameters = {"ip": tbip[0], "apikey": API_KEY, "field":"domains,tags,judgments,intelligences"} #"location,tags,judgments,"}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	ret_json = response.read()
	if re.search('tags',ret_json):
		print ret_json
		#mode=1
	if re.search('judgments',ret_json):
		#print ret_json
		mode=3	
	#htmldic=json.loads(ret_json.encode(''))
	ret_json=demjson.decode(ret_json)
	if ret_json["response_code"]==0:
		carrier=ret_json["ip"]["carrier"].encode('utf-8')
		ip=ret_json["ip"]["ip"].encode('utf-8')
		location=ret_json["ip"]["location"]["country"].encode('utf-8')+' '+ret_json["ip"]["location"]["province"].encode('utf-8')+' '+ret_json["ip"]["location"]["city"].encode('utf-8')
		lat=ret_json["ip"]["location"]["lat"].encode('utf-8')
		lon=ret_json["ip"]["location"]["lng"].encode('utf-8')
		if mode==3:
			jug=ret_json["judgments"]
			#print jug
			tbti.write(ip+' '+location+' '+carrier+' '+lat+' '+lon+' ')
			for i in range(len(jug)):
				tbti.write(jug[i].encode('utf-8')+' ')
			tbti.write('\n')
		else:
			tbti.write(ip+' '+location+' '+carrier+' '+lat+' '+lon+'\n')
	else:
		continue
#{"response_code":0,"judgments":["Dynamic IP"],"ip":{"carrier":"电信","ip":"218.4.166.174","location":{"country":"中国","province":"江苏","lng":"120.619585","city":"苏州","lat":"31.299379"}},"intelligences":[{"find_time":"2016-05-17 13:28:03","confidence":80,"source":"ThreatBook Labs","intel_types":["动态IP"]}]}
loggis.close()
tbti.close()
#生成zombie热力图
zcount=0
tbtianly=open('tbti.txt','r')
tbzombie=open('tbzombie.txt','w')
tbip=open('tbip.txt','w')
for i in tbtianly.readlines():
	if re.search('Zombie',i):
		zcount+=1
		tbanly=i.split(' ')
		tbzombie.write('{"lng":'+tbanly[6]+',"lat":'+tbanly[5]+',"count":'+'80'+'},\n')
		tbip.write(tbanly[0]+'\n')
print zcount
tbip.write('*'*10+'\n')
#生成spam热力图
scount=0
tbtianly.seek(0)
tbspam=open('tbspam.txt','w')
for i in tbtianly.readlines():
	if re.search('Spam',i):
		scount+=1
		tbanly=i.split(' ')
		tbspam.write('{"lng":'+tbanly[6]+',"lat":'+tbanly[5]+',"count":'+'80'+'},\n')
		tbip.write(tbanly[0]+'\n')
print scount
tbtianly.close()
tbzombie.close()
tbspam.close()


'''
print 'csv sqlin module'
reader = geoip2.database.Reader('GeoLite2-City.mmdb')
readercsv = csv.reader(file('SQLin_report.csv', 'rb'))
sqlingis=open('sqlingis.txt','w')
for line in readercsv:
	response = reader.city(line[1])
	cou=response.country.iso_code
	city=response.subdivisions.most_specific.name
	lat=response.location.latitude
	lon=response.location.longitude
# {"lng":116.418261,"lat":39.921984,"count":50},
	sqlingis.write("{lng:"+str(lon)+',"lat":'+str(lat)+',"count":'+'80'+'},\n')
sqlingis.close()
reader.close()
#readercsv.close()
'''


'''
tend=time.time()
print (tend-tstart)*1.0/60
'''