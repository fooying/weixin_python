#!/usr/bin/python
#encoding=utf-8

import web
import hashlib
import urllib2
import urllib
import time
import xml.dom.minidom
import json
import urlparse
import re
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

urls = (
	'/.*','index',
	)

app = web.application(urls, globals())

render = web.template.render('templates/', cache=False)
helpstr = '帮助:\n1、查看帮助:输入#help#\n2、网址安全查询:输入单个网址即可返回网址安全信息\n3、小黄鸡聊天:输入非特殊关键字可直接与小黄鸡聊天\n4、查看最新wooyun漏洞:输入#漏洞@(提交/公开/确认/待认)#可查看对应最新提交、公开、确认、待认领的漏洞\n5、人脸识别:发送带人脸的图片'

class index:
	def sign(self, dic):
		signature = dic.get('signature','')
		timestamp = dic.get('timestamp','')
		nonce = dic.get('nonce','')
		echostr = dic.get('echostr','ok')
		token = 'fooying'
		checklist = [token,nonce,timestamp]
		checklist.sort()
		strs = checklist[0]+checklist[1]+checklist[2]
		sha1result = hashlib.sha1(strs).hexdigest()	
		if sha1result == signature:
			return echostr
		else:
			return 'fooying'

	def simshttp(self, text):
		text = urllib.quote(text.encode('utf-8'))	
		url = 'http://www.simsimi.com/func/req?lc=ch&msg=%s'%text
		req = urllib2.Request(url) 
		req.add_header('Referer','http://www.simsimi.com/talk.htm?lc=ch') 
		req.add_header('User-Agent','Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)') 
		req.add_header('Accept','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8') 
		req.add_header('Cookie','JSESSIONID=8DBCA2CEF308AB340641266203B30D8F')
		res = urllib2.urlopen(req)
		html = res.read()
		res.close()
		return json.loads(html)

	def scanv(self, url):
		url = 'http://www.anquan.org/seccenter/search/%s'%url
		req = urllib2.Request(url) 
		req.add_header('User-Agent','Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)') 
		res = urllib2.urlopen(req)
		html = res.read()
		res.close()
		score_regex = '''<span\sclass="score">(\d*?)</span>'''
		title_regex = '''<span\sclass="pull-left "\sid="site-title"\stitle="(.*?)">'''
		safe_regex = '''<div\sclass="level-title\ssafe">(.*?)</div>'''
		mal_regex = '''<div\sclass="level-title\sdanger">(.*?)</div>'''
		sus_regex = '''<div\sclass="level-title\ssuspicious">(.*?)</div>'''
		result = {'score':'unknown','title':'','safe':'未知网站'}
		score = re.search(score_regex, html)
		if score:
			result['score'] = score.group(1)
		title = re.search(title_regex, html)
		if title:
			result['title'] = title.group(1)
		safe = re.search(safe_regex, html)
		if safe:
			result['safe'] = '安全网站'
		mal = re.search(mal_regex, html)
		if mal:
			result['safe'] = '危险网站'
		sus = re.search(sus_regex, html)
		if sus:
			result['safe'] = '存在被黑客入侵风险'
		return result	

	def get_woobug(self, text):
		if '@' not in text:
			url = 'http://api.wooyun.org/bugs/limit/1'
		elif '提交' in text:
			url = 'http://api.wooyun.org/bugs/submit/limit/1'
		elif '确认' in text:
			url = 'http://api.wooyun.org/bugs/confirm/limit/1'
		elif '公开' in text:
			url = 'http://api.wooyun.org/bugs/public/limit/1'
		elif '待认' in text:
			url = 'http://api.wooyun.org/bugs/unclaim/limit/1'
		req = urllib2.Request(url) 
		req.add_header('User-Agent','Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)') 
		res = urllib2.urlopen(req)
		html = res.read()
		res.close()
		status= {
			'0':'待厂商确认处理',
			'1':'厂商已经确认',
			'2':'漏洞通知厂商但厂商忽略',
			'3':'未联系到厂商或厂商忽略',
			'4':'正在联系厂商并等待认领',
		}
		bug = json.loads(html)[0]
		msg = '漏洞标题:%s\n漏洞状态:%s\n用户定义危害等级:%s\n厂商定义危害等级:%s\n厂商RANK:%s\n发布日期:%s\n漏洞链接:%s\n'%(bug['title'],status[bug['status']],bug['user_harmlevel'],bug['corp_harmlevel'],bug['corp_rank'],bug['date'],bug['link'])
		return msg

	def faceplus(self, imgurl):
		url = 'https://api.faceplusplus.com/detection/detect?url=%s&api_secret=%s&api_key=%s'%(imgurl,you secret,api_key)
		req = urllib2.Request(url) 
		req.add_header('User-Agent','Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)') 
		res = urllib2.urlopen(req)
		html = res.read()
		res.close()
		faces = json.loads(html)
		xingbie = {
			'Male':'男',
			'Female':'女',
		}
		zhongzu ={
			'White':'白种人',
			'Asian':'黄种人',
			'Black':'黑人',
		}
		msg = ''
		i = 0
		for fa in faces['face']:
			i += 1
			f = fa['attribute']
			xb = xingbie[f['gender']['value']]
			nl = f['age']['value']
			wc = f['age']['range']
			zz = zhongzu[f['race']['value']]
			msg = msg +'人脸%s:\n性别:%s\n年龄:%s(误差:%s)\n种族:%s\n'%(i,xb,nl,wc,zz)
		return msg

	def ifurl(self, text):
		text = text.strip()
		if not '.' in text:
			return False
		elif text.startswith(('http://','https://')):
			return True
		else:
			path = urlparse.urlparse(text).path	
			if text.split('/')[0] == path:
				return True
			else:
				return False

	def post_text(self, msg, FromUserName, ToUserName):
		post = {}
		post['ToUserName'] = FromUserName
		post['FromUserName'] = ToUserName
		post['CreateTime'] = time.time() 
		post['MsgType'] = 'text'
		post['Content'] = msg 
		post['FuncFlag'] = 0 
		web.header('Content-Type', 'text/xml')
		return render.post_text(post)

	def check_text(self, text):
		text = text.strip()
		if text == 'test':
			msg = 'test too！'
		elif text == '#help#':
			msg = helpstr
		elif text.startswith('#漏洞') and text.endswith('#'): 
			msg = self.get_woobug(text)
		elif self.ifurl(text):
			result = self.scanv(text.strip())
			msg = '网址:[%s]\n标题:%s\n检测分数:%s\n安全检测:%s\n该检测结果由安全联盟(http://www.anquan.org)提供技术支持\n'%(text.strip(),result['title'],result['score'],result['safe'])	
		else:
			ret = self.simshttp(text)
			if ret:
				msg = ret['response']
			else:
				msg = '输入#help#查看帮助\n'+helpstr
		return msg

	def GET(self):
		params = web.input()
		return self.sign(params)

	def POST(self):
		params = web.input()
		data= web.data()
		sign = self.sign(params)
		if sign != 'fooying':
			dom = xml.dom.minidom.parseString(data)
			root = dom.documentElement
			ToUserName = root.getElementsByTagName('ToUserName')[0].childNodes[0].data
			FromUserName = root.getElementsByTagName('FromUserName')[0].childNodes[0].data
			CreateTime = root.getElementsByTagName('CreateTime')[0].childNodes[0].data
			MsgType = root.getElementsByTagName('MsgType')[0].childNodes[0].data
			MsgId = root.getElementsByTagName('MsgId')[0].childNodes[0].data
			if MsgType == 'text':
				Content = root.getElementsByTagName('Content')[0].childNodes[0].data
				msg = self.check_text(Content)
			elif MsgType == 'image':
				PicUrl = root.getElementsByTagName('PicUrl')[0].childNodes[0].data
				msg = self.faceplus(PicUrl)
			return self.post_text(msg, FromUserName, ToUserName)	

if __name__ == "__main__":
	app.run()
else:
	application = app.wsgifunc()

