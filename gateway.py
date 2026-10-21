from datetime import datetime, timezone, timedelta
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from email.mime.text import MIMEText
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import requests
import secrets
import hashlib
import smtplib
import base64
import copy
import hmac
import json
import time
import zlib
import ssl
import sys
import os
import re

class MainConfigsGateCryptsStore:
    """后台加密协议：隔离请求、回执及持久化状态，验证密文完整性。"""
    @staticmethod
    def encode(value):
        return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode("utf-8")
    @staticmethod
    def decode(value):
        return base64.b64decode(str(value).encode("ascii"),validate=True)
    @classmethod
    def seal(cls,value,key,context):
        cipher=AES.new(key,AES.MODE_GCM,nonce=secrets.token_bytes(12))
        cipher.update(context.encode("utf-8"))
        encrypted,tag=cipher.encrypt_and_digest(cls.encode(value))
        return base64.b64encode(cipher.nonce+tag+encrypted).decode("ascii")
    @classmethod
    def unseal(cls,value,key,context,compressed=False):
        raw=cls.decode(value)
        if len(raw)<28:raise ValueError("密文长度错误")
        cipher=AES.new(key,AES.MODE_GCM,nonce=raw[:12])
        cipher.update(context.encode("utf-8"))
        plaintext=cipher.decrypt_and_verify(raw[28:],raw[12:28])
        if compressed:
            decoder=zlib.decompressobj();plaintext=decoder.decompress(plaintext,80001)
            if len(plaintext)>80000 or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:raise ValueError("请求解压长度错误")
        result=json.loads(plaintext.decode("utf-8"))
        if not isinstance(result,dict):raise ValueError("密文内容结构错误")
        return result
    @classmethod
    def unwrap(cls,body,private_key):
        if not isinstance(body,str) or not body.startswith("ENGREQ1:") or len(body)>62000:raise ValueError("请求格式错误")
        envelope=json.loads(cls.decode(body[8:]).decode("utf-8"))
        if not isinstance(envelope,dict) or set(envelope)!={"key","data","zip"} or envelope["zip"]!="zlib":raise ValueError("请求封装错误")
        secret=PKCS1_OAEP.new(RSA.import_key(private_key),hashAlgo=SHA256).decrypt(cls.decode(envelope["key"]))
        return cls.unseal(envelope["data"],secret,"ENGINEERING_REQUEST_V1",True)
    @staticmethod
    def installation_token(app_id,installation_id,private_key,repository):
        if not str(app_id).isdigit() or not str(installation_id).isdigit():raise ValueError("管理端App配置无效")
        jwt_token=MainConfigsGateCryptsStore.app_jwt(app_id,private_key)
        headers={"Authorization":"Bearer "+jwt_token,"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"}
        with requests.Session() as token_session:
            with token_session.post(f"https://api.github.com/app/installations/{installation_id}/access_tokens",headers=headers,json={"repositories":[repository.split("/",1)[1]],"permissions":{"contents":"write","issues":"write","metadata":"read"}},timeout=(10,30)) as response:
                if response.status_code!=201:raise RuntimeError(f"管理端令牌获取失败 HTTP {response.status_code}")
                result=response.json()
            token=str(result.get("token","") or "")
            if not token:raise RuntimeError("管理端令牌缺失")
            verified=False;headers["Authorization"]="Bearer "+token
            try:
                if result.get("permissions")!={"contents":"write","issues":"write","metadata":"read"}:raise RuntimeError("管理端令牌权限不匹配")
                with token_session.get("https://api.github.com/installation/repositories?per_page=100",headers=headers,timeout=(10,30)) as response:
                    if response.status_code!=200:raise RuntimeError("管理端令牌仓库核验失败")
                    repositories=response.json()
                if repositories.get("total_count")!=1 or [entry.get("full_name") for entry in repositories.get("repositories",[])]!=[repository]:raise RuntimeError("管理端令牌仓库范围不匹配")
                verified=True
                return token
            finally:
                if not verified:
                    try:
                        with token_session.delete("https://api.github.com/installation/token",headers=headers,timeout=(10,15)) as revoke_response:
                            if revoke_response.status_code!=204:print(f"❌ Failed verification token revocation returned HTTP {revoke_response.status_code}")
                    except requests.RequestException as revoke_error:print(f"❌ Failed verification token revocation failed: {type(revoke_error).__name__}")
    @staticmethod
    def app_jwt(app_id,private_key):
        key=RSA.import_key(private_key)
        if not key.has_private() or not str(app_id).isdigit():raise ValueError("App签名配置无效")
        now=int(time.time())
        def encode_part(value):return base64.urlsafe_b64encode(MainConfigsGateCryptsStore.encode(value)).rstrip(b"=")
        payload=encode_part({"alg":"RS256","typ":"JWT"})+b"."+encode_part({"iat":now-60,"exp":now+540,"iss":str(app_id)})
        signature=pkcs1_15.new(key).sign(SHA256.new(payload))
        return (payload+b"."+base64.urlsafe_b64encode(signature).rstrip(b"=")).decode("ascii")

class MainConfigsGateRemoteStore:
    """仓库访问适配：固定仓库和接口，使用乐观锁提交业务数据及去重记录。"""
    def __init__(self,formal,inbox,writer_token,inbox_token,state_key,branch="main",inbox_branch="main"):
        for repository in (formal,inbox):
            if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",repository):raise ValueError("仓库名称错误")
        if formal==inbox:raise ValueError("接收仓库不能与正式仓库相同")
        self.formal,self.inbox=formal,inbox
        self.writer_token,self.inbox_token=writer_token,inbox_token
        self.state_key=state_key
        self.branch,self.inbox_branch=branch,inbox_branch
        self.session=requests.Session()
        self.state_sha=""
    def close(self):self.session.close()
    def request(self,method,path,payload=None,inbox=False,accepted=(200,201)):
        token=self.inbox_token if inbox else self.writer_token
        with self.session.request(method,"https://api.github.com/"+path.lstrip("/"),headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"},json=payload,timeout=(10,30)) as response:
            if response.status_code not in accepted:raise RuntimeError(f"GitHub {method} 请求失败 HTTP {response.status_code}")
            if response.status_code in (204,404):return None
            return response.json()
    def read_file(self,path,ref=None,inbox=False):
        repository=self.inbox if inbox else self.formal
        suffix="?ref="+requests.utils.quote(ref,safe="") if ref else ""
        result=self.request("GET",f"repos/{repository}/contents/{path}{suffix}",inbox=inbox,accepted=(200,404))
        if result is None:return None,""
        if isinstance(result,dict) and result.get("encoding")=="none" and int(result.get("size",0))<=16000000:
            result=self.request("GET",f"repos/{repository}/git/blobs/{result['sha']}",inbox=inbox)
        if not isinstance(result,dict) or result.get("encoding")!="base64":raise RuntimeError("GitHub文件响应无效")
        return base64.b64decode(result.get("content","").replace("\n",""),validate=True),str(result.get("sha","") or "")
    def read_json(self,path,ref=None):
        content,_=self.read_file(path,ref)
        if content is None:return None
        result=json.loads(content.decode("utf-8-sig"))
        if not isinstance(result,dict):raise ValueError("远程JSON结构错误")
        return result
    def load_state(self):
        content,self.state_sha=self.read_file("github_gateway_state.enc",self.inbox_branch,True)
        if content is None:raise RuntimeError("后台状态尚未初始化，已停止处理")
        return MainConfigsGateCryptsStore.unseal(content.decode("ascii"),self.state_key,"ENGINEERING_STATE_V1")
    def save_state(self,state):
        encrypted=MainConfigsGateCryptsStore.seal(state,self.state_key,"ENGINEERING_STATE_V1").encode("ascii")
        payload={"message":"Update encrypted gateway state","content":base64.b64encode(encrypted).decode("ascii"),"branch":self.inbox_branch}
        if self.state_sha:payload["sha"]=self.state_sha
        try:result=self.request("PUT",f"repos/{self.inbox}/contents/github_gateway_state.enc",payload,True)
        except (requests.RequestException,RuntimeError):
            current,current_sha=self.read_file("github_gateway_state.enc",self.inbox_branch,True)
            if current!=encrypted:raise
            self.state_sha=current_sha
            return
        self.state_sha=result["content"]["sha"]
    def commit_json(self,path,request_id,digest,mutator):
        if path not in ("github_project_users.json","github_project_cards.json","github_project_stats.json"):raise ValueError("禁止修改该文件")
        receipt_path="github_gateway_receipts.enc"
        for attempt in range(5):
            head=self.request("GET",f"repos/{self.formal}/git/ref/heads/{self.branch}")["object"]["sha"]
            commit=self.request("GET",f"repos/{self.formal}/git/commits/{head}")
            raw,_=self.read_file(receipt_path,head)
            ledger=MainConfigsGateCryptsStore.unseal(raw.decode("ascii"),self.state_key,"ENGINEERING_RECEIPTS_V1") if raw else {"requests":{},"counters":{}}
            existing=ledger.setdefault("requests",{}).get(request_id)
            if existing:
                if not hmac.compare_digest(existing.get("digest",""),digest):raise ValueError("请求编号冲突")
                return existing["result"]
            document=self.read_json(path,head)
            if document is None:raise ValueError("正式数据文件缺失，已停止写入")
            result=mutator(document,ledger)
            now=time.time()
            ledger["requests"]={key:value for key,value in ledger["requests"].items() if now-float(value.get("at",0))<35*86400}
            ledger["requests"][request_id]={"digest":digest,"result":result,"at":now}
            entries=[]
            contents={path:json.dumps(document,ensure_ascii=False,indent=4),receipt_path:MainConfigsGateCryptsStore.seal(ledger,self.state_key,"ENGINEERING_RECEIPTS_V1")}
            for filename,content in contents.items():entries.append({"path":filename,"mode":"100644","type":"blob","content":content})
            tree=self.request("POST",f"repos/{self.formal}/git/trees",{"base_tree":commit["tree"]["sha"],"tree":entries})
            created=self.request("POST",f"repos/{self.formal}/git/commits",{"message":"Gateway "+request_id,"tree":tree["sha"],"parents":[head]})
            try:
                self.request("PATCH",f"repos/{self.formal}/git/refs/heads/{self.branch}",{"sha":created["sha"],"force":False})
                return result
            except (requests.RequestException,RuntimeError):
                latest,_=self.read_file(receipt_path,self.branch)
                recovered=MainConfigsGateCryptsStore.unseal(latest.decode("ascii"),self.state_key,"ENGINEERING_RECEIPTS_V1") if latest else {}
                saved=recovered.get("requests",{}).get(request_id)
                if saved:
                    if not hmac.compare_digest(saved.get("digest",""),digest):raise ValueError("请求编号冲突")
                    return saved["result"]
                if attempt==4:raise
        raise RuntimeError("正式数据提交未完成")
    def pages(self,path,inbox=False):
        separator="&" if "?" in path else "?"
        for page in range(1,101):
            rows=self.request("GET",f"repos/{self.inbox if inbox else self.formal}/{path}{separator}per_page=100&page={page}",inbox=inbox)
            if not isinstance(rows,list):raise RuntimeError("GitHub列表响应无效")
            yield from rows
            if len(rows)<100:return
        raise RuntimeError("列表超过安全分页范围，需分批处理")
    def find_issue(self,marker):
        for issue in self.pages("issues?state=all&sort=created&direction=desc"):
            if "pull_request" not in issue and marker in str(issue.get("body","") or ""):return issue
        return None
    def create_issue(self,payload,marker):
        existing=self.find_issue(marker)
        if existing:return existing
        value=dict(payload);value["body"]=str(value.get("body","") or "")+"\n"+marker
        return self.request("POST",f"repos/{self.formal}/issues",value)
    def append_comment(self,number,body,marker):
        for comment in self.pages(f"issues/{int(number)}/comments"):
            if marker in str(comment.get("body","") or ""):return comment
        return self.request("POST",f"repos/{self.formal}/issues/{int(number)}/comments",{"body":body+"\n"+marker})
    def result_comment(self,number,body):
        for comment in self.pages(f"issues/{int(number)}/comments",True):
            if comment.get("body")==body:return
        self.request("POST",f"repos/{self.inbox}/issues/{int(number)}/comments",{"body":body},True)

class MainConfigsGateWorkerStore:
    """可信后台处理：邮箱验证、设备授权、字段校验及幂等业务提交。"""
    def __init__(self,remote,private_key,state_key,mailer,now=None):
        self.remote,self.private_key,self.state_key,self.mailer=remote,private_key,state_key,mailer
        self.now=now if callable(now) else time.time
        self.state=remote.load_state()
        if self.state.get("version")!=1:raise ValueError("后台状态版本错误")
        for field in ("requests","challenges","sessions","mail_limits","feedback_limits","legacy_issues"):
            if not isinstance(self.state.get(field),dict):raise ValueError("后台状态字段错误")
    def save(self):self.remote.save_state(self.state)
    def timestamp(self):return datetime.fromtimestamp(self.now(),timezone(timedelta(hours=8))).strftime("%Y-%m-%dT%H:%M:%S")
    def marker(self,kind,value):
        text=kind+":"+value
        signature=hmac.new(self.state_key,text.encode("utf-8"),hashlib.sha256).hexdigest()
        return f"<!-- engineering:{text}:{signature} -->"
    def account(self,username):
        document=self.remote.read_json("github_project_users.json")
        if not isinstance(document,dict) or not isinstance(document.get("users"),list):raise ValueError("账号资料不可用")
        matches=[row for row in document["users"] if isinstance(row,dict) and row.get("github_username")==username]
        if len(matches)!=1:raise ValueError("账号不存在或资料重复")
        return matches[0]
    def validate(self,request,existing=False):
        required={"v","id","at","action","user","device","session","payload","reply"}
        if not isinstance(request,dict) or set(request)!=required or request.get("v")!=1:raise ValueError("请求结构错误")
        if not re.fullmatch(r"[a-f0-9]{32}",str(request["id"])):raise ValueError("请求编号错误")
        if not isinstance(request["at"],(int,float)) or (not existing and not 0<=self.now()-request["at"]+300<=86400+300):raise ValueError("请求已过期，请重新提交")
        if not isinstance(request["user"],str) or not 1<=len(request["user"])<=120:raise ValueError("账号错误")
        if not re.fullmatch(r"[A-Fa-f0-9]{32,128}",str(request["device"])):raise ValueError("设备标识错误")
        if not isinstance(request["payload"],dict) or len(MainConfigsGateCryptsStore.encode(request["payload"]))>60000:raise ValueError("请求内容过大或结构错误")
        if len(MainConfigsGateCryptsStore.decode(request["reply"]))!=32:raise ValueError("回执密钥错误")
        if request["action"] not in ("auth.begin","auth.verify","device.touch","card.save","card.hide","issue.create","issue.close","feedback.add","stats.merge","diagnostic.add"):raise ValueError("不允许的操作")
    def identity(self,request):
        token=request.get("session","")
        if not isinstance(token,str) or not 32<=len(token)<=128:raise ValueError("AUTH_REQUIRED|请先完成邮箱验证")
        session=self.state["sessions"].get(hashlib.sha256(token.encode("utf-8")).hexdigest())
        if not session or session.get("user")!=request["user"] or session.get("device")!=request["device"]:raise ValueError("AUTH_REQUIRED|登录凭据不匹配")
        account=self.account(request["user"])
        if account.get("email")!=session.get("email"):raise ValueError("AUTH_REQUIRED|邮箱资料已变化，请重新验证")
        devices=account.get("devices",{})
        if not isinstance(devices,dict) or not any(str(value).split("|")[0]==request["device"] for value in devices.values()):raise ValueError("AUTH_REQUIRED|当前设备授权已失效")
        return account
    def begin(self,request):
        account=self.account(request["user"])
        email=str(account.get("email","") or "").strip()
        if not re.fullmatch(r"[^\s@\r\n]+@[^\s@\r\n]+\.[^\s@\r\n]+",email):raise ValueError("账号邮箱配置无效")
        request_id=request["id"]
        challenge=self.state["challenges"].get(request_id)
        if challenge is None:
            recent=[stamp for stamp in self.state["mail_limits"].get(request["user"],[]) if 0<=self.now()-float(stamp)<3600]
            if len(recent)>=5:raise ValueError("发送频繁，请稍后再试，每小时上限5次")
            recent.append(self.now());self.state["mail_limits"][request["user"]]=recent
            code="".join(secrets.choice("ABCDEFGHJKLMNOPQRSTUVXYZ") for _ in range(6))
            challenge={"user":request["user"],"device":request["device"],"email":email,"code":code,"at":self.now(),"tries":0,"sent":False,"used":False}
            self.state["challenges"][request_id]=challenge
            self.save()
        if not challenge["sent"]:
            self.mailer(email,challenge["code"])
            challenge["sent"]=True;challenge["at"]=self.now();self.save()
        return {"challenge":request_id,"email":email,"expires":challenge["at"]+600}
    def enroll_device(self,request,digest):
        def mutate(document,ledger):
            users=document.get("users")
            if not isinstance(users,list):raise ValueError("账号资料结构错误")
            matches=[entry for entry in users if isinstance(entry,dict) and entry.get("github_username")==request["user"]]
            if len(matches)!=1:raise ValueError("账号不存在")
            user=matches[0]
            try:limit=int(user.get("device_limits",10)) if not isinstance(user.get("device_limits"),bool) else 10
            except (ValueError,TypeError):limit=10
            if limit<=0:limit=10
            devices=copy.deepcopy(user.get("devices",{}))
            if not isinstance(devices,dict):raise ValueError("设备资料结构错误")
            current=next((key for key,value in devices.items() if str(value).split("|")[0]==request["device"]),"")
            stamp=self.timestamp()
            if current:
                pieces=str(devices[current]).split("|");first=pieces[1] if len(pieces)>1 else stamp
            else:
                first=stamp
                if len(devices)>=limit:
                    stale=[]
                    for key,value in devices.items():
                        pieces=str(value).split("|")
                        try:last=datetime.fromisoformat(pieces[-1]).replace(tzinfo=timezone(timedelta(hours=8))).timestamp()
                        except (ValueError,TypeError):continue
                        if self.now()-last>14*86400:stale.append((last,key))
                    if not stale:raise ValueError("DEVICE_LIMIT|当前账号设备数量已达上限，无法在新设备上登录。")
                    current=min(stale)[1]
                else:
                    index=1
                    used={int(match.group(1)) for key in devices if (match:=re.fullmatch(r"device_(\d+)",str(key)))}
                    while index in used:index+=1
                    current=f"device_{index:03d}"
            devices[current]=f"{request['device']}|{first}|{stamp}"
            user["devices"]=devices
            return {"device_hash":request["device"],"device_verified_at":stamp,"device_check_state":"verified","device_remote_verified":True}
        return self.remote.commit_json("github_project_users.json",request["id"]+"device",digest,mutate)
    def verify(self,request,digest):
        payload=request["payload"]
        if set(payload)!={"challenge","code"}:raise ValueError("验证码请求结构错误")
        if not isinstance(payload["challenge"],str) or not isinstance(payload["code"],str) or not re.fullmatch(r"[A-Za-z]{6}",payload["code"]):raise ValueError("验证码格式错误")
        challenge=self.state["challenges"].get(payload.get("challenge"))
        if not challenge or challenge.get("user")!=request["user"] or challenge.get("device")!=request["device"]:raise ValueError("验证码请求不存在或不属于当前设备")
        if not challenge.get("sent") or not 0<=self.now()-challenge["at"]<=600 or challenge.get("tries",0)>=3:raise ValueError("验证码已过期或尝试次数已达上限，请重新发送")
        if challenge.get("used") and challenge.get("verified_request")!=request["id"]:raise ValueError("验证码已使用，请重新发送")
        if not hmac.compare_digest(str(payload.get("code","")).upper(),challenge["code"]):
            challenge["tries"]+=1;self.save();raise ValueError("验证码错误")
        if self.account(request["user"]).get("email")!=challenge["email"]:raise ValueError("账号邮箱已变化，请重新发送")
        if not challenge.get("used"):
            challenge["used"]=True;challenge["verified_request"]=request["id"];challenge["session"]=secrets.token_urlsafe(32);self.save()
        fields=self.enroll_device(request,digest)
        token=challenge["session"]
        self.state["sessions"][hashlib.sha256(token.encode("utf-8")).hexdigest()]={"user":request["user"],"device":request["device"],"email":challenge["email"],"at":self.now()}
        self.save()
        return {"session":token,"device_fields":fields,"user":request["user"]}
    def card(self,request,digest):
        allowed={"账号匿名","公司规模","合作身份","用户性别","手机号码","邮箱号码","所在城市","从业年限","选择主题","合作邀请","交易情报","擅长领域","项目经验","项目预算","合作伙伴","礼品偏好","个人介绍","结算方式","收款账号","提交时间","user_id","show_id"}
        value=request["payload"]
        if request["action"]=="card.save":
            if set(value)-allowed or not value or value.get("账号匿名")!=request["user"]:raise ValueError("名片字段或账号不匹配")
            if any(not isinstance(item,(str,int)) or isinstance(item,bool) or len(str(item))>5000 for item in value.values()):raise ValueError("名片内容无效")
            if str(value.get("show_id","")) not in ("true","false"):raise ValueError("名片展示状态无效")
        elif value:raise ValueError("隐藏名片请求不允许附加字段")
        def mutate(document,ledger):
            username=request["user"]
            if request["action"]=="card.hide":
                if not isinstance(document.get(username),dict):raise ValueError("未找到匹配的用户名片")
                document[username]["show_id"]="false"
            else:
                existing=document.get(username,{})
                data=dict(value)
                if isinstance(existing,dict) and existing.get("user_id"):data["user_id"]=existing["user_id"]
                if any(isinstance(row,dict) and key!=username and row.get("user_id")==data.get("user_id") for key,row in document.items()):raise ValueError("名片编号冲突，请刷新后重试")
                if not data.get("user_id"):raise ValueError("名片编号缺失")
                document[username]=data
            return {"username":username}
        return self.remote.commit_json("github_project_cards.json",request["id"],digest,mutate)
    def create_issue(self,request):
        payload=request["payload"]
        if set(payload)!={"title","body","labels"}:raise ValueError("提交字段无效")
        title,body,labels=payload["title"],payload["body"],payload["labels"]
        if not isinstance(title,str) or not 1<=len(title)<=256 or not isinstance(body,str) or len(body)>22000:raise ValueError("提交内容长度无效")
        if f" - {request['user']} - " not in title:raise ValueError("提交账号不匹配")
        if not isinstance(labels,list) or len(labels)!=2 or labels[1]!="2-等待审核处理" or labels[0] not in self.issue_labels[:2]:raise ValueError("提交类型无效")
        if "<!-- engineering:" in body:raise ValueError("提交内容包含保留标识")
        owner_mark=self.marker("owner",request["user"])
        request_mark=self.marker("request",request["id"])
        data=dict(payload);data["body"]=body+"\n"+owner_mark
        issue=self.remote.create_issue(data,request_mark)
        self.state["legacy_issues"][str(issue["number"])]=request["user"];self.save()
        return {key:issue[key] for key in ("number","title","body","state","html_url","labels") if key in issue}
    def close_issue(self,request):
        if set(request["payload"])!={"number"}:raise ValueError("关闭请求字段无效")
        number=request["payload"].get("number")
        if not isinstance(number,int) or isinstance(number,bool) or number<=0:raise ValueError("Issue编号无效")
        issue=self.remote.request("GET",f"repos/{self.remote.formal}/issues/{number}",accepted=(200,404))
        ownership=self.state["legacy_issues"].get(str(number))
        legacy=ownership==request["user"] if isinstance(ownership,str) else isinstance(ownership,dict) and ownership.get("user")==request["user"]
        if legacy and isinstance(ownership,dict) and issue is not None:legacy=issue.get("id")==ownership.get("id") and issue.get("created_at")==ownership.get("created_at")
        if issue is None:
            if not legacy:raise ValueError("无法确认该记录归属，本地记录已保留")
            return {"number":number,"missing":True}
        if "pull_request" in issue:raise ValueError("不允许操作Pull Request")
        if not legacy and self.marker("owner",request["user"]) not in str(issue.get("body","") or ""):raise ValueError("无权关闭其他用户的记录")
        self.remote.request("PATCH",f"repos/{self.remote.formal}/issues/{number}",{"state":"closed","labels":["已关闭"]})
        return {"number":number,"missing":False}
    def feedback(self,request):
        payload=request["payload"]
        if set(payload)!={"message","time"} or not isinstance(payload["message"],str) or not 5<=len(payload["message"].strip())<=18000:raise ValueError("留言内容无效")
        hour=datetime.fromtimestamp(self.now(),timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H")
        bucket=self.state["feedback_limits"].setdefault(request["user"],{})
        ids=bucket.setdefault(hour,[])
        if request["id"] not in ids:
            if len(ids)>=2:raise ValueError("当前小时留言次数已达上限（2次）")
            ids.append(request["id"]);self.save()
        year=hour[:4]
        issue=self.container("feedback",year)
        body=f"用户：{request['user']} | 时间：{self.timestamp().replace('T',' ')}\n{payload['message']}"
        self.remote.append_comment(issue["number"],body,self.marker("request",request["id"]))
        return {"number":issue["number"]}
    def statistics(self,request,digest):
        payload=request["payload"]
        if set(payload)!={"user","api_source"} or not isinstance(payload["user"],dict):raise ValueError("统计结构错误")
        supplied=payload["user"]
        permitted={"login_count","first_login_time","last_login_time","monthly","last_upload_month","last_upload_time","api_monthly"}
        if set(supplied)-permitted:raise ValueError("统计字段无效")
        source=str(payload["api_source"])
        if not re.fullmatch(r"[a-f0-9]{32}",source):raise ValueError("统计来源无效")
        def counts(raw,api=False):
            if not isinstance(raw,dict) or len(raw)>120:raise ValueError("月度统计结构错误")
            output={}
            for month,value in raw.items():
                if not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])",month):raise ValueError("统计月份无效")
                values=value if api else {"count":value}
                if not isinstance(values,dict) or (api and set(values)!={"requests","failed"}):raise ValueError("API统计字段错误")
                if any(not isinstance(total,int) or isinstance(total,bool) or not 0<=total<=100000000 for total in values.values()):raise ValueError("统计数值无效")
                output[month]=dict(values) if api else value
            return output
        legacy_month=str(supplied.get("last_upload_month","") or "")
        if legacy_month and not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])",legacy_month):raise ValueError("统计迁移月份无效")
        monthly=counts(supplied.get("monthly",{}));api_monthly=counts(supplied.get("api_monthly",{}),True)
        def mutate(document,ledger):
            users=document.setdefault("users",{})
            if not isinstance(users,dict):raise ValueError("远程统计资料错误")
            target=users.setdefault(request["user"],{})
            if not isinstance(target,dict):raise ValueError("远程用户统计资料错误")
            counter_key=hashlib.sha256((request["user"]+"|"+request["device"]+"|"+source).encode("utf-8")).hexdigest()
            previous=ledger.setdefault("counters",{}).setdefault(counter_key,{})
            target_months=target.setdefault("monthly",{})
            current=self.timestamp()[:7]
            for month,total in monthly.items():
                old=int(previous.get(month,0));increment=max(0,total-old)
                already_uploaded=month not in previous and legacy_month==month
                target_months[month]=int(target_months.get(month,0))+increment if (month==current or month in previous) and not already_uploaded else max(int(target_months.get(month,0)),total)
                previous[month]=max(old,total)
            api_sources=target.setdefault("api_sources",{}).setdefault(source,{})
            api_totals=target.setdefault("api_monthly",{})
            for month,values in api_monthly.items():
                old=api_sources.setdefault(month,{"requests":0,"failed":0});total=api_totals.setdefault(month,{"requests":0,"failed":0})
                for field in ("requests","failed"):
                    total[field]=int(total.get(field,0))+max(0,values[field]-int(old.get(field,0)))
                    old[field]=max(int(old.get(field,0)),values[field])
            first=str(supplied.get("first_login_time","") or "")[:32];last=str(supplied.get("last_login_time","") or "")[:32]
            target["first_login_time"]=min([value for value in (str(target.get("first_login_time","") or ""),first) if value],default="")
            target["last_login_time"]=max(str(target.get("last_login_time","") or ""),last)
            target["login_count"]=max(int(target.get("login_count",0)),sum(int(value) for value in target_months.values()))
            target["last_upload_month"]=current;target["last_upload_time"]=self.timestamp().replace("T"," ")
            document["schema_version"]=1;document["total_users"]=len(users);document["last_updated"]=self.timestamp().replace("T"," ")
            return {"month":current}
        return self.remote.commit_json("github_project_stats.json",request["id"],digest,mutate)
    def diagnostic(self,request):
        payload=request["payload"]
        if set(payload)!={"report_id","text","year"} or not isinstance(payload["text"],str) or len(payload["text"])>24000:raise ValueError("诊断内容无效")
        report_id=str(payload["report_id"])
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}",report_id):raise ValueError("诊断编号无效")
        year=str(payload["year"])
        if not re.fullmatch(r"20\d{2}",year):raise ValueError("诊断年份无效")
        issue=self.container("diagnostic",year)
        self.remote.append_comment(issue["number"],payload["text"],self.marker("diagnostic",request["user"]+":"+report_id))
        return {"number":issue["number"]}
    @property
    def issue_labels(self):
        return ("1-情报提交","1-方案提交","2-等待审核处理")
    def container(self,kind,year):
        key=kind+":"+year
        number=self.state.setdefault("containers",{}).get(key)
        if number:
            current=self.remote.request("GET",f"repos/{self.remote.formal}/issues/{int(number)}",accepted=(200,404))
            if current is not None and "pull_request" not in current:return current
        if kind=="feedback":
            title=f"留言建议反馈 - {year}年1月-12月";body=title+"\n用于收集当年留言建议反馈（1月-12月）。";label="4-用户反馈"
        else:
            title=f"程序诊断反馈 - {year}年1月-12月";body="本Issue由应用程序自动创建，用于集中接收当年自动上报或经过用户确认的脱敏诊断报告。每份报告单独作为一条评论保存。";label="5-程序诊断"
        issue=self.remote.create_issue({"title":title,"body":body,"labels":[label]},self.marker("container",key))
        self.state["containers"][key]=int(issue["number"]);self.save()
        return issue
    def prune(self):
        now=self.now()
        self.state["requests"]={key:record for key,record in self.state["requests"].items() if now-float(record.get("at",now))<35*86400}
        self.state["challenges"]={key:record for key,record in self.state["challenges"].items() if now-float(record.get("at",now))<86400}
        self.state["mail_limits"]={user:[stamp for stamp in values if 0<=now-float(stamp)<3600] for user,values in self.state["mail_limits"].items()}
        hour=self.timestamp().replace("T"," ")[:13]
        self.state["feedback_limits"]={user:{key:ids for key,ids in values.items() if key==hour} for user,values in self.state["feedback_limits"].items()}
    def dispatch(self,request,digest):
        action=request["action"]
        if action=="auth.begin":return self.begin(request)
        if action=="auth.verify":return self.verify(request,digest)
        self.identity(request)
        if action=="device.touch":return self.enroll_device(request,digest)
        if action in ("card.save","card.hide"):return self.card(request,digest)
        if action=="issue.create":return self.create_issue(request)
        if action=="issue.close":return self.close_issue(request)
        if action=="feedback.add":return self.feedback(request)
        if action=="stats.merge":return self.statistics(request,digest)
        if action=="diagnostic.add":return self.diagnostic(request)
        raise ValueError("不允许的操作")
    def process(self,issue):
        if not isinstance(issue,dict) or "pull_request" in issue:return False
        request=MainConfigsGateCryptsStore.unwrap(issue.get("body",""),self.private_key)
        self.validate(request,isinstance(request,dict) and str(request.get("id","")) in self.state["requests"])
        request_id=request["id"]
        if issue.get("title")!="ENGREQ1:"+request_id:raise ValueError("请求标题与编号不匹配")
        digest=hashlib.sha256(MainConfigsGateCryptsStore.encode(request)).hexdigest()
        record=self.state["requests"].get(request_id)
        if record and not hmac.compare_digest(record.get("digest",""),digest):raise ValueError("请求编号已被其他内容使用")
        if not record:
            record={"digest":digest,"at":self.now(),"issue":issue["number"]}
            self.state["requests"][request_id]=record;self.save()
        if "response" not in record:
            try:result={"ok":True,"kind":"success","data":self.dispatch(request,digest),"message":"操作完成"}
            except ValueError as validation_error:
                message=str(validation_error)
                kind=message.split("|",1)[0] if "|" in message else "rejected"
                result={"ok":False,"kind":kind,"data":{},"message":message}
            result.update({"id":request_id,"action":request["action"]})
            record["response"]="ENGRES1:"+MainConfigsGateCryptsStore.seal(result,MainConfigsGateCryptsStore.decode(request["reply"]),request_id)
            self.save()
        posted=record.setdefault("posted",[])
        if issue["number"] in posted:return False
        self.remote.result_comment(issue["number"],record["response"])
        posted.append(issue["number"]);self.save()
        return True
    @staticmethod
    def send_mail(recipient,code):
        sender=os.environ["GATEWAY_SMTP_USER"]
        message=MIMEText("感谢您选择我们的服务！祝您使用愉快！\n您的验证码是："+code,"plain","utf-8")
        message["Subject"]="尊敬的用户您好！验证码已发送";message["From"]=sender;message["To"]=recipient
        with smtplib.SMTP_SSL("smtp.qq.com",465,timeout=20,context=ssl.create_default_context()) as smtp:
            smtp.login(sender,os.environ["GATEWAY_SMTP_PASSWORD"])
            smtp.sendmail(sender,[recipient],message.as_string())
    @classmethod
    def main(cls):
        state_key=MainConfigsGateCryptsStore.decode(os.environ["GATEWAY_STATE_KEY"])
        if len(state_key)!=32:raise ValueError("后台状态密钥长度错误")
        writer_token=MainConfigsGateCryptsStore.installation_token(os.environ["GATEWAY_WRITER_APP_ID"],os.environ["GATEWAY_WRITER_INSTALLATION_ID"],os.environ["GATEWAY_WRITER_PRIVATE_KEY"],os.environ["GATEWAY_FORMAL_REPO"])
        remote=MainConfigsGateRemoteStore(os.environ["GATEWAY_FORMAL_REPO"],os.environ["GITHUB_REPOSITORY"],writer_token,os.environ["GITHUB_TOKEN"],state_key)
        try:
            worker=cls(remote,os.environ["GATEWAY_PRIVATE_KEY"],state_key,cls.send_mail)
            with open(os.environ["GITHUB_EVENT_PATH"],encoding="utf-8") as event_stream:event=json.load(event_stream)
            if os.environ.get("GITHUB_EVENT_NAME")=="workflow_dispatch" and event.get("inputs",{}).get("operation")=="check":
                for filename in ("github_project_users.json","github_project_cards.json","github_project_stats.json"):
                    if remote.read_json(filename) is None:raise ValueError("正式仓库资料缺失")
                with smtplib.SMTP_SSL("smtp.qq.com",465,timeout=20,context=ssl.create_default_context()) as smtp:smtp.login(os.environ["GATEWAY_SMTP_USER"],os.environ["GATEWAY_SMTP_PASSWORD"])
                print("Gateway configuration and SMTP authentication verified; no email sent")
                return
            previous_state=MainConfigsGateCryptsStore.encode(worker.state)
            worker.prune()
            if MainConfigsGateCryptsStore.encode(worker.state)!=previous_state:worker.save()
            selected=event.get("issue")
            def candidates():
                if isinstance(selected,dict):yield selected
                for pending in list(worker.state["requests"].values()):
                    if pending.get("issue") and pending["issue"] not in pending.get("posted",[]):
                        issue=remote.request("GET",f"repos/{remote.inbox}/issues/{int(pending['issue'])}",inbox=True,accepted=(200,404))
                        if issue is not None:yield issue
                for issue in remote.pages("issues?state=all&sort=created&direction=desc",True):
                    try:created=datetime.fromisoformat(issue.get("created_at","").replace("Z","+00:00")).timestamp()
                    except (TypeError,ValueError):continue
                    if time.time()-created>86400:break
                    yield issue
            seen=set();processed=0;started=time.monotonic()
            for issue in candidates():
                number=issue.get("number")
                if issue.get("user",{}).get("login")!="bagman-survey-inbox[bot]" or "pull_request" in issue:continue
                if number in seen or not str(issue.get("title","")).startswith("ENGREQ1:"):continue
                seen.add(number)
                request_id=issue["title"][8:]
                if number in worker.state["requests"].get(request_id,{}).get("posted",[]):continue
                try:
                    if worker.process(issue):processed+=1
                except (ValueError,TypeError,KeyError,UnicodeError,RecursionError) as invalid_request:
                    print(f"❌ Rejected request issue {number}: {type(invalid_request).__name__}")
                if processed>=30 or time.monotonic()-started>=480:break
            print(f"Gateway processed {processed} requests")
        finally:
            try:
                with remote.session.delete("https://api.github.com/installation/token",headers={"Authorization":"Bearer "+writer_token,"Accept":"application/vnd.github+json"},timeout=(10,15)) as response:
                    if response.status_code!=204:print(f"❌ Temporary writer token revocation returned HTTP {response.status_code}")
            except requests.RequestException as revoke_error:print(f"❌ Temporary writer token revocation failed: {type(revoke_error).__name__}")
            finally:remote.close()

if __name__=="__main__":
    try:MainConfigsGateWorkerStore.main()
    except (OSError,ValueError,TypeError,KeyError,RuntimeError,requests.RequestException,smtplib.SMTPException) as gateway_error:
        print(f"❌ Gateway failed: {type(gateway_error).__name__}",file=sys.stderr)
        raise SystemExit(1)
