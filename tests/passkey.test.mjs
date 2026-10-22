import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createHash, generateKeyPairSync, sign, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { handlePasskey } from '../lib/passkey.ts';
const ORIGIN='https://yc-aleph-08-passkey.ksyji123.chatgpt.site';
const sql=new DatabaseSync(':memory:');
for(const file of readdirSync(new URL('../drizzle/',import.meta.url)).filter(f=>f.endsWith('.sql')).sort())sql.exec(readFileSync(new URL('../drizzle/'+file,import.meta.url),'utf8'));
class Statement{constructor(q){this.q=q;this.values=[];}bind(...values){this.values=values;return this;}async first(){return sql.prepare(this.q).get(...this.values)||null;}async all(){return {results:sql.prepare(this.q).all(...this.values)};}async run(){const r=sql.prepare(this.q).run(...this.values);return {success:true,meta:{changes:r.changes}};}}
const db={prepare:q=>new Statement(q),async batch(stmts){sql.exec('BEGIN');try{const out=[];for(const s of stmts)out.push(await s.run());sql.exec('COMMIT');return out;}catch(e){sql.exec('ROLLBACK');throw e;}}};
const b64=b=>Buffer.from(b).toString('base64url');
function head(t,n){if(n<24)return Buffer.from([(t<<5)|n]);if(n<256)return Buffer.from([(t<<5)|24,n]);const b=Buffer.alloc(3);b[0]=(t<<5)|25;b.writeUInt16BE(n,1);return b;}
function cbor(x){if(typeof x==='number')return head(x>=0?0:1,x>=0?x:-1-x);if(typeof x==='string'){const b=Buffer.from(x);return Buffer.concat([head(3,b.length),b]);}if(Buffer.isBuffer(x)||x instanceof Uint8Array)return Buffer.concat([head(2,x.length),Buffer.from(x)]);const pairs=x instanceof Map?[...x]:Object.entries(x);return Buffer.concat([head(5,pairs.length),...pairs.flatMap(([k,v])=>[cbor(k),cbor(v)])]);}
function device(){const {publicKey,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});return {id:b64(randomBytes(32)),privateKey,jwk:publicKey.export({format:'jwk'}),counter:0};}
function client(type,challenge,origin=ORIGIN){return Buffer.from(JSON.stringify({type,challenge,origin,crossOrigin:false}));}
const rpHash=createHash('sha256').update(new URL(ORIGIN).hostname).digest();
function authData(d,registration=false){const ctr=Buffer.alloc(4);ctr.writeUInt32BE(d.counter);const base=Buffer.concat([rpHash,Buffer.from([registration?0x45:0x05]),ctr]);if(!registration)return base;const id=Buffer.from(d.id,'base64url'),len=Buffer.alloc(2);len.writeUInt16BE(id.length);const key=cbor(new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(d.jwk.x,'base64url')],[-3,Buffer.from(d.jwk.y,'base64url')]]));return Buffer.concat([base,Buffer.alloc(16),len,id,key]);}
function registration(d,q){const cd=client('webauthn.create',q.options.challenge);d.owner=q.options.user.id;return {id:d.id,rawId:d.id,type:'public-key',response:{clientDataJSON:b64(cd),attestationObject:b64(cbor({fmt:'none',attStmt:{},authData:authData(d,true)})),transports:['internal']},clientExtensionResults:{credProps:{rk:true}},authenticatorAttachment:'platform'};}
function authentication(d,q,options={}){d.counter++;const cd=client('webauthn.get',options.challenge||q.options.challenge,options.origin||ORIGIN);const ad=authData(d);return {id:d.id,rawId:d.id,type:'public-key',response:{clientDataJSON:b64(cd),authenticatorData:b64(ad),signature:options.bad?'AAAA':b64(sign('sha256',Buffer.concat([ad,createHash('sha256').update(cd).digest()]),d.privateKey)),userHandle:d.owner},clientExtensionResults:{},authenticatorAttachment:'platform'};}
const cases=[],records=[];
function clean(v){if(Array.isArray(v))return v.map(clean);if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,val])=>[k,/ticket|cookie|token/i.test(k)?'[REDACTED]':k==='items'?{count:val.length,ids:val.map(x=>x.id)}:clean(val)]));return v;}
class Browser{constructor(name){this.name=name;this.jar=new Map();}async request(path,method='GET',body={},opts={}){const headers={cookie:[...this.jar].map(([k,v])=>`${k}=${v}`).join('; '),origin:opts.origin||ORIGIN,'content-type':'application/json'};const res=await handlePasskey(new Request(ORIGIN+path,{method,headers,body:method==='GET'?undefined:JSON.stringify(body)}),db,ORIGIN);const data=await res.json();if(opts.saveCookie!==false)for(const v of res.headers.getSetCookie()){const [entry]=v.split(';');const ix=entry.indexOf('=');this.jar.set(entry.slice(0,ix),entry.slice(ix+1));}records.push({browser:this.name,method,path,request:clean(body),status:res.status,response:clean(data)});return {status:res.status,data};}}
function check(name,fn){fn();cases.push({name,status:'PASS'});}
async function reg(b,d,name){const q=await b.request('/api/auth/register/options','POST',{name,provider:'기기 자체'});assert.equal(q.status,200);const r=await b.request('/api/auth/register/verify','POST',{ticket:q.data.ticket,response:registration(d,q.data)});assert.equal(r.status,200,JSON.stringify(r));return {q:q.data,r:r.data};}
async function login(b,d,opts={}){const q=await b.request('/api/auth/login/options','POST');const body={ticket:q.data.ticket,response:authentication(d,q.data,opts)};const r=await b.request('/api/auth/login/verify','POST',body);return {q:q.data,body,r};}
const A=new Browser('A'),B=new Browser('B'),anon=new Browser('anonymous'),a1=device(),a2=device(),b1=device();
let r=await anon.request('/api/private');check('로그인 없는 직접 자료 요청 401',()=>assert.equal(r.status,401));
const cancelled=await anon.request('/api/auth/register/options','POST',{name:'취소 시험',provider:'기기 자체'});await anon.request('/api/auth/cancel','POST',{ticket:cancelled.data.ticket});check('등록 취소 시 계정·공개키 저장 없음',()=>{assert.equal(sql.prepare('SELECT COUNT(*) n FROM credentials').get().n,0);assert.equal(sql.prepare('SELECT COUNT(*) n FROM accounts').get().n,0);});
const ra=await reg(A,a1,'A 노트북'),ra2=await reg(A,a2,'A 예비 키'),rb=await reg(B,b1,'B 시험 키');
check('A의 패스키 두 개, B 별도 계정 등록',()=>{assert.equal(ra.r.accountId,ra2.r.accountId);assert.notEqual(ra.r.accountId,rb.r.accountId);assert.equal(sql.prepare('SELECT COUNT(*) n FROM credentials WHERE owner=?').get(a1.owner).n,2);});
check('등록 challenge 서로 다름',()=>assert.notEqual(ra.q.options.challenge,ra2.q.options.challenge));
const stored=sql.prepare('SELECT * FROM credentials WHERE id=?').get(a1.id);
check('서버 저장 값은 COSE 공개키, 개인키와 비밀번호 없음',()=>{assert.ok(stored.public_key);assert.equal(bytesPublicKeyType(stored.public_key),0xa5);assert.ok(!JSON.stringify(stored).includes('PRIVATE KEY'));assert.ok(!Object.keys(stored).some(k=>/password|private/i.test(k)));});
function bytesPublicKeyType(v){return Buffer.from(v,'base64url')[0];}
const ownA=await A.request('/api/private'),ownB=await B.request('/api/private');
check('계정마다 서로 다른 가상 자료 3개',()=>{assert.equal(ownA.data.items.length,3);assert.equal(ownB.data.items.length,3);assert.notEqual(ownA.data.items[0].content,ownB.data.items[0].content);});
const crossA=await A.request('/api/private?accountId='+b1.owner),crossB=await B.request('/api/private?accountId='+a1.owner);
check('A → B, B → A 모두 403',()=>{assert.equal(crossA.status,403);assert.equal(crossB.status,403);});
const afterA=await A.request('/api/private'),afterB=await B.request('/api/private');
check('거절 전후 양쪽 자료 건수·내용 변화 없음',()=>{assert.deepEqual(afterA.data,ownA.data);assert.deepEqual(afterB.data,ownB.data);});
const forged=await A.request('/api/private','POST',{accountId:b1.owner});
check('본문 계정 위조 시 세션 소유자 자료만 반환',()=>assert.deepEqual(forged.data,ownA.data));
r=await A.request('/api/passkeys','DELETE',{id:b1.id});check('타인 패스키 삭제 403',()=>assert.equal(r.status,403));
const stolenTicket=await A.request('/api/auth/login/options','POST');r=await B.request('/api/auth/login/verify','POST',{ticket:stolenTicket.data.ticket,response:authentication(a1,stolenTicket.data)});check('다른 브라우저가 가져간 challenge 403',()=>assert.equal(r.status,403));
const oldSession=A.jar.get('__Host-t08_session');r=await A.request('/api/auth/logout','POST');check('로그아웃 성공',()=>assert.equal(r.status,200));const revoked=new Browser('revoked session');revoked.jar.set('__Host-t08_session',oldSession);r=await revoked.request('/api/private');check('로그아웃 전 동일 세션 값 재사용 401',()=>assert.equal(r.status,401));
const ok=await login(A,a1);check('진짜 P-256 서명 확인 후 로그인 200',()=>assert.equal(ok.r.status,200));
r=await A.request('/api/auth/login/verify','POST',ok.body);check('이미 쓴 질문 동일 요청 재사용 403',()=>{assert.equal(r.status,403);assert.equal(r.data.error,'challenge_used_or_unknown');});
const bad=await login(A,a1,{bad:true});check('변조된 서명 403',()=>assert.equal(bad.r.status,403));check('로그인 질문 매번 다름',()=>assert.notEqual(ok.q.options.challenge,bad.q.options.challenge));
const wrongOrigin=await login(A,a1,{origin:'https://attacker.example'});check('다른 Origin 서명 403',()=>assert.equal(wrongOrigin.r.status,403));
const wrongChallenge=await login(A,a1,{challenge:b64(randomBytes(32))});check('질문이 다른 유효한 서명 403',()=>assert.equal(wrongChallenge.r.status,403));
r=await A.request('/api/auth/logout','POST',{}, {origin:'https://attacker.example'});check('교차 Origin 상태 변경 요청 403',()=>assert.equal(r.status,403));
const expired=await A.request('/api/auth/login/options','POST');sql.prepare('UPDATE challenges SET expires_at=0 WHERE id=?').run(expired.data.ticket);r=await A.request('/api/auth/login/verify','POST',{ticket:expired.data.ticket,response:authentication(a1,expired.data)});check('만료된 질문 403',()=>{assert.equal(r.status,403);assert.equal(r.data.error,'challenge_expired');});
r=await A.request('/api/passkeys');check('패스키 이름·등록일·공개키 목록 제공',()=>{assert.equal(r.data.items.length,2);assert.ok(r.data.items.every(k=>k.name&&k.created_at&&k.public_key));});
r=await A.request('/api/passkeys','DELETE',{id:a1.id});check('두 개 중 하나 삭제 성공',()=>{assert.equal(r.status,200);assert.equal(r.data.remaining,1);});await A.request('/api/auth/logout','POST');const deleted=await login(A,a1);check('삭제한 패스키로 로그인 403',()=>{assert.equal(deleted.r.status,403);assert.equal(deleted.r.data.error,'passkey_unknown_or_deleted');});const remaining=await login(A,a2);check('남은 예비 패스키로 로그인 200',()=>assert.equal(remaining.r.status,200));
const zeroSession=A.jar.get('__Host-t08_session');r=await A.request('/api/passkeys','DELETE',{id:a2.id});check('마지막 패스키 삭제 시 복구 불가 안내와 세션 폐기',()=>{assert.equal(r.data.remaining,0);assert.equal(r.data.lockedOut,true);assert.ok(r.data.message.includes('복구'));});const zero=new Browser('last-key session');zero.jar.set('__Host-t08_session',zeroSession);r=await zero.request('/api/private');check('마지막 삭제 후 기존 세션도 401',()=>assert.equal(r.status,401));
const zeroLogin=await login(A,a2);check('마지막 패스키 삭제 뒤 재로그인 403',()=>assert.equal(zeroLogin.r.status,403));
const repeat=await anon.request('/api/auth/register/verify','POST',{ticket:ra.q.ticket,response:registration(a1,ra.q)});check('등록 질문 재사용 403',()=>assert.equal(repeat.status,403));
const html=readFileSync(new URL('../app/page.tsx',import.meta.url),'utf8')+readFileSync(new URL('../app/private-space.tsx',import.meta.url),'utf8')+readFileSync(new URL('../public/original/index.html',import.meta.url),'utf8');
check('공개 화면·클라이언트 소스에 가상 비공개 본문 미포함',()=>{assert.ok(!html.includes('가상 실습 '));assert.ok(!html.includes('가상 기업 '));assert.ok(!html.includes('가상 회고 '));assert.ok(!/type=["']password/.test(html));});
const result={assignment:'ALEPH_08',environment:'Node.js + SQLite adapter, 실제 SimpleWebAuthn 검증기 및 P-256 소프트웨어 인증기',deviceTest:'NOT_RUN: 실제 영찬님 기기의 패스키 창과 저장 위치, 두 기기 등록은 별도 확인 필요',summary:{passed:cases.length,failed:0},cases,storedPublicKey:{...stored,counter:0},dataCounts:{before:{A:3,B:3},after:{A:3,B:3}},records};
writeFileSync(new URL('../docs/automated-evidence.json',import.meta.url),JSON.stringify(result,null,2)+'\n');
console.log(`${cases.length}개 검사 통과. 실제 기기 검사: NOT_RUN`);
