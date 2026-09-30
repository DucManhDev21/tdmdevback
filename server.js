const express=require('express');
const cors=require('cors');
const dotenv=require('dotenv');
const nodemailer=require('nodemailer');
const multer=require('multer');
const axios=require('axios');
const crypto=require('crypto');

dotenv.config();
const app=express();
const port=Number.parseInt(process.env.PORT||'5000',10);
const origins=String(process.env.CORS_ORIGINS||'*').split(',').map(s=>s.trim()).filter(Boolean);
app.use(cors({origin:(origin,cb)=>{if(!origin||origins.includes('*')||origins.includes(origin))return cb(null,true);return cb(new Error('CORS origin not allowed'));},methods:['GET','POST','OPTIONS'],allowedHeaders:['Content-Type','Accept','Authorization'],maxAge:86400}));
app.use(express.json({limit:'1mb'}));
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:(Number.parseInt(process.env.MAX_ATTACHMENT_MB||'10',10)||10)*1024*1024,files:1}});
const adminConfig={tools:{link4m:true,tempmail:true,sendmail:true},banner:'',updatedAt:null};
const requestCounters=new Map();
function now(){return new Date().toISOString();}
function err(res,status,message,code='ERROR',extra={}){return res.status(status).json({success:false,code,message,...extra});}
function validUrl(value){try{const u=new URL(value);return['http:','https:'].includes(u.protocol);}catch{return false;}}
function limit(key,max,window=60000){const t=Date.now();const s=requestCounters.get(key);if(!s||t-s.at>=window){requestCounters.set(key,{at:t,count:1});return true;}if(s.count>=max)return false;s.count++;return true;}
function clientKey(req){return String(req.ip||req.headers['x-forwarded-for']||'unknown').split(',')[0].trim();}
function equalToken(a,b){const x=Buffer.from(String(a||''));const y=Buffer.from(String(b||''));return x.length===y.length&&x.length>0&&crypto.timingSafeEqual(x,y);}
function requireAdmin(req,res,next){const expected=String(process.env.ADMIN_TOKEN||'').trim();const auth=String(req.get('authorization')||'');const actual=auth.toLowerCase().startsWith('bearer ')?auth.slice(7).trim():String(req.body?.token||'').trim();if(!equalToken(actual,expected))return err(res,401,'Admin token không hợp lệ.','UNAUTHORIZED');next();}
function extractShortUrl(data){if(typeof data==='string'){const text=data.trim();const match=text.match(/https?:\/\/[^\s"'<>]+/i);if(match)return match[0];try{return extractShortUrl(JSON.parse(text));}catch{return null;}}const candidates=[data?.shortenedUrl,data?.shortUrl,data?.shortened_url,data?.shorturl,data?.url,data?.data?.shortenedUrl,data?.data?.shortUrl,data?.data?.shorturl,data?.data?.url,data?.result?.shortenedUrl,data?.result?.shortUrl,data?.result?.shorturl,data?.result?.url];return candidates.find(v=>typeof v==='string'&&validUrl(v))||null;}

app.get('/health',(_req,res)=>res.json({success:true,service:'tdmdev-backend',status:'ok',time:now()}));
app.get('/api/config/public',(_req,res)=>res.json({success:true,...adminConfig}));

// Link4M: user supplies both API key and destination URL.
app.post('/api/link4m/shorten',async(req,res)=>{if(adminConfig.tools.link4m===false)return err(res,503,'Công cụ Link4M đang tạm tắt.','TOOL_DISABLED');if(!limit(`link4m:${clientKey(req)}`,30))return err(res,429,'Quá nhiều yêu cầu Link4M.','RATE_LIMITED');const apiKey=String(req.body?.apiKey||'').trim();const destination=String(req.body?.url||'').trim();if(!apiKey||!validUrl(destination))return err(res,400,'API Key và URL đích là bắt buộc; URL phải là HTTP/HTTPS.','VALIDATION_ERROR');const endpoint='https://link4m.co/api-shorten/v2';try{const response=await axios.get(endpoint,{params:{api:apiKey,url:destination},timeout:20000,headers:{Accept:'*/*','User-Agent':'TDM-Dev/3.0'}});const shortUrl=extractShortUrl(response.data);if(!shortUrl)return err(res,502,'Link4M không trả về URL rút gọn mà TDM Dev có thể nhận diện.','PROVIDER_RESPONSE',{providerResponse:response.data});return res.json({success:true,shortUrl,providerResponse:response.data});}catch(error){const provider=error.response?.data;return err(res,502,`Link4M lỗi: ${provider?.message||provider?.error||error.message}`,'PROVIDER_ERROR',{status:error.response?.status||null});}});

function transporter(){const user=String(process.env.GMAIL_USER||'').trim();const pass=String(process.env.GMAIL_APP_PASS||'').trim();if(!user||!pass||user==='your_gmail@gmail.com'||pass==='your_16_digit_app_password')throw new Error('GMAIL_USER hoặc GMAIL_APP_PASS chưa được cấu hình trên Railway.');return{user,transport:nodemailer.createTransport({service:'gmail',auth:{user,pass},connectionTimeout:20000,greetingTimeout:20000,socketTimeout:30000})};}
app.post('/api/sendmail',upload.single('attachment'),async(req,res)=>{if(adminConfig.tools.sendmail===false)return err(res,503,'Công cụ SendMail đang tạm tắt.','TOOL_DISABLED');if(!limit(`sendmail:${clientKey(req)}`,20))return err(res,429,'Đã vượt giới hạn gửi email tạm thời.','RATE_LIMITED');const toEmail=String(req.body?.toEmail||'').trim();const subject=String(req.body?.subject||'').trim();const body=String(req.body?.body||'');const isHtml=String(req.body?.isHtml||'false')==='true';if(!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(toEmail))return err(res,400,'Email nhận không hợp lệ.','VALIDATION_ERROR');if(!subject||!body.trim())return err(res,400,'Tiêu đề và nội dung không được để trống.','VALIDATION_ERROR');try{const {user,transport}=transporter();const options={from:user,to:toEmail,subject,...(isHtml?{html:body}:{text:body})};if(req.file)options.attachments=[{filename:req.file.originalname,content:req.file.buffer,contentType:req.file.mimetype}];const info=await transport.sendMail(options);return res.json({success:true,message:'Gửi thành công',messageId:info.messageId,accepted:info.accepted,rejected:info.rejected,from:user});}catch(error){return err(res,502,`Gửi email thất bại: ${error.message}`,'SMTP_ERROR');}});

app.post('/api/admin/login',(req,res)=>{const expected=String(process.env.ADMIN_TOKEN||'').trim();if(!equalToken(String(req.body?.token||'').trim(),expected))return err(res,401,'Admin token không hợp lệ.','UNAUTHORIZED');return res.json({success:true,message:'Đăng nhập thành công'});});
app.get('/api/admin/config',requireAdmin,(_req,res)=>res.json({success:true,...adminConfig}));
app.post('/api/admin/config',requireAdmin,(req,res)=>{const tools=req.body?.tools;if(tools&&typeof tools==='object'){for(const key of Object.keys(adminConfig.tools))if(typeof tools[key]==='boolean')adminConfig.tools[key]=tools[key];}if(typeof req.body?.banner==='string')adminConfig.banner=req.body.banner.slice(0,500);adminConfig.updatedAt=now();return res.json({success:true,...adminConfig});});
app.use((error,_req,res,next)=>{if(res.headersSent)return next(error);if(error instanceof multer.MulterError)return err(res,413,`Upload lỗi: ${error.message}`,'UPLOAD_ERROR');if(error.message==='CORS origin not allowed')return err(res,403,'Origin không được phép bởi CORS.','CORS_ERROR');console.error(error);return err(res,500,'Internal server error.','INTERNAL_ERROR');});
app.use((_req,res)=>res.status(404).json({success:false,code:'NOT_FOUND',message:'API endpoint not found.'}));
app.listen(port,()=>console.log(`TDM Dev backend listening on ${port}`));
