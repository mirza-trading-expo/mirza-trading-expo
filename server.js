require("dotenv").config();
const express=require("express"), helmet=require("helmet"), rateLimit=require("express-rate-limit");
const bcrypt=require("bcryptjs"), jwt=require("jsonwebtoken"), Database=require("better-sqlite3");
const path=require("path"), crypto=require("crypto");
const app=express(), db=new Database("mte.sqlite");
const PORT=process.env.PORT||3000, SECRET=process.env.JWT_SECRET;
if(!SECRET) { console.error("Set JWT_SECRET in .env"); process.exit(1); }
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"40kb"}));
app.use("/api",rateLimit({windowMs:15*60*1000,limit:180}));
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',vip_until TEXT);
CREATE TABLE IF NOT EXISTS signals(id INTEGER PRIMARY KEY,market TEXT NOT NULL,side TEXT NOT NULL,entry TEXT NOT NULL,targets TEXT NOT NULL,stop TEXT NOT NULL,analysis TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Active',visibility TEXT NOT NULL DEFAULT 'vip',created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,plan TEXT NOT NULL,network TEXT NOT NULL,tx_hash TEXT NOT NULL UNIQUE,proof_note TEXT DEFAULT '',status TEXT NOT NULL DEFAULT 'pending',submitted_at TEXT NOT NULL,reviewed_at TEXT,FOREIGN KEY(user_id) REFERENCES users(id));
`);
const count=db.prepare("SELECT count(*) n FROM users WHERE role='admin'").get().n;
if(!count && process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD && !process.env.ADMIN_PASSWORD.startsWith("replace-")){
 const hash=bcrypt.hashSync(process.env.ADMIN_PASSWORD,12);
 db.prepare("INSERT OR IGNORE INTO users(email,password_hash,role) VALUES(?,?,?)").run(process.env.ADMIN_EMAIL.toLowerCase(),hash,"admin");
}
const safeUser=u=>({id:u.id,email:u.email,role:u.role,vipActive:!!u.vip_until&&new Date(u.vip_until)>new Date(),vipUntil:u.vip_until||null});
function auth(req,res,next){const h=req.headers.authorization||"";try{req.user=jwt.verify(h.replace(/^Bearer\s+/i,""),SECRET);next()}catch{return res.status(401).json({error:"Please sign in"})}}
function admin(req,res,next){if(req.user.role!=="admin")return res.status(403).json({error:"Admin access required"});next()}
function vip(req,res,next){const u=db.prepare("SELECT vip_until FROM users WHERE id=?").get(req.user.id);if(!u?.vip_until||new Date(u.vip_until)<=new Date())return res.status(403).json({error:"Active VIP membership required"});next()}
app.post("/api/register",async(req,res)=>{const email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<10)return res.status(400).json({error:"Use a valid email and password of at least 10 characters"});try{const hash=await bcrypt.hash(password,12),r=db.prepare("INSERT INTO users(email,password_hash) VALUES(?,?)").run(email,hash);const user=db.prepare("SELECT * FROM users WHERE id=?").get(r.lastInsertRowid);res.json({token:jwt.sign({id:user.id,email:user.email,role:user.role},SECRET,{expiresIn:"7d"}),user:safeUser(user)})}catch{res.status(409).json({error:"Email already registered"})}});
app.post("/api/login",async(req,res)=>{const email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");const u=db.prepare("SELECT * FROM users WHERE email=?").get(email);if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:"Invalid email or password"});res.json({token:jwt.sign({id:u.id,email:u.email,role:u.role},SECRET,{expiresIn:"7d"}),user:safeUser(u)})});
app.get("/api/me",auth,(req,res)=>{const u=db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);res.json({user:safeUser(u)})});
app.get("/api/config",(req,res)=>res.json({usdtNetwork:process.env.USDT_NETWORK||"TRC20",walletAddress:process.env.USDT_WALLET_ADDRESS||"Set wallet address in server .env",plans:[{id:"monthly",label:"Monthly VIP",durationDays:30},{id:"yearly",label:"Yearly VIP",durationDays:365}]}));
app.get("/api/signals",(req,res)=>{const rows=db.prepare("SELECT * FROM signals WHERE visibility='public' ORDER BY id DESC LIMIT 100").all();res.json({signals:rows})});
app.get("/api/vip/signals",auth,vip,(req,res)=>res.json({signals:db.prepare("SELECT * FROM signals ORDER BY id DESC LIMIT 200").all()}));
app.post("/api/payments",auth,(req,res)=>{const plan=String(req.body.plan||""),network=String(req.body.network||""),tx=String(req.body.txHash||"").trim(),note=String(req.body.note||"").slice(0,500);if(!["monthly","yearly"].includes(plan)||!tx||tx.length<20||tx.length>160)return res.status(400).json({error:"Choose a plan and provide a valid transaction hash"});try{db.prepare("INSERT INTO payments(user_id,plan,network,tx_hash,proof_note,submitted_at) VALUES(?,?,?,?,?,?)").run(req.user.id,plan,network,tx,note,new Date().toISOString());res.json({message:"Submitted for manual review. VIP access starts only after admin verification."})}catch{res.status(409).json({error:"That transaction hash has already been submitted"})}});
app.get("/api/payments/mine",auth,(req,res)=>res.json({payments:db.prepare("SELECT plan,network,tx_hash,status,submitted_at,reviewed_at FROM payments WHERE user_id=? ORDER BY id DESC").all(req.user.id)}));
app.get("/api/admin/payments",auth,admin,(req,res)=>res.json({payments:db.prepare("SELECT p.*,u.email FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC").all()}));
app.post("/api/admin/payments/:id/approve",auth,admin,(req,res)=>{const p=db.prepare("SELECT * FROM payments WHERE id=? AND status='pending'").get(req.params.id);if(!p)return res.status(404).json({error:"Pending payment not found"});const days=p.plan==="yearly"?365:30;const u=db.prepare("SELECT vip_until FROM users WHERE id=?").get(p.user_id);const now=new Date(),current=u.vip_until&&new Date(u.vip_until)>now?new Date(u.vip_until):now;current.setDate(current.getDate()+days);const until=current.toISOString();db.transaction(()=>{db.prepare("UPDATE payments SET status='approved',reviewed_at=? WHERE id=?").run(now.toISOString(),p.id);db.prepare("UPDATE users SET vip_until=? WHERE id=?").run(until,p.user_id)})();res.json({message:"Payment marked approved; VIP access activated",vipUntil:until})});
app.post("/api/admin/payments/:id/reject",auth,admin,(req,res)=>{const r=db.prepare("UPDATE payments SET status='rejected',reviewed_at=? WHERE id=? AND status='pending'").run(new Date().toISOString(),req.params.id);res.json({updated:r.changes})});
app.post("/api/admin/signals",auth,admin,(req,res)=>{const b=req.body;if(!b.market||!["LONG","SHORT","SPOT"].includes(b.side)||!b.entry||!b.stop||!b.analysis||!["public","vip"].includes(b.visibility))return res.status(400).json({error:"Complete required signal fields"});const r=db.prepare("INSERT INTO signals(market,side,entry,targets,stop,analysis,status,visibility,created_at) VALUES(?,?,?,?,?,?,?,?,?)").run(String(b.market).slice(0,30),b.side,String(b.entry).slice(0,80),JSON.stringify(Array.isArray(b.targets)?b.targets.slice(0,5):[]),String(b.stop).slice(0,80),String(b.analysis).slice(0,2000),String(b.status||"Active").slice(0,30),b.visibility,new Date().toISOString());res.json({id:r.lastInsertRowid})});
app.patch("/api/admin/signals/:id",auth,admin,(req,res)=>{const allowed=["status","visibility","analysis"];const fields=allowed.filter(k=>req.body[k]!==undefined);if(!fields.length)return res.status(400).json({error:"No supported fields"});const vals=fields.map(k=>String(req.body[k]).slice(0,k==="analysis"?2000:40));db.prepare(`UPDATE signals SET ${fields.map(k=>k+"=?").join(",")} WHERE id=?`).run(...vals,req.params.id);res.json({updated:true})});
app.get("/api/admin/users",auth,admin,(req,res)=>res.json({users:db.prepare("SELECT id,email,role,vip_until FROM users ORDER BY id DESC LIMIT 500").all()}));
app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Mirza Trading Expo running on http://localhost:${PORT}`));
