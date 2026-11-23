import os, hmac, hashlib, secrets, base64, json, time
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, ForeignKey, DateTime, Text, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker, Session

DATABASE_URL=os.getenv('DATABASE_URL','sqlite:///./farmsetu_dev.db')
if DATABASE_URL.startswith('postgres://'): DATABASE_URL='postgresql://'+DATABASE_URL[11:]
engine=create_engine(DATABASE_URL,connect_args={'check_same_thread':False} if DATABASE_URL.startswith('sqlite') else {},pool_pre_ping=True)
SessionLocal=sessionmaker(bind=engine)
Base=declarative_base()
SECRET=os.getenv('JWT_SECRET','development-only-change-before-deploy')

class User(Base):
 __tablename__='users'
 id=Column(Integer,primary_key=True); email=Column(String(255),unique=True,nullable=False,index=True); password_hash=Column(String(256),nullable=False); role=Column(String(20),nullable=False); name=Column(String(120),nullable=False); phone=Column(String(30)); district=Column(String(120)); approved=Column(Boolean,default=False,nullable=False)
class Product(Base):
 __tablename__='products'
 id=Column(Integer,primary_key=True); farmer_id=Column(Integer,ForeignKey('users.id'),nullable=False); name=Column(String(120),nullable=False); category=Column(String(80),nullable=False); price_per_kg=Column(Float,nullable=False); stock_kg=Column(Integer,nullable=False); verified=Column(Boolean,default=False,nullable=False); description=Column(Text,default='')
class Order(Base):
 __tablename__='orders'
 id=Column(Integer,primary_key=True); customer_id=Column(Integer,ForeignKey('users.id'),nullable=False); farmer_id=Column(Integer,ForeignKey('users.id'),nullable=False); product_id=Column(Integer,ForeignKey('products.id'),nullable=False); quantity_kg=Column(Integer,nullable=False); total=Column(Float,nullable=False); status=Column(String(30),default='placed',nullable=False); address=Column(Text,nullable=False); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))
class Group(Base):
 __tablename__='purchase_groups'
 id=Column(Integer,primary_key=True); owner_id=Column(Integer,ForeignKey('users.id'),nullable=False); name=Column(String(120),nullable=False); location=Column(String(120),nullable=False); description=Column(Text,default='')
class Membership(Base):
 __tablename__='group_memberships'
 id=Column(Integer,primary_key=True); group_id=Column(Integer,ForeignKey('purchase_groups.id'),nullable=False); user_id=Column(Integer,ForeignKey('users.id'),nullable=False); __table_args__=(UniqueConstraint('group_id','user_id'),)
class Quote(Base):
 __tablename__='group_quotes'
 id=Column(Integer,primary_key=True); group_id=Column(Integer,ForeignKey('purchase_groups.id'),nullable=False); farmer_id=Column(Integer,ForeignKey('users.id'),nullable=False); product_id=Column(Integer,ForeignKey('products.id'),nullable=False); quantity_kg=Column(Integer,nullable=False); total_price=Column(Float,nullable=False); status=Column(String(20),default='submitted')

app=FastAPI(title='FarmSetu V2 API',version='0.1.0')
origins=os.getenv('CORS_ORIGINS','http://localhost:5173').split(',')
app.add_middleware(CORSMiddleware,allow_origins=origins,allow_credentials=True,allow_methods=['*'],allow_headers=['*'])
@app.on_event('startup')
def startup(): Base.metadata.create_all(engine)
def db():
 with SessionLocal() as s: yield s

def hash_pw(p):
 salt=secrets.token_bytes(16); return base64.b64encode(salt+hashlib.pbkdf2_hmac('sha256',p.encode(),salt,260000)).decode()
def verify_pw(p,stored):
 try:
  raw=base64.b64decode(stored); return hmac.compare_digest(raw[16:],hashlib.pbkdf2_hmac('sha256',p.encode(),raw[:16],260000))
 except Exception:return False
def token(uid):
 payload=base64.urlsafe_b64encode(json.dumps({'sub':uid,'exp':int(time.time())+86400}).encode()).decode().rstrip('='); sig=hmac.new(SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest(); return payload+'.'+sig
def current(authorization:Optional[str]=Header(None),s:Session=Depends(db)):
 try:
  scheme,t=authorization.split(' ',1); payload,sig=t.split('.',1)
  if scheme.lower()!='bearer' or not hmac.compare_digest(hmac.new(SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest(),sig):raise ValueError()
  data=json.loads(base64.urlsafe_b64decode(payload+'='*(-len(payload)%4)))
  if data['exp']<time.time():raise ValueError()
  user=s.get(User,data['sub'])
  if not user:raise ValueError()
  return user
 except Exception:raise HTTPException(401,'Please sign in')
def require(*roles):
 def dependency(u:User=Depends(current)):
  if u.role not in roles:raise HTTPException(403,'Insufficient permissions')
  return u
 return dependency

def public_user(u):return {'id':u.id,'email':u.email,'name':u.name,'role':u.role,'phone':u.phone,'district':u.district,'approved':u.approved}
def public_product(p):return {'id':p.id,'farmer_id':p.farmer_id,'name':p.name,'category':p.category,'price_per_kg':p.price_per_kg,'stock_kg':p.stock_kg,'verified':p.verified,'description':p.description}
def public_order(o):return {'id':o.id,'customer_id':o.customer_id,'farmer_id':o.farmer_id,'product_id':o.product_id,'quantity_kg':o.quantity_kg,'total':o.total,'status':o.status,'address':o.address,'created_at':o.created_at.isoformat() if o.created_at else None}
class Register(BaseModel):
 name:str=Field(min_length=2,max_length=120); email:str; password:str=Field(min_length=8); role:str; phone:str=''; district:str=''
class Login(BaseModel):email:str;password:str
class Profile(BaseModel):name:str=Field(min_length=2);phone:str='';district:str=''
class ProductIn(BaseModel):name:str;category:str;price_per_kg:float=Field(gt=0);stock_kg:int=Field(ge=0);description:str=''
class OrderIn(BaseModel):product_id:int;quantity_kg:int=Field(gt=0);address:str=Field(min_length=8)
class GroupIn(BaseModel):name:str=Field(min_length=3);location:str=Field(min_length=2);description:str=''
class QuoteIn(BaseModel):product_id:int;quantity_kg:int=Field(gt=0);total_price:float=Field(gt=0)
@app.get('/health')
def health():return {'ok':True}
@app.post('/auth/register',status_code=201)
def register(v:Register,s:Session=Depends(db)):
 if v.role not in ('farmer','customer'):raise HTTPException(400,'Choose farmer or customer')
 if '@' not in v.email:raise HTTPException(422,'Invalid email')
 if s.query(User).filter_by(email=v.email.lower().strip()).first():raise HTTPException(409,'Email already registered')
 u=User(email=v.email.lower().strip(),password_hash=hash_pw(v.password),role=v.role,name=v.name,phone=v.phone,district=v.district,approved=v.role=='customer');s.add(u);s.commit();s.refresh(u)
 return {'access_token':token(u.id),'user':public_user(u)}
@app.post('/auth/login')
def login(v:Login,s:Session=Depends(db)):
 u=s.query(User).filter_by(email=v.email.lower().strip()).first()
 if not u or not verify_pw(v.password,u.password_hash):raise HTTPException(401,'Invalid credentials')
 return {'access_token':token(u.id),'user':public_user(u)}
@app.get('/me')
def me(u:User=Depends(current)):return public_user(u)
@app.patch('/me')
def profile(v:Profile,u:User=Depends(current),s:Session=Depends(db)):
 u.name=v.name;u.phone=v.phone;u.district=v.district;s.commit();return public_user(u)
@app.get('/products')
def products(s:Session=Depends(db)):
 return [public_product(p) for p in s.query(Product).filter_by(verified=True).filter(Product.stock_kg>0).order_by(Product.id.desc()).all()]
@app.get('/farmer/products')
def my_products(u:User=Depends(require('farmer')),s:Session=Depends(db)):
 return [public_product(p) for p in s.query(Product).filter_by(farmer_id=u.id).all()]
@app.post('/farmer/products',status_code=201)
def add_product(v:ProductIn,u:User=Depends(require('farmer')),s:Session=Depends(db)):
 if not u.approved:raise HTTPException(403,'Farmer approval required')
 p=Product(farmer_id=u.id,**v.model_dump(),verified=False);s.add(p);s.commit();s.refresh(p);return public_product(p)
@app.get('/admin/farmers')
def farmers(u:User=Depends(require('admin')),s:Session=Depends(db)):
 return [public_user(x) for x in s.query(User).filter_by(role='farmer').all()]
@app.post('/admin/farmers/{uid}/approve')
def approve_farmer(uid:int,u:User=Depends(require('admin')),s:Session=Depends(db)):
 farmer=s.get(User,uid)
 if not farmer or farmer.role!='farmer':raise HTTPException(404,'Farmer not found')
 farmer.approved=True;s.commit();return public_user(farmer)
@app.get('/admin/products')
def admin_products(u:User=Depends(require('admin')),s:Session=Depends(db)):
 return [public_product(p) for p in s.query(Product).all()]
@app.post('/admin/products/{pid}/verify')
def verify_product(pid:int,u:User=Depends(require('admin')),s:Session=Depends(db)):
 p=s.get(Product,pid)
 if not p:raise HTTPException(404,'Product not found')
 farmer=s.get(User,p.farmer_id)
 if not farmer.approved or p.stock_kg<=0:raise HTTPException(400,'Farmer approval and positive stock required')
 p.verified=True;s.commit();return public_product(p)
@app.post('/orders',status_code=201)
def order(v:OrderIn,u:User=Depends(require('customer')),s:Session=Depends(db)):
 # Lock the row on PostgreSQL to avoid concurrent overselling.
 p=s.query(Product).filter_by(id=v.product_id).with_for_update().first()
 if not p or not p.verified:raise HTTPException(404,'Verified product not found')
 sizes=[25,50,75,100] if p.category.lower()=='rice' else [5,10,15]
 if v.quantity_kg not in sizes:raise HTTPException(400,f'Allowed pack sizes: {sizes}')
 if p.stock_kg<v.quantity_kg:raise HTTPException(409,'Insufficient stock')
 p.stock_kg-=v.quantity_kg
 o=Order(customer_id=u.id,farmer_id=p.farmer_id,product_id=p.id,quantity_kg=v.quantity_kg,total=round(p.price_per_kg*v.quantity_kg,2),address=v.address,status='placed');s.add(o);s.commit();s.refresh(o);return public_order(o)
@app.get('/orders')
def orders(u:User=Depends(current),s:Session=Depends(db)):
 q=s.query(Order)
 if u.role=='customer':q=q.filter_by(customer_id=u.id)
 elif u.role=='farmer':q=q.filter_by(farmer_id=u.id)
 elif u.role!='admin':raise HTTPException(403)
 return [public_order(o) for o in q.order_by(Order.id.desc()).all()]
@app.post('/orders/{oid}/advance')
def advance(oid:int,u:User=Depends(require('farmer')),s:Session=Depends(db)):
 o=s.get(Order,oid)
 if not o or o.farmer_id!=u.id:raise HTTPException(404,'Order not found')
 statuses=['placed','confirmed','packed','dispatched','delivered']
 if o.status not in statuses[:-1]:raise HTTPException(400,'Order cannot advance')
 o.status=statuses[statuses.index(o.status)+1];s.commit();return public_order(o)
@app.get('/groups')
def groups(s:Session=Depends(db)):
 return [{'id':g.id,'name':g.name,'location':g.location,'description':g.description,'members':s.query(Membership).filter_by(group_id=g.id).count()} for g in s.query(Group).all()]
@app.post('/groups',status_code=201)
def create_group(v:GroupIn,u:User=Depends(require('customer')),s:Session=Depends(db)):
 g=Group(owner_id=u.id,**v.model_dump());s.add(g);s.flush();s.add(Membership(group_id=g.id,user_id=u.id));s.commit();return {'id':g.id,'name':g.name,'location':g.location}
@app.post('/groups/{gid}/join')
def join_group(gid:int,u:User=Depends(require('customer')),s:Session=Depends(db)):
 if not s.get(Group,gid):raise HTTPException(404,'Group not found')
 if s.query(Membership).filter_by(group_id=gid,user_id=u.id).first():return {'joined':True}
 s.add(Membership(group_id=gid,user_id=u.id));s.commit();return {'joined':True}
@app.get('/groups/{gid}/quotes')
def quotes(gid:int,s:Session=Depends(db)):
 return [{'id':q.id,'farmer_id':q.farmer_id,'product_id':q.product_id,'quantity_kg':q.quantity_kg,'total_price':q.total_price,'status':q.status} for q in s.query(Quote).filter_by(group_id=gid).all()]
@app.post('/groups/{gid}/quotes',status_code=201)
def submit_quote(gid:int,v:QuoteIn,u:User=Depends(require('farmer')),s:Session=Depends(db)):
 if not u.approved:raise HTTPException(403,'Farmer approval required')
 p=s.get(Product,v.product_id)
 if not s.get(Group,gid) or not p or p.farmer_id!=u.id or not p.verified:raise HTTPException(400,'Invalid group or verified product')
 q=Quote(group_id=gid,farmer_id=u.id,**v.model_dump());s.add(q);s.commit();return {'id':q.id,'status':q.status}
