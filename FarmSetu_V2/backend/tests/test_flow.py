import os,tempfile
fd,path=tempfile.mkstemp(suffix='.db');os.close(fd)
os.environ['DATABASE_URL']='sqlite:///'+path
os.environ['JWT_SECRET']='test-only-secret'
from fastapi.testclient import TestClient
from app.main import app,SessionLocal,User,hash_pw

def test_complete_farmer_to_customer_flow():
 with TestClient(app) as c:
  def call(method,url,t=None,**kw):return c.request(method,url,headers={'Authorization':'Bearer '+t} if t else {},**kw)
  farmer=call('POST','/auth/register',json={'name':'Sample Farmer','email':'farmer@example.test','password':'password123','role':'farmer','district':'Siddipet'});assert farmer.status_code==201
  ft=farmer.json()['access_token'];fid=farmer.json()['user']['id']
  assert call('POST','/farmer/products',ft,json={'name':'Rice','category':'rice','price_per_kg':60,'stock_kg':500}).status_code==403
  with SessionLocal() as s:
   admin=User(name='Test Admin',email='admin@example.test',password_hash=hash_pw('password123'),role='admin',approved=True);s.add(admin);s.commit()
  at=call('POST','/auth/login',json={'email':'admin@example.test','password':'password123'}).json()['access_token']
  assert call('POST',f'/admin/farmers/{fid}/approve',at).status_code==200
  p=call('POST','/farmer/products',ft,json={'name':'Rice','category':'rice','price_per_kg':60,'stock_kg':500});assert p.status_code==201
  pid=p.json()['id'];assert call('GET','/products').json()==[]
  assert call('POST',f'/admin/products/{pid}/verify',at).status_code==200
  assert len(call('GET','/products').json())==1
  customer=call('POST','/auth/register',json={'name':'Sample Customer','email':'customer@example.test','password':'password123','role':'customer'});ct=customer.json()['access_token']
  group=call('POST','/groups',ct,json={'name':'Miyapur Buyers','location':'Hyderabad'});assert group.status_code==201,group.text
  gid=group.json()['id'];assert call('POST',f'/groups/{gid}/join',ct).status_code==200
  assert call('POST',f'/groups/{gid}/quotes',ft,json={'product_id':pid,'quantity_kg':100,'total_price':5800}).status_code==201
  order=call('POST','/orders',ct,json={'product_id':pid,'quantity_kg':25,'address':'Miyapur, Hyderabad, Telangana'});assert order.status_code==201,order.text
  oid=order.json()['id'];assert order.json()['total']==1500
  assert call('GET','/products').json()[0]['stock_kg']==475
  assert call('POST','/orders',ct,json={'product_id':pid,'quantity_kg':7,'address':'Miyapur Hyderabad'}).status_code==400
  for status in ['confirmed','packed','dispatched','delivered']:
   advanced=call('POST',f'/orders/{oid}/advance',ft);assert advanced.status_code==200 and advanced.json()['status']==status
   assert call('GET','/orders',ct).json()[0]['status']==status
  assert call('POST',f'/orders/{oid}/advance',ft).status_code==400
