# -*- coding:utf-8 -*-
from Pyfhel import Pyfhel, PyPtxt, PyCtxt
from Pyfhel.util import ENCODING_t
from requests import put, get
import base64,os

HE = Pyfhel()           # Creating empty Pyfhel object


#************************************
#Generate test files, run load for the first time
HE.contextGen(p=65537)
HE.keyGen()

HE.saveContext("context.pycon")
HE.savepublicKey("public_k.pypk")
HE.savesecretKey("secret_k.pysk")

integer1 = 20
integer2 = 68
ctxtx = HE.encryptInt(integer1)
ctxty = HE.encryptInt(integer2)
ctxtx.save("ctxt.c1")
ctxty.save("ctxt.c2")
#************************************

with open("context.pycon", "rb") as con_f:
    a = con_f.read() + b"="
    context_b64e = str(base64.b64encode(a),"utf-8")

with open("public_k.pypk", "rb") as pk_f:
    b = pk_f.read() + b"="
    public_b64e = str(base64.b64encode(b),"utf-8")

with open("ctxt.c1", "rb") as c1_f:
    c = c1_f.read() + b"="
    ctxt1_b64e=str(base64.b64encode(c),"utf-8")

with open("ctxt.c2", "rb") as c2_f:
    d = c2_f.read() + b"="
    ctxt2_b64e=str(base64.b64encode(d),"utf-8")

# os.remove("context.pycon")
# os.remove("public_k.pypk")
# os.remove("secret_k.pysk")


sum_e = put('http://localhost:5000/fhe/add', data={"a": context_b64e, 'b': public_b64e, "c": ctxt1_b64e, "d": ctxt2_b64e}).json()
sub_e = put('http://localhost:5000/fhe/sub', data={"a": context_b64e, 'b': public_b64e, "c": ctxt1_b64e, "d": ctxt2_b64e}).json()
mul_e = put('http://localhost:5000/fhe/mul', data={"a": context_b64e, 'b': public_b64e, "c": ctxt1_b64e, "d": ctxt2_b64e}).json()

#Assuming that ciphertext is received, verify reliability

sum_d = base64.b64decode(bytes(sum_e, "utf-8"))
sub_d = base64.b64decode(bytes(sub_e, "utf-8"))
mul_d = base64.b64decode(bytes(mul_e, "utf-8"))

with open("txt.c1", "wb") as t1_f:
    t1_f.write(sum_d)

with open("txt.c2", "wb") as t2_f:
    t2_f.write(sub_d)

with open("txt.c3", "wb") as t3_f:
    t3_f.write(mul_d)

sum = PyCtxt()
sum.load("txt.c1")
sum._encoding = ENCODING_t.INTEGER

sub = PyCtxt()
sub.load("txt.c2")
sub._encoding = ENCODING_t.INTEGER

mul = PyCtxt()
mul.load("txt.c3")
mul._encoding = ENCODING_t.INTEGER

HE.restoresecretKey("secret_k.pysk")
print(" addition:       decrypt(ctxt1 + ctxt2) =  ", HE.decryptInt(sum))
print(" substraction:   decrypt(ctxt1 - ctxt2) =  ", HE.decryptInt(sub))
print(" multiplication: decrypt(ctxt1 * ctxt2) =  ", HE.decryptInt(mul))