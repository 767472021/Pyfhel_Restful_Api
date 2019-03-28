# -*- coding:utf-8 -*-
from flask import Flask,jsonify,request
from flask_restful import reqparse, abort, Api, Resource
from Pyfhel import Pyfhel, PyPtxt, PyCtxt
from Pyfhel.util import ENCODING_t
import base64,os

# parser = reqparse.RequestParser()
# parser.add_argument('name', type=str)

# def abort_if_not_exist(user_id):
#     if user_id not in todos:
#         abort(404, message="User {} doesn't exist".format(user_id))

app = Flask(__name__)
api = Api(app)

todos = {}

#curl http://localhost:5000/add -d "data=a,b,c,d" -X PUT
# Among them, A is context, B is public key, C is ciphertext 1, D is ciphertext 2, after base64 encoding.
class Fhe(Resource):
    def get(self, func):
        if func == "sum":
            todos[func] = sum_e
        elif func == "sub":
            todos[func] = sub_e
        elif func == "mul":
            todos[func] = mul_e
        return todos

    def put(self, func):
        todos[func] = "1"
        a = request.form['a']
        b = request.form['b']
        c = request.form['c']
        d = request.form['d']
        HE = Pyfhel()
        
        #Import context
        con =base64.b64decode(bytes(a, "utf-8"))
        with open('context.pycon',"wb") as pk_fw:
            pk_fw.write(con)

        HE.restoreContext("context.pycon")
        
        # Import public key
        pk =base64.b64decode(bytes(b, "utf-8"))
        with open('public_k.pypk',"wb") as pk_fw:
            pk_fw.write(pk)
        HE.restorepublicKey("public_k.pypk")

        # Import Ciphertext 1
        c1=base64.b64decode(bytes(c, "utf-8"))
        with open('ctxt.c1',"wb") as c1_fw:
            c1_fw.write(c1)
        ctxt1 = PyCtxt()
        ctxt1.load("ctxt.c1")
        ctxt1._encoding = ENCODING_t.INTEGER


        # Import Ciphertext 2
        c2=base64.b64decode(bytes(d, "utf-8"))
        with open('ctxt.c2',"wb") as c2_fw:
            c2_fw.write(c2)
        ctxt2 = PyCtxt()
        ctxt2.load("ctxt.c2")
        ctxt2._encoding = ENCODING_t.INTEGER

      
        #密文同态运算
        ctxtSum = HE.add(ctxt1, ctxt2, True)      
        ctxtSub = HE.sub(ctxt1, ctxt2, True)
        ctxtMul = HE.multiply(ctxt1, ctxt2, True)
        
      
        #Ciphertext homomorphism operation
        ctxtSum.save("sum")
        ctxtSub.save("sub")
        ctxtMul.save("mul")


        with open("sum", "rb") as f_sum:
            sum_e=str(base64.b64encode(f_sum.read()),"utf-8")
        
        with open("sub", "rb") as f_sub:
            sub_e=str(base64.b64encode(f_sub.read()),"utf-8")

        with open("mul", "rb") as f_mul:
            mul_e=str(base64.b64encode(f_mul.read()),"utf-8")

        if func == "add":
            todos[func] = sum_e
        elif func == "sub":
            todos[func] = sub_e
        elif func == "mul":
            todos[func] = mul_e
        return todos[func]


api.add_resource(Fhe, '/fhe/<string:func>')


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)