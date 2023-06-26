import cors from 'cors';
import express from 'express'
import bcrypt from 'bcrypt'
import mysql from 'mysql'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser';

const salt=10
const app=express()
app.use(express.json())
app.use(cors({
    origin:["http://localhost:3000"],
    methods:["POST","GET"],
    credentials:true,
}))
app.use(cookieParser())

const db=mysql.createConnection(
    {
        host:"localhost",
        user:"root",
        password:"",
        database:"db"
        
    }
)
 app.post('/register',(req,res)=>{
    const sql="INSERT INTO REGISTER (`name`,`email`,`password`) VALUES (?)";
    bcrypt.hash(req.body.password,salt,(err,hash)=>{
        if(err) return res.json({Error:"Error when hashing"})
        const values=[
            req.body.name,
            req.body.email,
            hash
        ]
        db.query(sql,[values],(err,result)=>{
            if(err) return res.json({Error:"Insert Error in server"})
            return res.json({Status:"Success"})
        })
    })
    
 })

 app.post('/login',(req,res)=>{
    const sql='SELECT * FROM register WHERE email=? ';
    db.query(sql,[req.body.email],(err,data)=>{
        if(err) return res.json({Error:"LOgin Error in server"});
        if(data.length>0){
        bcrypt.compare(req.body.password.toString(),data[0].password,(err,response)=>{
            if(err) return res.json({Error:"Password compare error"})
            if(response){
                const name=data[0].name;
                const token=jwt.sign({name},"jwt-secret-key",{expiresIn:'1d'})
                res.cookie('token',token)
                return res.json({Status:"Success"})

            }else {
                return res.json({Error:"Password does not matched"})
            }
        })
        }else{
            return res.json({Error:"No email existed"}); 
        }
    })
 })
 const verifyUser=(req,res,next)=>{
    const token=req.cookies.token;
    if(!token){
        return res.json({Error:"You are not authenticated"})
    }else {
        jwt.verify(token,"jwt-secret-key",(err,decoded)=>{
            if(err){
                return res.json({Error:"Token is not correct"})
            }else{
                req.name=decoded.name;
                next()
            }
        })
    }
 }
 app.get('/',verifyUser,(req,res)=>{
return res.json({Status:"Success",name:req.name})
 })


app.get('/logout',(req,res)=>{
res.clearCookie('token')
return res.json({Status:"Success"})
 })
app.listen(8081,()=>{
    console.log("Running.. Server")
})