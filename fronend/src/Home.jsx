import React from 'react'
import { useState,useEffect} from 'react'

import axios from 'axios'
import {Link} from 'react-router-dom'

const Home = () => {
  const [auth,setAuth]=useState(false); 
  const [message,setMessage]=useState("")
const [name,setName]=useState('')



axios.defaults.withCredentials=true

  useEffect(()=>{
    axios.get('http://localhost:8081')
    .then(res=>{
       if(res.data.Status==="Success"){
       setName(res.data.name)
        setAuth(true)
  
       }else{
        setAuth(false)
        setMessage(res.data.Error)
       }
    })
    .then(err=>console.log(err))
  },[])

  const handleLogout=()=>{
    axios.get('http://localhost:8081/logout')
    .then(res=>{
     window.location.reload(true)
    }).catch(err=>console.log(err))
  }
  return (
    <div className='container mt-4'>
    {
      auth?
      <div>
        <h3>You are Authorised{name}</h3>
        <button className='btn btn-danger' onClick={handleLogout}>Logout</button>
        </div>
        :
        <div>
          <h3>{message}</h3>
          <h3>Login Now</h3>
          <Link to="/login" className='btn btn-primary'>Login</Link>
        </div>
    }
    
    </div>
  )
}

export default Home