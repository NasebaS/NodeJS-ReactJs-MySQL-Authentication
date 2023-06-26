import React from 'react';
import { useState } from 'react';
import './App.css';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Form, Input, Button } from 'reactstrap';

function Register() {
  const [values, setValues] = useState({
    name: '',
    email: '',
    password: '',
  });
const navigate=useNavigate()
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    await axios.post("http://localhost:8081/register", values)
     .then(res=>{
        if(res.data.Status==="Success"){
            navigate("/login")
        }else{
         alert("Error")   
        }
     })
     .then(err=>console.log(err))
    
  } 
   const handleChange = (e) => {
    setValues({ ...values, [e.target.name]: e.target.value });
  };

  return (
    <div className='App bg-primary'>
      <div className='register bg-white p-3 rounded w-25'>
        <Form inline onSubmit={handleSubmit} className='form'>
          <h3>Register Page</h3>

          <Input type="text" name="name" label="Name" className="mr-3" onChange={handleChange} />
          <Input type="email" name="email" label="Email" onChange={handleChange} />
          <Input type="password" name="password" label="Password" onChange={handleChange} />

          <Button type="submit" color="success" className="font-weight-bold">SignUp</Button>
          <Link to="/login">LOGIN</Link>
        </Form>
      </div>
    </div>
  );
}

export default Register;