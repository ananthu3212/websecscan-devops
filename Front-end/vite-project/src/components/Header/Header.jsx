import React from 'react';
import { Link, useNavigate, Outlet } from 'react-router-dom';
import LogIn from './LogIn';
import { useAuth } from "../../context/authProvider.jsx";
import { endUserSession } from '../../api/authApiService.jsx';
import './Header.css';
import { useState } from 'react';

/**
 * This Lamda Function Creates the Header Object with all the Links
 * to Subsites and the Login and Logout Button.
 * 
 * @returns The Header Object for the Application
 */
const Header = () => {
  const [showLogIn, setLogInShow] = useState(false);
  const { logIn, setUser } = useAuth();
  const navigate = useNavigate();

  const toggleForm = () => {
		setLogInShow(!showLogIn);
	};

  const handleLogOut = () => {
    endUserSession(logIn);
    setUser();
    navigate("/", { replace: true });
    alert("Log Out Successful");	
  
  }

  return (
    <div>
      <header className="header">
  
        {/* Logo Section */}
        <div className="logo-section">
          <div className="logo">
            <img src="/SECUNET.png" alt="SECUNET Logo" className="logo-image" />
          </div>
        </div>
        
             
  
        {/* Navigation */}
        <div className="nav-section">
          <Link to="/" className="nav-link home-page">Home Page</Link>
          <Link to="/about" className="nav-link about-us">About Us</Link>
          <Link to="/history" className="nav-link history">History</Link>
          <Link to="/delta" className="nav-link delta">Delta Scan</Link> {/* Added */}
          <Link to="/profile" className="nav-link">My Profile</Link>
        </div>
  
        {/* Logout */}
        <div className="logout-section">
          {logIn 
                ? <button className='login-button' onClick={handleLogOut} type='submit'>Abmelden</button> 
                : <button onClick={toggleForm} className='login-button'>Anmelden</button>}
        </div>
  
        {showLogIn && <LogIn showLogIn={toggleForm} />}
      </header>
      <Outlet />
    </div>
  );
};

export default Header;
