import React, { useState } from 'react';
import {startUserSession, endUserSession, createNewUser, getFormData, forgotPassword} from '../../api/authApiService.jsx'
import { useAuth } from "../../context/authProvider.jsx";
import './Header.css'




/**
 * The Log In and Sign In Form element to register and authenticate the User
 * @returns The JSX Element whith the Log In Form
 */
function LogIn({showLogIn}) {

 	//The State which evaluates the visibillity of teh Authentication Form
	const [showSwitch, setShowSwitch] = useState(true); // Switches between the Log in and Registration Form based on the Boolean value
	const [error, setError] = useState(null); // The State to store the Error message of the Authentication Form
		
	const {setUser} = useAuth();
				
	const toggleSwitch = () => {
		setError(null);
		setShowSwitch(!showSwitch);
	}
			
	/**
		* This Function is called by the Form Event Handler of the Sign In Form,
		* to parse in the Form data and fetch a Post Request to the backend.
		* The return is Saved inside a React Context
		* 
		* @param {*} e Stores the Form Data 
		*/
	async function handleSignIn(e) {
		setError(null);
		const signInData = getFormData(e);
				
		try{
					
			const signIn = await startUserSession(signInData);
			setUser(signIn.access_token);
			// sessionStorage.setItem('user', signIn.id);
			showLogIn()
		} catch (err) {
			setError(err.message);
		}

	}

	/**
	 * This Function fetches the Formdata to the Create User endpoint and then changes the the LogIn Form to the sign In
	 * @param {*} n 
	 */		
	async function handleCreateUser(n) {
		setError(null); 
		const userData = getFormData(n);
					
		try{
			const newUser = await createNewUser(userData);
			toggleSwitch
		} catch (err) {
			setError(err.message);
		}
					
	}

	/**
	 * This Function Renders the Sign in Form the User uses to Login into there Account 
	 * @returns The SignIn JSX Element 
	 */
	function SignIn() { 
		return(
			<form className='form' onSubmit={handleSignIn}>
				<label>Sign in into your Account</label>
				<input
				type='text'
				name='username'
				placeholder='musterman'
				required
				onChange={(u) => u.target.value}
				className='login-input'
				/>
				<input 
				type='password'
				name='password'
				placeholder='password'
				required
				onChange={(p) => p.target.value}
				className='login-input'
				/>
				{error && <p className='formError'>Error: {error}</p>}
				<button type='submit' className='login-button'>Sign In</button>
				<a>Forgot your Password?</a>
				<p>You don't have an account? 
					<a onClick={toggleSwitch}> Register</a>
				</p>
			</form>
		);
	}
	
	/**
	 * This Function renders the Form the User uses to create there UserAccount 
	 * @returns The CreateUser JSX Elememt
	 */
	function CreateUser() {
		return (
			<form className='form' onSubmit={handleCreateUser}>
				<label>Create your Account</label>
				<input
				type='email'
				name='email'
				placeholder='email@example.com'
				required
				onChange={(e) => e.target.value}
				className='login-input'
				/>
				<input
				type='text'
				name='username'
				placeholder='musterman'
				required
				onChange={(u) => u.target.value}
				className='login-input'
				/>
				<input 
				type='password'
				name='password'
				placeholder='password'
				required
				onChange={(p) => p.target.value}
				className='login-input'
				/>
				{error && <p className='formError'>Error: {error}</p>}
				<button type='submit' className='login-button'>Register</button>
				<p>You already have an account?
					<a onClick={toggleSwitch} > Sign In</a>
				</p>
			</form>
		);
	}
	
	
	return(
			<div id='loginForm' className='login'>
				<button onClick={showLogIn} className='closeButton'>
					<svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
						<line x1="5" y1="5" x2="15" y2="15" stroke="#3A31D8" stroke-width="2" stroke-linecap="round"></line>
						<line x1="15" y1="5" x2="5" y2="15" stroke="#3A31D8" stroke-width="2" stroke-linecap="round"></line>
					</svg>
				</button>
				<div>
					{showSwitch ? <SignIn /> : <CreateUser />}
				</div>
			</div>
		);

}

export default LogIn;