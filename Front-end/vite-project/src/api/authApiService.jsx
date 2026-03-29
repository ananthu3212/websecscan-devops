import React, { useState, createContext } from 'react';

// The deafult Base for the Backend API's
const API_BASE_URL = 'http://localhost:5001';

/**
 * This Function parses the FormData Object from any Form into a JSON 
 * @param {*} e Any Form Data from a Form  
 * @returns A JSON with the Values of the Form Data
 */
export function getFormData(e) {
  // Prevent the browser from reloading the page
	e.preventDefault();
  // Read the form data
  const form = e.target;
  const formData = new FormData(form);

  return JSON.stringify( Object.fromEntries(formData.entries()));
    
}

/**
 * Asyc API call to the Log In API in the Backend wich is used to Authenticate the User in The Backend. 
 * This is nessecery to enable more Functionality
 * @param {*} credetials The users Password and username to Authentcate
 * @returns the JWT Token if the User is a Valid User 
 */
export const startUserSession = async (credetials) => {

  try {
    const authenticated = await fetch(API_BASE_URL + '/api/login', {
      method: 'POST', // Use POST method to send data
      headers: {
        'Content-Type': 'application/json', // Indicate that the request body is JSON
      },
      body: credetials
    });

    const user = await authenticated.json();

    if (!authenticated.ok) {
      throw new Error(user.error);
    }


    return user;

  } catch (error) {
    throw error;
  }
}

/**
 * The async API to handle Log Out in the Backend
 * @param {*} token The JWT Token of the current User
 * @returns if the Log Out was Succsessfull
 */
export const endUserSession = async (token) => {
  try {
    const logOut = await fetch(API_BASE_URL + '/api/logout', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json', // Indicate that the request body is JSON
        'Authorization': 'Bearer ' + token,
      },


    });

    if (!logOut.ok) {
      throw new Error("Log Out nicht erfolgreich bitte erneut versuchen");
    }

    return logOut;

  } catch (error) {
    throw error;
  }
}

/**
 * The API Call to Register a User in the System
 * @param {*} userData The required Information enterted by the User
 * @returns if the new User was Sucsessfully createt in the Backend
 */
export const createNewUser = async (userData) => {
  try {
    const userCreated = await fetch(API_BASE_URL + '/api/register', {
      method: 'POST', // Use POST method to send data
      headers: {
        'Content-Type': 'application/json' // Indicate that the request body is JSON
      },
      body: userData,
    });

    const newUser = await userCreated.json();

    if (!userCreated.ok) {
      throw new Error(userCreated.error);        
    }

    return newUser;

  } catch (error) {
    throw error;
  }
}

export const forgotPassword = async (email) => {
  try {
  	const newPassword = await fetch(API_BASE_URL + '/api/forgot_password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json', // Indicate that the request body is JSON        
        },
        body: email,

    });

    if (!newPassword.ok) {
      throw new Error("Log Out nicht erfolgreich bitte erneut versuchen");
    }

    return newPassword;

  } catch (error) {
    throw error;
  }
}

/**
 * The API Call to request the Profile Information of the User 
 * @param {*} token JWT Token of the Current User
 * @returns {Promise<Object>} A Object containig the Information
 */
export const getProfile = async (token) => {
	
	try{
		const userInfo = await fetch(API_BASE_URL + '/api/profile', {
			method: 'GET',
			headers: {
				'Content-Type': 'application/json', // Indicate that the request body is JSON
        'Authorization': 'Bearer ' + token,
			},
			
		})
		
		const data = userInfo.json();
		
		return data;

	} catch (error) {
		throw error;
	}
}