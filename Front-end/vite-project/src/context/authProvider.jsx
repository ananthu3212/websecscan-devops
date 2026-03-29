import React, { createContext, useContext, useMemo, useState, useEffect } from 'react'

/**
 * This Context Object carrys the information if the user is Logged In and who the user is.
 * The useAuth custom Hook is used to access the Provided Information 
 */
const AuthContext = createContext();

/**
 * A React context to manage the authenticatet Status of a User
 * @param {*} param0 Inherent JSX Elements
 * @returns A Context Objets about the Current Authentication Status of a User
 */
const AuthProvider = ({ children }) => {
  const [logIn, setLogIn] = useState(sessionStorage.getItem('user'));

  const setUser = (user) => {
    setLogIn(user); 
  }

  /**
   * Trigger to Save the JWT Token of a User or remove it 
   */
  useEffect(() => {
    if (logIn) {
      
      sessionStorage.setItem('user', logIn);
    } else {
      
      sessionStorage.removeItem('user')
    }
  }, [logIn]);

  const contextValue = useMemo(
    () => ({
    	logIn,
      setUser,
    }), [logIn]
  );

  return(
    <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>

  );
};

/**
 * A React Hook to check and update the Authentication Context 
 * @returns The Authentication Context Object 
 */
export const useAuth = () => {
  return useContext(AuthContext);
};

export default AuthProvider;