import React, { createContext, useState, useEffect } from 'react';
import { authService } from '../services/api';

export const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('epa_token') || null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchUser = async () => {
      const storedToken = localStorage.getItem('epa_token');
      const isGuest = localStorage.getItem('epa_guest');

      if (storedToken) {
        try {
          const userData = await authService.getMe();
          setUser(userData);
        } catch (err) {
          console.warn('Session expired or invalid token:', err);
          localStorage.removeItem('epa_token');
          setToken(null);
          setUser(null);
        }
      } else if (isGuest === 'true') {
        setUser({
          user_id: 'anonymous_demo_user',
          name: 'Security Analyst (Demo)',
          email: 'analyst@demo.local',
        });
      }
      setLoading(false);
    };

    fetchUser();

    const handleExpired = () => {
      setToken(null);
      setUser(null);
    };
    window.addEventListener('epa_auth_expired', handleExpired);
    return () => window.removeEventListener('epa_auth_expired', handleExpired);
  }, [token]);

  const login = async (email, password) => {
    const data = await authService.login(email, password);
    localStorage.setItem('epa_token', data.access_token);
    setToken(data.access_token);
    setUser(data.user);
    return data;
  };

  const register = async (name, email, password) => {
    const data = await authService.register(name, email, password);
    localStorage.setItem('epa_token', data.access_token);
    setToken(data.access_token);
    setUser(data.user);
    return data;
  };

  const guestLogin = () => {
    const demoUser = {
      user_id: 'anonymous_demo_user',
      name: 'Security Analyst (Demo)',
      email: 'analyst@demo.local',
    };
    setUser(demoUser);
    localStorage.setItem('epa_guest', 'true');
  };

  const logout = () => {
    localStorage.removeItem('epa_token');
    localStorage.removeItem('epa_guest');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user || !!token,
        loading,
        login,
        register,
        guestLogin,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};
