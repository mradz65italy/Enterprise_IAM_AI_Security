import React, { createContext, useContext, useState, useEffect } from 'react';
import jwt_decode from 'jwt-decode';
import api from '../services/api';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [token, setToken] = useState(localStorage.getItem('access_token'));

  useEffect(() => {
    if (token) {
      try {
        const decoded = jwt_decode(token);
        const currentTime = Date.now() / 1000;
        
        if (decoded.exp > currentTime) {
          // Token is valid
          api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
          fetchUserInfo();
        } else {
          // Token expired
          logout();
        }
      } catch (error) {
        console.error('Invalid token:', error);
        logout();
      }
    } else {
      setLoading(false);
    }
  }, [token]);

  const fetchUserInfo = async () => {
    try {
      const response = await api.get('/auth/me');
      setUser(response.data);
    } catch (error) {
      console.error('Failed to fetch user info:', error);
      logout();
    } finally {
      setLoading(false);
    }
  };

  const login = async (credentials) => {
    try {
      const response = await api.post('/auth/login', credentials);
      const { access_token, refresh_token } = response.data;
      
      localStorage.setItem('access_token', access_token);
      localStorage.setItem('refresh_token', refresh_token);
      
      setToken(access_token);
      api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      
      return { success: true };
    } catch (error) {
      console.error('Login failed:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Login failed' 
      };
    }
  };

  const logout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    delete api.defaults.headers.common['Authorization'];
    setUser(null);
    setToken(null);
    setLoading(false);
  };

  const hasRole = (requiredRole) => {
    if (!user) return false;
    
    const roleHierarchy = {
      'viewer': 1,
      'auditor': 2,
      'ai_manager': 3,
      'admin': 4,
      'super_admin': 5
    };
    
    const userLevel = roleHierarchy[user.role] || 0;
    const requiredLevel = roleHierarchy[requiredRole] || 0;
    
    return userLevel >= requiredLevel;
  };

  const hasPermission = (permission) => {
    // This would be implemented based on your permission system
    return user && user.permissions && user.permissions.includes(permission);
  };

  const value = {
    user,
    token,
    loading,
    login,
    logout,
    hasRole,
    hasPermission,
    isAuthenticated: !!user
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthProvider;