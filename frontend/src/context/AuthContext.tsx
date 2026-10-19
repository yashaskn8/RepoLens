'use client';

/**
 * Authentication context and session management provider.
 */

import React, { createContext, useContext, useEffect, useRef, useState } from 'react';
import { UserResponse, UserRole } from '@/types/domain';
import { fetchCurrentUser, loginUser, logoutUser, registerUser } from '@/lib/api';

interface AuthContextType {
  user: UserResponse | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  isOperator: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const authRequestVersion = useRef(0);

  const refreshUser = async () => {
    const version = ++authRequestVersion.current;
    try {
      const current = await fetchCurrentUser();
      if (version === authRequestVersion.current) setUser(current);
    } catch {
      if (version === authRequestVersion.current) setUser(null);
    } finally {
      if (version === authRequestVersion.current) setIsLoading(false);
    }
  };

  useEffect(() => {
    refreshUser();
  }, []);

  const login = async (email: string, password: string) => {
    const version = ++authRequestVersion.current;
    try {
      const loggedIn = await loginUser({ email, password });
      if (version === authRequestVersion.current) setUser(loggedIn);
    } finally {
      if (version === authRequestVersion.current) setIsLoading(false);
    }
  };

  const register = async (email: string, password: string) => {
    const version = ++authRequestVersion.current;
    try {
      await registerUser({ email, password });
      // Registration creates the account only. Authenticate explicitly so the
      // client state never claims a session before HttpOnly/CSRF cookies exist.
      const loggedIn = await loginUser({ email, password });
      if (version === authRequestVersion.current) setUser(loggedIn);
    } finally {
      if (version === authRequestVersion.current) setIsLoading(false);
    }
  };

  const logout = async () => {
    const version = ++authRequestVersion.current;
    try {
      await logoutUser();
    } finally {
      if (version === authRequestVersion.current) {
        setUser(null);
        setIsLoading(false);
      }
    }
  };

  const isOperator = user?.role === 'OPERATOR';
  const isAuthenticated = !!user;

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAuthenticated,
        isOperator,
        login,
        register,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
