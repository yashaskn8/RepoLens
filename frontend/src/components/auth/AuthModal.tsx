'use client';

/**
 * Authentication Modal providing Login and Registration flows.
 */

import React, { useState } from 'react';
import { useAuth } from '@/context/AuthContext';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function AuthModal({ isOpen, onClose }: AuthModalProps) {
  const { login, register } = useAuth();
  const [tab, setTab] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      if (tab === 'login') {
        await login(email, password);
      } else {
        if (password.length < 12) {
          setError('Password must be at least 12 characters.');
          setIsSubmitting(false);
          return;
        }
        await register(email, password);
        // After register, log in
        await login(email, password);
      }
      onClose();
    } catch (err: any) {
      setError(err.message || 'Authentication request failed.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        <div className="flex border-b border-slate-800 bg-slate-950/50">
          <button
            type="button"
            className={`flex-1 py-4 text-sm font-semibold transition-colors ${
              tab === 'login'
                ? 'text-cyan-400 border-b-2 border-cyan-400 bg-slate-900/50'
                : 'text-slate-400 hover:text-slate-200'
            }`}
            onClick={() => {
              setTab('login');
              setError(null);
            }}
          >
            Sign In
          </button>
          <button
            type="button"
            className={`flex-1 py-4 text-sm font-semibold transition-colors ${
              tab === 'register'
                ? 'text-cyan-400 border-b-2 border-cyan-400 bg-slate-900/50'
                : 'text-slate-400 hover:text-slate-200'
            }`}
            onClick={() => {
              setTab('register');
              setError(null);
            }}
          >
            Create Account
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <h2 className="text-xl font-bold text-white mb-1">
              {tab === 'login' ? 'Welcome back' : 'Get started with RepoLens'}
            </h2>
            <p className="text-xs text-slate-400">
              {tab === 'login'
                ? 'Sign in to access your tenant scans and change intelligence.'
                : 'Create an account to securely analyze repositories and remediation patches.'}
            </p>
          </div>

          {error && (
            <div className="p-3 bg-red-950/50 border border-red-800/80 rounded-lg text-xs text-red-300">
              {error}
            </div>
          )}

          <div className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Email Address</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="user@example.com"
                className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-700/80 rounded-xl text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Password {tab === 'register' && <span className="text-slate-500">(min. 12 characters)</span>}
              </label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-700/80 rounded-xl text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition"
              />
            </div>
          </div>

          <div className="pt-2 flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2.5 text-xs font-semibold text-slate-400 hover:text-slate-200 transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 text-white text-xs font-semibold rounded-xl shadow-lg shadow-cyan-950/50 transition flex items-center gap-2"
            >
              {isSubmitting ? (
                <span>Processing...</span>
              ) : tab === 'login' ? (
                <span>Sign In</span>
              ) : (
                <span>Create Account</span>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
