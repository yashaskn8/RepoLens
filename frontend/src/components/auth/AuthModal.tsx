'use client';

import React, { useEffect, useRef, useState } from 'react';
import { useAuth } from '@/context/AuthContext';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';

export interface AuthModalProps {
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
  const modalRef = useRef<HTMLDivElement>(null);
  const firstInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!isOpen) return;

    // Focus first input on open
    setTimeout(() => {
      firstInputRef.current?.focus();
    }, 50);

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

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
        await login(email, password);
      }
      onClose();
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Authentication request failed.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDemoLogin = async (role: 'USER' | 'OPERATOR') => {
    setError(null);
    setIsSubmitting(true);
    try {
      if (role === 'USER') {
        await login('demo@repolens.io', 'RepoLensDemo2026!');
      } else {
        await login('operator@repolens.io', 'RepoLensOperator2026!');
      }
      onClose();
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Demo login failed.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-md p-4 animate-in fade-in duration-200"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="auth-modal-title"
        className="w-full max-w-md bg-slate-950/95 border border-slate-700/60 rounded-2xl shadow-[0_25px_60px_-15px_rgba(0,0,0,0.85),0_0_40px_-10px_rgba(99,102,241,0.35)] overflow-hidden backdrop-blur-2xl animate-in zoom-in-95 duration-200"
      >
        {/* Tab Header */}
        <div className="flex border-b border-slate-800/80 bg-slate-900/70 p-1.5 gap-1.5" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={tab === 'login'}
            className={`flex-1 py-2.5 text-sm font-semibold rounded-xl transition-all cursor-pointer border ${
              tab === 'login'
                ? 'text-cyan-300 bg-slate-800/90 border-cyan-500/40 shadow-sm'
                : 'text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/40'
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
            role="tab"
            aria-selected={tab === 'register'}
            className={`flex-1 py-2.5 text-sm font-semibold rounded-xl transition-all cursor-pointer border ${
              tab === 'register'
                ? 'text-cyan-300 bg-slate-800/90 border-cyan-500/40 shadow-sm'
                : 'text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/40'
            }`}
            onClick={() => {
              setTab('register');
              setError(null);
            }}
          >
            Create Account
          </button>
        </div>

        <div className="p-6 space-y-4">
          <div>
            <h2 id="auth-modal-title" className="text-xl font-bold text-white mb-1">
              {tab === 'login' ? 'Sign In to RepoLens' : 'Get Started with RepoLens'}
            </h2>
            <p className="text-xs text-slate-400">
              {tab === 'login'
                ? 'Authenticate to launch AST scans, generate AI remediations, and deliver PR reviews.'
                : 'Create an account to securely scan repositories and publish verified remediation patches.'}
            </p>
          </div>

          {/* Quick Demo Logins Ribbon */}
          <div className="p-3 rounded-xl bg-indigo-950/40 border border-indigo-500/30 space-y-2">
            <div className="flex items-center justify-between text-[11px]">
              <span className="font-bold text-indigo-300 font-mono">⚡ 1-CLICK QUICK DEMO ACCESS</span>
              <span className="text-[10px] text-slate-400">Instant Sign-In</span>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                className="py-1.5 px-3 rounded-lg text-xs font-semibold bg-indigo-600/30 hover:bg-indigo-600/50 text-indigo-200 border border-indigo-500/40 transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
                onClick={() => handleDemoLogin('USER')}
                disabled={isSubmitting}
              >
                <span>👤</span> Demo User
              </button>
              <button
                type="button"
                className="py-1.5 px-3 rounded-lg text-xs font-semibold bg-purple-600/30 hover:bg-purple-600/50 text-purple-200 border border-purple-500/40 transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
                onClick={() => handleDemoLogin('OPERATOR')}
                disabled={isSubmitting}
              >
                <span>🛡️</span> Operator (Admin)
              </button>
            </div>
          </div>

          <div className="relative flex py-1 items-center">
            <div className="flex-grow border-t border-slate-800"></div>
            <span className="flex-shrink mx-2 text-[11px] text-slate-500 font-mono uppercase">Or with credentials</span>
            <div className="flex-grow border-t border-slate-800"></div>
          </div>

          {error && <Alert variant="error">{error}</Alert>}

          <form onSubmit={handleSubmit} className="space-y-3">
            <Input
              ref={firstInputRef}
              label="Email Address"
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="user@example.com"
              disabled={isSubmitting}
            />

            <Input
              label={`Password ${tab === 'register' ? '(min. 12 characters)' : ''}`}
              type="password"
              required
              autoComplete={tab === 'login' ? 'current-password' : 'new-password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              disabled={isSubmitting}
            />

            <div className="pt-3 flex items-center justify-end gap-3">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={onClose}
                disabled={isSubmitting}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                variant="primary"
                size="sm"
                isLoading={isSubmitting}
              >
                {tab === 'login' ? 'Sign In' : 'Create Account'}
              </Button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
