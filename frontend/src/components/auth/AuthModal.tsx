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

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-md p-4 animate-in fade-in duration-200"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="auth-modal-title"
        className="w-full max-w-md bg-slate-950/90 border border-slate-700/60 rounded-2xl shadow-[0_25px_60px_-15px_rgba(0,0,0,0.8),0_0_40px_-10px_rgba(99,102,241,0.3)] overflow-hidden backdrop-blur-2xl animate-in zoom-in-95 duration-200"
      >
        {/* Tab Header */}
        <div className="flex border-b border-slate-800/80 bg-slate-900/60 p-1.5 gap-1.5" role="tablist">
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

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <h2 id="auth-modal-title" className="text-xl font-bold text-white mb-1">
              {tab === 'login' ? 'Welcome Back' : 'Get Started with RepoLens'}
            </h2>
            <p className="text-xs text-slate-400">
              {tab === 'login'
                ? 'Sign in to access your tenant scans, remediations, and PR change intelligence.'
                : 'Create an account to securely analyze private repositories and trigger verified remediation patches.'}
            </p>
          </div>

          {error && <Alert variant="error">{error}</Alert>}

          <div className="space-y-3">
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
          </div>

          <div className="pt-2 flex items-center justify-end gap-3">
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
  );
}
