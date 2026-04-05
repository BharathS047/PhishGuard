import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import './Login.css';

const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError] = useState('');
    const [isNotVerified, setIsNotVerified] = useState(false);
    const [isLoading, setIsLoading] = useState(false);

    const { login } = useAuth();
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setIsNotVerified(false);
        setIsLoading(true);

        try {
            const userData = await login(username, password);
            navigate(userData.is_staff ? '/admin-dashboard' : '/dashboard');
        } catch (err) {
            const detail = err.response?.data?.detail || '';
            if (detail.toLowerCase().includes('no active account')) {
                setError('Account not verified. Check your email for the verification link.');
                setIsNotVerified(true);
            } else {
                setError('Invalid username or password.');
            }
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="auth-container d-flex flex-column align-items-center justify-content-center" style={{ minHeight: '80vh' }}>
            <div className="glass-panel text-center p-5 auth-card" style={{ maxWidth: '500px', width: '100%' }}>
                <h2 className="mb-2 text-cyan">LOGIN</h2>
                <p className="text-muted mb-5 tracking-widest text-uppercase" style={{ fontSize: '0.85rem' }}>Sign in to your account</p>

                {error && (
                    <div className="alert alert-danger mb-4" style={{ backgroundColor: 'rgba(255,42,95,0.1)', color: 'var(--accent-rose)', border: '1px solid var(--accent-rose)', borderRadius: '8px' }}>
                        {error}
                        {isNotVerified && (
                            <div className="mt-2">
                                <Link to="/register" className="text-cyan text-decoration-none" style={{ fontSize: '0.8rem' }}>
                                    Resend verification email
                                </Link>
                            </div>
                        )}
                    </div>
                )}

                <form onSubmit={handleSubmit} className="text-start">
                    <div className="mb-4">
                        <label className="text-muted mb-2 text-uppercase tracking-widest" style={{ fontSize: '0.75rem', fontWeight: '600' }}>Username</label>
                        <input
                            type="text"
                            className="cyber-input w-100"
                            placeholder="Enter username"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            required
                        />
                    </div>
                    <div className="mb-5">
                        <label className="text-muted mb-2 text-uppercase tracking-widest" style={{ fontSize: '0.75rem', fontWeight: '600' }}>Password</label>
                        <div style={{ position: 'relative' }}>
                            <input
                                type={showPassword ? 'text' : 'password'}
                                className="cyber-input w-100"
                                placeholder="Enter password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                required
                                style={{ paddingRight: '44px' }}
                            />
                            <button
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                                style={{ position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', padding: '4px', color: 'var(--accent-cyan)', opacity: 0.7 }}
                                tabIndex={-1}
                                aria-label={showPassword ? 'Hide password' : 'Show password'}
                            >
                                {showPassword ? (
                                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                                ) : (
                                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                )}
                            </button>
                        </div>
                    </div>

                    <button type="submit" className="cyber-btn cyber-btn-primary w-100" disabled={isLoading}>
                        {isLoading ? 'LOGGING IN...' : 'LOGIN'}
                    </button>
                </form>

                <div className="mt-4 text-center">
                    <p className="text-muted mb-2" style={{ fontSize: '0.85rem' }}>
                        <Link to="/forgot-password" className="text-muted text-decoration-none" style={{ borderBottom: '1px solid var(--text-muted)' }}>
                            Forgot your password?
                        </Link>
                    </p>
                    <p className="text-muted mb-0" style={{ fontSize: '0.85rem' }}>
                        Don't have an account? <Link to="/register" className="text-cyan text-decoration-none">Register</Link>
                    </p>
                </div>
            </div>
        </div>
    );
};

export default Login;
