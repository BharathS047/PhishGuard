import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import './Login.css';

const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
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
                        <input
                            type="password"
                            className="cyber-input w-100"
                            placeholder="Enter password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                        />
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
