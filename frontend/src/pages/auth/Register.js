import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import './Register.css';

const Register = () => {
    const [username, setUsername] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    const { register } = useAuth();
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setIsLoading(true);

        try {
            await register(username, email, password);
            // Redirect to verify-email, passing email so the OTP form is pre-filled
            navigate('/verify-email', { state: { email } });
        } catch (err) {
            const data = err.response?.data;
            if (data) {
                const messages = Object.values(data).flat().join(' ');
                setError(messages || 'Registration failed. Username may already be taken.');
            } else {
                setError('Registration failed. Please try again.');
            }
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="auth-container d-flex flex-column align-items-center justify-content-center" style={{ minHeight: '80vh' }}>
            <div className="glass-panel text-center p-5 auth-card" style={{ maxWidth: '500px', width: '100%' }}>
                <h2 className="mb-2 text-cyan">REGISTER</h2>
                <p className="text-muted mb-5 tracking-widest text-uppercase" style={{ fontSize: '0.85rem' }}>Create your account</p>

                {error && (
                    <div className="alert alert-danger mb-4" style={{ backgroundColor: 'rgba(255,42,95,0.1)', color: 'var(--accent-rose)', border: '1px solid var(--accent-rose)', borderRadius: '8px' }}>
                        {error}
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
                    <div className="mb-4">
                        <label className="text-muted mb-2 text-uppercase tracking-widest" style={{ fontSize: '0.75rem', fontWeight: '600' }}>Email</label>
                        <input
                            type="email"
                            className="cyber-input w-100"
                            placeholder="you@example.com"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                        />
                    </div>
                    <div className="mb-5">
                        <label className="text-muted mb-2 text-uppercase tracking-widest" style={{ fontSize: '0.75rem', fontWeight: '600' }}>Password</label>
                        <input
                            type="password"
                            className="cyber-input w-100"
                            placeholder="Create password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            minLength={8}
                        />
                    </div>

                    <button type="submit" className="cyber-btn cyber-btn-primary w-100" disabled={isLoading}>
                        {isLoading ? 'REGISTERING...' : 'REGISTER'}
                    </button>
                </form>

                <div className="mt-4 text-center">
                    <p className="text-muted mb-0" style={{ fontSize: '0.85rem' }}>
                        Already have an account? <Link to="/login" className="text-cyan text-decoration-none">Login</Link>
                    </p>
                </div>
            </div>
        </div>
    );
};

export default Register;
