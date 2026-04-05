import React, { useState, useRef } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import './Login.css';

// Standalone reset page — used if someone navigates directly to /reset-password.
// The primary reset flow is handled inside ForgotPassword.js (two-step).
const ResetPassword = () => {
    const { resetPassword } = useAuth();

    const [email, setEmail] = useState('');
    const [otp, setOtp] = useState(['', '', '', '', '', '']);
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [showNewPassword, setShowNewPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState(false);

    const inputRefs = useRef([]);

    const handleOtpChange = (index, value) => {
        if (!/^\d*$/.test(value)) return;
        const newOtp = [...otp];
        newOtp[index] = value.slice(-1);
        setOtp(newOtp);
        if (value && index < 5) inputRefs.current[index + 1]?.focus();
    };

    const handleOtpKeyDown = (index, e) => {
        if (e.key === 'Backspace' && !otp[index] && index > 0) {
            inputRefs.current[index - 1]?.focus();
        }
    };

    const handlePaste = (e) => {
        e.preventDefault();
        const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
        const newOtp = [...otp];
        pasted.split('').forEach((ch, i) => { newOtp[i] = ch; });
        setOtp(newOtp);
        inputRefs.current[Math.min(pasted.length, 5)]?.focus();
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        const code = otp.join('');
        if (code.length < 6) { setError('Please enter the full 6-digit code.'); return; }
        if (newPassword !== confirmPassword) { setError('Passwords do not match.'); return; }
        setIsLoading(true);
        try {
            await resetPassword(email, code, newPassword, confirmPassword);
            setSuccess(true);
        } catch (err) {
            const detail = err.response?.data?.detail;
            setError(Array.isArray(detail) ? detail.join(' ') : (detail || 'Reset failed. The OTP may be invalid or expired.'));
        } finally {
            setIsLoading(false);
        }
    };

    if (success) {
        return (
            <div className="auth-container d-flex flex-column align-items-center justify-content-center" style={{ minHeight: '80vh' }}>
                <div className="glass-panel text-center p-5 auth-card" style={{ maxWidth: '500px', width: '100%' }}>
                    <h2 className="mb-2 text-emerald">PASSWORD RESET</h2>
                    <p className="text-muted mb-4 tracking-widest text-uppercase" style={{ fontSize: '0.85rem' }}>Password updated successfully</p>
                    <p className="text-main mb-4">You may now log in with your new password.</p>
                    <Link to="/login" className="cyber-btn cyber-btn-primary d-inline-block" style={{ textDecoration: 'none' }}>
                        PROCEED TO LOGIN
                    </Link>
                </div>
            </div>
        );
    }

    return (
        <div className="auth-container d-flex flex-column align-items-center justify-content-center" style={{ minHeight: '80vh' }}>
            <div className="glass-panel text-center p-5 auth-card" style={{ maxWidth: '520px', width: '100%' }}>
                <h2 className="mb-2 text-cyan">RESET PASSWORD</h2>
                <p className="text-muted mb-5 tracking-widest text-uppercase" style={{ fontSize: '0.85rem' }}>Enter your email and OTP</p>

                {error && (
                    <div className="alert mb-4" style={{ backgroundColor: 'rgba(255,42,95,0.1)', color: 'var(--accent-rose)', border: '1px solid var(--accent-rose)', borderRadius: '8px' }}>
                        {error}
                    </div>
                )}

                <form onSubmit={handleSubmit} className="text-start">
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

                    <div className="mb-4">
                        <label className="text-muted mb-2 text-uppercase tracking-widest" style={{ fontSize: '0.75rem', fontWeight: '600' }}>OTP Code</label>
                        <div className="d-flex justify-content-center gap-2" onPaste={handlePaste}>
                            {otp.map((digit, i) => (
                                <input
                                    key={i}
                                    ref={(el) => (inputRefs.current[i] = el)}
                                    type="text"
                                    inputMode="numeric"
                                    maxLength={1}
                                    value={digit}
                                    onChange={(e) => handleOtpChange(i, e.target.value)}
                                    onKeyDown={(e) => handleOtpKeyDown(i, e)}
                                    style={{
                                        width: '48px',
                                        height: '56px',
                                        textAlign: 'center',
                                        fontSize: '1.4rem',
                                        fontWeight: '700',
                                        fontFamily: 'monospace',
                                        background: 'rgba(0,255,255,0.05)',
                                        border: digit ? '2px solid var(--accent-cyan)' : '2px solid rgba(255,255,255,0.15)',
                                        borderRadius: '10px',
                                        color: 'var(--accent-cyan)',
                                        outline: 'none',
                                        transition: 'border-color 0.2s, box-shadow 0.2s',
                                        boxShadow: digit ? '0 0 10px rgba(0,255,255,0.2)' : 'none',
                                    }}
                                />
                            ))}
                        </div>
                    </div>

                    <div className="mb-4">
                        <label className="text-muted mb-2 text-uppercase tracking-widest" style={{ fontSize: '0.75rem', fontWeight: '600' }}>New Password</label>
                        <div style={{ position: 'relative' }}>
                            <input
                                type={showNewPassword ? 'text' : 'password'}
                                className="cyber-input w-100"
                                placeholder="Enter new password"
                                value={newPassword}
                                onChange={(e) => setNewPassword(e.target.value)}
                                required
                                minLength={8}
                                style={{ paddingRight: '44px' }}
                            />
                            <button
                                type="button"
                                onClick={() => setShowNewPassword(!showNewPassword)}
                                style={{ position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', padding: '4px', color: 'var(--accent-cyan)', opacity: 0.7 }}
                                tabIndex={-1}
                                aria-label={showNewPassword ? 'Hide password' : 'Show password'}
                            >
                                {showNewPassword ? (
                                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                                ) : (
                                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                )}
                            </button>
                        </div>
                    </div>
                    <div className="mb-5">
                        <label className="text-muted mb-2 text-uppercase tracking-widest" style={{ fontSize: '0.75rem', fontWeight: '600' }}>Confirm Password</label>
                        <div style={{ position: 'relative' }}>
                            <input
                                type={showConfirmPassword ? 'text' : 'password'}
                                className="cyber-input w-100"
                                placeholder="Confirm new password"
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                required
                                minLength={8}
                                style={{ paddingRight: '44px' }}
                            />
                            <button
                                type="button"
                                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                style={{ position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', padding: '4px', color: 'var(--accent-cyan)', opacity: 0.7 }}
                                tabIndex={-1}
                                aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                            >
                                {showConfirmPassword ? (
                                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                                ) : (
                                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                )}
                            </button>
                        </div>
                    </div>

                    <button type="submit" className="cyber-btn cyber-btn-primary w-100" disabled={isLoading}>
                        {isLoading ? 'RESETTING...' : 'RESET PASSWORD'}
                    </button>
                </form>

                <div className="mt-4 text-center">
                    <Link to="/forgot-password" className="text-cyan text-decoration-none" style={{ fontSize: '0.85rem' }}>
                        ← Back to Forgot Password
                    </Link>
                </div>
            </div>
        </div>
    );
};

export default ResetPassword;
