import React, { useState, useRef } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import './Login.css';

const VerifyEmail = () => {
    const location = useLocation();
    const { verifyEmail, resendVerification } = useAuth();

    const [email, setEmail] = useState(location.state?.email || '');
    const [otp, setOtp] = useState(['', '', '', '', '', '']);
    const [status, setStatus] = useState('idle'); // idle | loading | success | error
    const [message, setMessage] = useState('');
    const [resendMsg, setResendMsg] = useState('');
    const [resendLoading, setResendLoading] = useState(false);

    const inputRefs = useRef([]);

    const handleOtpChange = (index, value) => {
        if (!/^\d*$/.test(value)) return; // digits only
        const newOtp = [...otp];
        newOtp[index] = value.slice(-1); // take last char if pasted
        setOtp(newOtp);
        if (value && index < 5) {
            inputRefs.current[index + 1]?.focus();
        }
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
        const code = otp.join('');
        if (code.length < 6) {
            setMessage('Please enter the full 6-digit code.');
            setStatus('error');
            return;
        }
        setStatus('loading');
        setMessage('');
        try {
            await verifyEmail(email, code);
            setStatus('success');
            setMessage('Email verified successfully. You may now log in.');
        } catch (err) {
            setStatus('error');
            setMessage(err.response?.data?.detail || 'Invalid or expired OTP. Please try again.');
        }
    };

    const handleResend = async () => {
        setResendMsg('');
        setResendLoading(true);
        try {
            await resendVerification(email);
            setResendMsg('A new OTP has been sent to your email.');
        } catch {
            setResendMsg('Could not resend. Please try again later.');
        } finally {
            setResendLoading(false);
        }
    };

    if (status === 'success') {
        return (
            <div className="auth-container d-flex flex-column align-items-center justify-content-center" style={{ minHeight: '80vh' }}>
                <div className="glass-panel text-center p-5 auth-card" style={{ maxWidth: '500px', width: '100%' }}>
                    <h2 className="mb-2 text-emerald">VERIFIED</h2>
                    <p className="text-muted mb-4 tracking-widest text-uppercase" style={{ fontSize: '0.85rem' }}>Email Confirmed</p>
                    <p className="text-main mb-4">{message}</p>
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
                <h2 className="mb-2 text-cyan">VERIFY EMAIL</h2>
                <p className="text-muted mb-2 tracking-widest text-uppercase" style={{ fontSize: '0.85rem' }}>Enter the 6-digit code</p>
                <p className="text-muted mb-4" style={{ fontSize: '0.85rem' }}>
                    A verification code was sent to <span className="text-cyan fw-bold">{email || 'your email'}</span>
                </p>

                {status === 'error' && (
                    <div className="alert mb-4" style={{ backgroundColor: 'rgba(255,42,95,0.1)', color: 'var(--accent-rose)', border: '1px solid var(--accent-rose)', borderRadius: '8px' }}>
                        {message}
                    </div>
                )}

                <form onSubmit={handleSubmit}>
                    {!location.state?.email && (
                        <div className="mb-4 text-start">
                            <label className="text-muted mb-2 text-uppercase tracking-widest" style={{ fontSize: '0.75rem', fontWeight: '600' }}>Email</label>
                            <input
                                type="email"
                                className="cyber-input w-100"
                                placeholder="your@email.com"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                required
                            />
                        </div>
                    )}

                    {/* OTP digit boxes */}
                    <div className="d-flex justify-content-center gap-2 mb-4" onPaste={handlePaste}>
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
                                    width: '52px',
                                    height: '60px',
                                    textAlign: 'center',
                                    fontSize: '1.5rem',
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

                    <button
                        type="submit"
                        className="cyber-btn cyber-btn-primary w-100 mb-3"
                        disabled={status === 'loading'}
                    >
                        {status === 'loading' ? 'VERIFYING...' : 'VERIFY CODE'}
                    </button>
                </form>

                <p className="text-muted mb-2" style={{ fontSize: '0.85rem' }}>
                    Didn't receive it?{' '}
                    <button
                        onClick={handleResend}
                        disabled={resendLoading}
                        style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', cursor: 'pointer', padding: 0, fontSize: '0.85rem' }}
                    >
                        {resendLoading ? 'Sending...' : 'Resend OTP'}
                    </button>
                </p>
                {resendMsg && <p className="mb-3" style={{ fontSize: '0.82rem', color: resendMsg.includes('sent') ? 'var(--accent-cyan)' : 'var(--accent-rose)' }}>{resendMsg}</p>}

                <Link to="/login" className="text-cyan text-decoration-none" style={{ fontSize: '0.85rem' }}>
                    Return to Login
                </Link>
            </div>
        </div>
    );
};

export default VerifyEmail;
