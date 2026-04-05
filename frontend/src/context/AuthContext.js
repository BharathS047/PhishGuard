import React, { createContext, useState, useEffect, useContext } from 'react';
import axios from 'axios';

const AuthContext = createContext();
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [tokens, setTokens] = useState(() => {
        const localTokens = localStorage.getItem('tokens');
        return localTokens ? JSON.parse(localTokens) : null;
    });

    const fetchUserProfile = async (token) => {
        try {
            setLoading(true);
            const response = await axios.get(`${API_URL}/auth/me/`, {
                headers: {
                    Authorization: `Bearer ${token}`
                }
            });
            setUser(response.data);
        } catch (error) {
            console.error('Error fetching user profile', error);
            logout();
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (tokens) {
            fetchUserProfile(tokens.access);
        } else {
            setLoading(false);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [tokens]);

    const login = async (username, password) => {
        const response = await axios.post(`${API_URL}/auth/login/`, { username, password });
        const newTokens = response.data;
        setTokens(newTokens);
        localStorage.setItem('tokens', JSON.stringify(newTokens));
        // Fetch and return user profile so callers can route based on role
        const profileRes = await axios.get(`${API_URL}/auth/me/`, {
            headers: { Authorization: `Bearer ${newTokens.access}` }
        });
        setUser(profileRes.data);
        return profileRes.data;
    };

    const register = async (username, email, password) => {
        await axios.post(`${API_URL}/auth/register/`, { username, email, password });
        // Do NOT auto-login — the account is inactive until email is verified
    };

    const verifyEmail = async (email, otp) => {
        const response = await axios.post(`${API_URL}/auth/verify-email/`, { email, otp });
        return response.data;
    };

    const forgotPassword = async (email) => {
        const response = await axios.post(`${API_URL}/auth/forgot-password/`, { email });
        return response.data;
    };

    const resetPassword = async (email, otp, new_password, confirm_password) => {
        const response = await axios.post(`${API_URL}/auth/reset-password/`, {
            email, otp, new_password, confirm_password,
        });
        return response.data;
    };

    const resendVerification = async (email) => {
        const response = await axios.post(`${API_URL}/auth/resend-verification/`, { email });
        return response.data;
    };

    const logout = () => {
        setTokens(null);
        setUser(null);
        localStorage.removeItem('tokens');
    };

    return (
        <AuthContext.Provider value={{ user, tokens, loading, login, register, logout, verifyEmail, forgotPassword, resetPassword, resendVerification }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);

export default AuthContext;
