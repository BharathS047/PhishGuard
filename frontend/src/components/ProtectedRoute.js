import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const ProtectedRoute = ({ adminOnly = false }) => {
    const { user, tokens, loading } = useAuth();

    if (loading) {
        return (
            <div className="d-flex flex-column align-items-center justify-content-center" style={{ minHeight: '80vh' }}>
                <div className="spinner mb-4" style={{ width: '60px', height: '60px', borderTopColor: 'var(--accent-cyan)' }}></div>
                <p className="text-cyan text-uppercase tracking-widest font-weight-bold" style={{ letterSpacing: '0.2em' }}>Authenticating...</p>
            </div>
        );
    }

    if (!tokens) {
        return <Navigate to="/login" replace />;
    }

    if (adminOnly && user && !user.is_staff) {
        return <Navigate to="/" replace />;
    }

    // Admin users can only access the admin panel
    if (!adminOnly && user?.is_staff) {
        return <Navigate to="/admin-dashboard" replace />;
    }

    return <Outlet />;
};

export default ProtectedRoute;
