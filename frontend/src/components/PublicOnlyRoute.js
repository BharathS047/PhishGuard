import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const PublicOnlyRoute = () => {
    const { user, tokens, loading } = useAuth();

    if (loading) {
        return null;
    }

    if (tokens) {
        return <Navigate to={user?.is_staff ? '/admin-dashboard' : '/checkurl'} replace />;
    }

    return <Outlet />;
};

export default PublicOnlyRoute;
