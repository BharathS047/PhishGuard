import React, { useEffect } from "react";
import "./App.css";
import { Routes, Route } from 'react-router-dom';
import EmailAnalysis from "./pages/emailanalysis/EmailAnalysis";
import Navbar from "./components/navbar/Navbar";
import Features from "./components/features/Features";
import CheckUrl from "./pages/checkurl/CheckUrl";
import Head from "./components/head/Head";
import Footer from "./components/footer/Footer";
import Dashboard from "./pages/dashboard/Dashboard";

import Notification from "./components/notifications/Notification";
import { NotificationProvider, useNotification } from "./context/NotificationContext";
import { AuthProvider } from "./context/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import PublicOnlyRoute from "./components/PublicOnlyRoute";
import Login from "./pages/auth/Login";
import Register from "./pages/auth/Register";
import VerifyEmail from "./pages/auth/VerifyEmail";
import ForgotPassword from "./pages/auth/ForgotPassword";
import ResetPassword from "./pages/auth/ResetPassword";
import AdminPanel from "./pages/adminpanel/AdminPanel";

function AppContent() {
  const { notifications, removeNotification } = useNotification();

  return (
    <div className="App">
      <div className="container">
        <Navbar />
        <Routes>
          <Route element={<PublicOnlyRoute />}>
            <Route path="/" element={<Head />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
          </Route>
          <Route path="/verify-email" element={<VerifyEmail />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          
          <Route element={<ProtectedRoute />}>
            <Route path="/checkurl" element={<CheckUrl />} />
            <Route path="/features" element={<Features />} />
            <Route path="/email-analysis" element={<EmailAnalysis />} />
            <Route path="/dashboard" element={<Dashboard />} />
          </Route>
          
          <Route element={<ProtectedRoute adminOnly={true} />}>
            <Route path="/admin-dashboard" element={<AdminPanel />} />
          </Route>
        </Routes>
        <Footer />
        <Notification notifications={notifications} onDismiss={removeNotification} />
      </div>
    </div>
  );
}

function App() {
  useEffect(() => {
    // Check localStorage for theme preference, default to dark
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
  }, []);

  return (
    <AuthProvider>
      <NotificationProvider>
        <AppContent />
      </NotificationProvider>
    </AuthProvider>
  );
}

export default App;
