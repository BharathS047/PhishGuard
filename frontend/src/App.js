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

function AppContent() {
  const { notifications, removeNotification } = useNotification();

  return (
    <div className="App">
      <div className="container">
        <Navbar />
        <Routes>
          <Route path="/" element={<Head />} />
          <Route path="/checkurl" element={<CheckUrl />} />
          <Route path="/features" element={<Features />} />
          <Route path="/email-analysis" element={<EmailAnalysis />} />
          <Route path="/dashboard" element={<Dashboard />} />
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
    <NotificationProvider>
      <AppContent />
    </NotificationProvider>
  );
}

export default App;
