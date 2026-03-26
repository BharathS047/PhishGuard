import React, { createContext, useContext, useState, useCallback } from 'react';
import { v4 as uuidv4 } from 'uuid';
import '../components/notifications/Notification.css';

// ...existing code...

const NotificationContext = createContext();

export const useNotification = () => {
  const context = useContext(NotificationContext);
  
  if (context === undefined) {
    throw new Error('useNotification must be used within a NotificationProvider');
  }
  
  return context;
};

export const NotificationProvider = ({ children }) => {
  const [notifications, setNotifications] = useState([]);
  
  // Helper to format current time
  const getCurrentTime = () => {
    const now = new Date();
    return now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };
  
  // Add a notification
  const addNotification = useCallback((notification) => {
    const id = notification.id || uuidv4();
    const time = notification.time || getCurrentTime();
    
    setNotifications(prev => [
      ...prev,
      {
        ...notification,
        id,
        time,
      }
    ]);
    
    return id;
  }, []);
  
  // Specific notification types
  const notifyDanger = useCallback((title, message, options = {}) => {
    return addNotification({
      type: 'danger',
      icon: 'bi-exclamation-triangle-fill',
      title,
      message,
      autoDismiss: options.autoDismiss !== false,
      ...options
    });
  }, [addNotification]);
  
  const notifyWarning = useCallback((title, message, options = {}) => {
    return addNotification({
      type: 'warning',
      icon: 'bi-exclamation-circle-fill',
      title,
      message,
      autoDismiss: options.autoDismiss !== false,
      ...options
    });
  }, [addNotification]);
  
  const notifySuccess = useCallback((title, message, options = {}) => {
    return addNotification({
      type: 'success',
      icon: 'bi-check-circle-fill',
      title,
      message,
      autoDismiss: true,
      ...options
    });
  }, [addNotification]);
  
  const notifyInfo = useCallback((title, message, options = {}) => {
    return addNotification({
      type: 'info',
      icon: 'bi-info-circle-fill',
      title,
      message,
      autoDismiss: true,
      ...options
    });
  }, [addNotification]);
  
  // Remove a notification
  const removeNotification = useCallback((id) => {
    setNotifications(prev => prev.filter(item => item.id !== id));
  }, []);
  
  // Clear all notifications
  const clearNotifications = useCallback(() => {
    setNotifications([]);
  }, []);
  
  const value = {
    notifications,
    addNotification,
    notifyDanger,
    notifyWarning,
    notifySuccess,
    notifyInfo,
    removeNotification,
    clearNotifications
  };
  
  return (
    <NotificationContext.Provider value={value}>
      {children}
    </NotificationContext.Provider>
  );
};

export default NotificationContext; 