import React from 'react';
import { Toast, ToastContainer } from 'react-bootstrap';
import './Notification.css';

const Notification = ({ notifications, onDismiss }) => {
  return (
    <ToastContainer position="top-end" className="p-4 notification-container">
      {notifications.map((notification, idx) => (
        <Toast
          key={notification.id}
          onClose={() => onDismiss(notification.id)}
          show={true}
          delay={notification.autoDismiss ? 8000 : null}
          autohide={notification.autoDismiss}
          className={`notification-toast ${notification.type} glass-panel`}
          animation={true}
        >
          <Toast.Header className={`notification-header ${notification.type}`}>
            <i className={`bi ${notification.icon} notification-icon me-2`}></i>
            <strong className="me-auto text-uppercase tracking-wider">{notification.title}</strong>
            <small className="opacity-75">{notification.time}</small>
          </Toast.Header>
          <Toast.Body className="notification-body">
            {notification.message}
            {notification.actionLabel && (
              <div className="notification-actions mt-3">
                <button className="cyber-btn cyber-btn-primary" style={{ padding: '0.4rem 1rem', fontSize: '0.75rem' }} onClick={notification.action}>
                  {notification.actionLabel}
                </button>
              </div>
            )}
          </Toast.Body>
        </Toast>
      ))}
    </ToastContainer>
  );
};

export default Notification;