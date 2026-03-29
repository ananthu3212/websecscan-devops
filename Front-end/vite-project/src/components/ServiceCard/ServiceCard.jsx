import React from 'react';
import './ServiceCard.css';

/**
 * JSX Element to discribe a Service the Application offers 
 * @param {*} param0 
 * @returns A JSX Element containig siple html 
 */
const ServiceCard = ({ title, functionText, benefitText, className = '' }) => {
  return (
    <div className={`service-card ${className}`}>
      <h3 className="service-title">{title}</h3>
      <div className="service-content">
        <div className="function-section">
          <h4 className="section-label">Function:</h4>
          <p className="section-text">{functionText}</p>
        </div>
        <div className="benefits-section">
          <h4 className="section-label">Benefit:</h4>
          <p className="section-text">{benefitText}</p>
        </div>
      </div>
    </div>
  );
};

export default ServiceCard;