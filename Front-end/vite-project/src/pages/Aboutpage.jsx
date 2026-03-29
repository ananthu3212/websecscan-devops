import React from 'react';
import ServiceCard from '../components/ServiceCard/ServiceCard';
import './Aboutpage.css';

/**
 * A Static About Us Page with information about this Webapplication and more
 * @returns A JSX Element containig the About-Us Page 
 */
const AboutPage = () => {
  return (
    <div className="about-page">


      <section className="about-hero">
        <div className="hero-content">
          {/* Title with Gradient on the Word "Security" */}
          <h1 className="hero-title">
            <div className="title-line">
              Redefining <span className="security-word">Security</span> Through
            </div>
            <div>Actionable Intelligence</div>
          </h1>

          <div className="welcome-text-container">
            <p className="welcome-text">
              Welcome to SecuNet. We are not just a security scanning service; we are a dedicated
              authority in digital integrity, committed to delivering unparalleled clarity and
              actionable intelligence on your digital assets.
            </p>
          </div>

          <section className="services-section">
            <div className="services-container">
              <ServiceCard
                title="Network Port Mapper"
                functionText="Comprehensive scanning and mapping of all network ports, protocols, and services running on your infrastructure."
                benefitText="Provides complete network visibility, identifies unauthorized services, and eliminates security blind spots in your perimeter."
              />

              <ServiceCard
                title="Vulnerability Database Checker"
                functionText="Automated scanning against global CVE databases to detect known vulnerabilities and security patches required for your systems."
                benefitText="Proactively identifies security risks, prioritizes critical updates, and reduces organizational attack surface significantly."
              />

              <ServiceCard
                title="Configuration Analyzer"
                functionText="Systematic review of security configurations against industry benchmarks and compliance standards for optimal hardening."
                benefitText="Ensures systems are properly configured, prevents misconfiguration breaches, and maintains continuous security compliance."
              />
            </div>
          </section>
        </div>
      </section>
    </div>
  );
};

export default AboutPage;
