import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useScan } from '../context/ScanContext';
import "./AppPage.css"

/**
 * The Main Page of The Application where User Starts a Scan 
 * @returns JSX Element of the Main Page
 */
export default function AppPage() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { startDynamicScan } = useScan();

  /**
   * Handle the entry of the "target" Textfield by calling the Scan API with the "target" as Parameter and awaiting the result.
   * After reciving the response navigate to the Report Page. 
   * @param {*} e Text entry of target 
   * @returns an alert if the field was empty
   */
  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!target.trim()) {
      alert("Please enter a target URL.");
      return;
    }

    setLoading(true);

    try {
      // Use the context function for scanning
      const result = await startDynamicScan(target);

      if (result && result.success) {
        // Get scan_id from the nested data object
        const scanId = result.data?.scan_id || result.data?.id;

        alert("Scan completed successfully! Redirecting to report...");
        setTarget('');

        if (scanId) {
          navigate(`/report?scanId=${scanId}`);
        } else {
          navigate('/report');
        }
      } else {
        alert(`Scan failed: ${result?.error || "Unknown error"}`);
      }

    } catch (err) {
      console.error("Network error:", err);
      alert("Failed to connect to the server. Please make sure the backend is running.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      background: '#000000',
      minHeight: '100vh',
      color: 'white',
      display: 'flex',
      flexDirection: 'column'
    }}>

      {/* MAIN CONTENT CONTAINER */}
      <div style={{
        flex: 1,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-end',
        padding: '0px 100px 50px 100px',
        gap: '50px'
      }}>

        {/* LEFT SIDE - TEXT CONTENT */}
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '49px',
          width: '579px',
          marginBottom: '340px'
        }}>

          {/* TITLE */}
          <h1 style={{
            color: '#FFFFFF',
            fontSize: '38px',
            fontWeight: '700',
            margin: '0',
            lineHeight: '1.1',
            width: '579px',
          }}>
            Precision <span className="accent">Security</span> Scanning
          </h1>

          {/* PARAGRAPH */}
          <p style={{
            color: '#EBE9FC',
            fontSize: '20px',
            lineHeight: '1.4',
            margin: '0'
          }}>
            Our platform, Secunet, is built on the expertise of the most trusted names in ethical hacking—Nmap for network mapping,
            Nikto for web server checks, OWASP ZAP for active application testing, and WhatWeb for technology profiling.
            This focused approach ensures deep, reliable visibility into your digital infrastructure.
          </p>

          {/* INPUT FORM */}
          <form onSubmit={handleSubmit} style={{
            display: 'flex',
            gap: '15px',
            width: '100%'
          }}>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="Enter Target URL"
              disabled={loading}
              required
              className="hero-input"
            />
            <button
              type="submit"
              disabled={loading || !target.trim()}
              className="scan-button"
            >
              {loading ? "Scanning..." : "Scan"}
            </button>
          </form>

        </div>

        {/* RIGHT SIDE - IMAGE CONTAINER */}
        <div style={{
          display: 'flex',
          justifyContent: 'flex-end',
          alignItems: 'flex-end',
          flex: 1
        }}>
          <img
            src="/Group.png"
            alt="Security Scanning Illustration"
            className="hero-image"
          />
        </div>

      </div>
    </div>
  );
}