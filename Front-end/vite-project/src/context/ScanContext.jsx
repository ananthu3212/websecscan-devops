import React, { createContext, useState, useContext } from 'react';
import { useAuth } from './authProvider';

const ScanContext = createContext();

/**
 * The Scan Context Provider to manage the Scan and latest report Data 
 * @param {*} param0 The Inherit JSX Elements
 * @returns The Scan Context Provider Object 
 */
export const ScanProvider = ({ children }) => {
    const initialScanResult = {
        nikto_data: null,
        nmap_data: null,
        whatweb_data: null,
        zap_data: { alerts: [] },
        status: 'idle',
        errors: [],
    };

    const [scanResult, setScanResult] = useState(initialScanResult);
    const [targetUrl, setTargetUrl] = useState('');
    const [isScanning, setIsScanning] = useState(false);

    const {logIn} = useAuth();

    /**
     * Set of an API Call to Initiate the Scan and await the result and save it in the Context
     * @param {*} target URL of the scan target
     * @returns A Context object containing the scan result 
     */
    const startDynamicScan = async (target) => {
        setIsScanning(true);
        try {
            const response = await fetch("http://localhost:5001/api/scan", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    'Authorization': 'Bearer ' + logIn,
                },
                body: JSON.stringify({ target: target }),
            });

            // Check if response is JSON
            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                const text = await response.text();
                console.error('❌ Received HTML instead of JSON:', text.substring(0, 500));
                throw new Error('Backend server returned HTML instead of JSON. The API might be down.');
            }

            const data = await response.json();

            if (response.ok) {
                // Store the full data in context
                setScanResult(data);
                setTargetUrl(target);

                // Return success with the data (including scan_id)
                return {
                    success: true,
                    data: data  // This contains scan_id, zap, nmap, etc.
                };
            } else {
                console.error("❌ API Scan Failed:", data.message);
                return {
                    success: false,
                    error: data.message || "Scan failed"
                };
            }
        } catch (error) {
            console.error("🚨 Network Error:", error);
            let errorMessage = error.message;

            if (error.message.includes('HTML instead of JSON')) {
                errorMessage = 'Backend server is not responding properly. Please check if all services are running.';
            } else if (error.message.includes('Failed to fetch')) {
                errorMessage = 'Cannot connect to the backend server. The API might be down.';
            }

            return {
                success: false,
                error: errorMessage
            };
        } finally {
            setIsScanning(false);
        }
    };

    const value = {
        scanResult,
        setScanResult,
        targetUrl,
        setTargetUrl,
        isScanning,
        startDynamicScan
    };

    return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
};

/**
 * A Hook to 
 * @returns the Scan Context Object
 */
export const useScan = () => useContext(ScanContext);