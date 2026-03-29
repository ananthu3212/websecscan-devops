import React, { useState, useMemo, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useScan } from '../context/ScanContext';
import VulnerabilityCard from '../components/VulnerabilityCard/VulnerabilityCard';
import './ReportPage.css';

// Helper function to process and group the API data
const groupVulnerabilities = (apiData) => {
    const grouped = { critical: [], high: [], medium: [], low: [], info: [] };

    if (!apiData) {
        return grouped;
    }

    // Process ZAP alerts
    if (apiData.zap && apiData.zap.alerts && Array.isArray(apiData.zap.alerts)) {
        apiData.zap.alerts.forEach((alert) => {
            let severity = 'info';
            const risk = alert.risk?.toLowerCase() || '';

            if (risk.includes('high')) severity = 'high';
            else if (risk.includes('medium')) severity = 'medium';
            else if (risk.includes('low')) severity = 'low';
            else if (risk.includes('informational')) severity = 'info';

            const vulnerability = {
                source: 'ZAP',
                title: alert.name || alert.alert || 'ZAP Finding',
                summary: alert.description || 'No description available',
                severity: severity.charAt(0).toUpperCase() + severity.slice(1),
                references: alert.reference ? [alert.reference] : [],
                url: alert.url || null,
                pluginId: alert.pluginId || null,
                confidence: alert.confidence || null,
                solution: alert.solution || null
            };

            if (grouped[severity]) {
                grouped[severity].push(vulnerability);
            }
        });
    }

    // Process Nikto findings
    if (apiData.nikto && apiData.nikto.findings && Array.isArray(apiData.nikto.findings)) {
        apiData.nikto.findings.forEach(finding => {
            const severity = finding.severity?.toLowerCase() || 'info';

            let title = 'Security Finding';
            if (finding.name) {
                title = finding.name
                    .replace(/^GET\s+\//, 'Web Security Issue: ')
                    .replace(/^GET\s+/, 'Web Security Issue: ')
                    .replace(/contains a full wildcard entry\.?/, 'Wildcard Entry Security Risk')
                    .replace(/The X-Content-Type-Options header is not set/, 'Missing Security Header: X-Content-Type-Options')
                    .replace(/Suggested security header missing:/, 'Missing Security Header:')
                    .replace(/Retrieved x-powered-by header:/, 'Server Information Disclosure:')
                    .replace(/See:$/, 'Security Configuration Issue')
                    .replace(/\s+See$/, ' Security Issue');

                title = title.charAt(0).toUpperCase() + title.slice(1);
            }

            const vulnerability = {
                source: 'Nikto',
                title: title,
                summary: finding.description || 'No description available',
                severity: severity.charAt(0).toUpperCase() + severity.slice(1),
                references: finding.references || [],
                url: finding.url || null
            };

            if (grouped[severity]) {
                grouped[severity].push(vulnerability);
            }
        });
    }

    // Process Nmap data
    if (apiData.nmap && Array.isArray(apiData.nmap) && apiData.nmap.length > 0) {
        const validPorts = apiData.nmap.filter(port => port && port.port);
        const openPorts = validPorts.map(port =>
            `${port.port}/${port.protocol || 'tcp'}${port.service ? ` (${port.service})` : ''}`
        );

        const nmapInfo = {
            source: 'Nmap',
            title: 'Network Port Scan',
            summary: openPorts.length > 0
                ? `Open ports: ${openPorts.join(', ')}`
                : 'No open ports found',
            severity: 'Info',
            references: [],
            url: apiData.nmap[0]?.ip || 'N/A'
        };
        grouped.info.push(nmapInfo);
    }

    // Process WhatWeb data
    if (apiData.whatweb && apiData.whatweb.output) {
        const whatwebInfo = {
            source: 'WhatWeb',
            title: 'Technology Fingerprinting',
            summary: 'Technology detection completed',
            severity: 'Info',
            references: [],
            url: apiData.whatweb.output.target || 'N/A'
        };
        grouped.info.push(whatwebInfo);
    }

    // ========== NEW: Process Harvester data ==========
    if (apiData.harvester && apiData.harvester.status === 'success') {

        // Main summary info
        const harvesterSummary = {
            source: 'Harvester',
            title: 'OSINT Information Gathering Results',
            summary: `Found ${apiData.harvester.summary?.emails_count || 0} emails, ${apiData.harvester.summary?.subdomains_count || 0} subdomains, ${apiData.harvester.summary?.hosts_count || 0} hosts, ${apiData.harvester.summary?.ips_count || 0} IPs`,
            severity: 'Info',
            references: [],
            url: apiData.harvester.domain || 'N/A',
            details: apiData.harvester.summary
        };
        grouped.info.push(harvesterSummary);

        // Add IP addresses if found
        if (apiData.harvester.results?.ips && apiData.harvester.results.ips.length > 0) {
            const ipsInfo = {
                source: 'Harvester',
                title: 'Discovered IP Addresses',
                summary: apiData.harvester.results.ips.join(' • '),
                severity: 'Info',
                references: [],
                url: apiData.harvester.domain || 'N/A'
            };
            grouped.info.push(ipsInfo);
        }

        // Add emails if found
        if (apiData.harvester.results?.emails && apiData.harvester.results.emails.length > 0) {
            const emailsInfo = {
                source: 'Harvester',
                title: 'Discovered Email Addresses',
                summary: apiData.harvester.results.emails.join(' • '),
                severity: 'Info',
                references: [],
                url: apiData.harvester.domain || 'N/A'
            };
            grouped.info.push(emailsInfo);
        }

        // Add subdomains if found
        if (apiData.harvester.results?.subdomains && apiData.harvester.results.subdomains.length > 0) {
            const subdomainsInfo = {
                source: 'Harvester',
                title: 'Discovered Subdomains',
                summary: apiData.harvester.results.subdomains.join(' • '),
                severity: 'Info',
                references: [],
                url: apiData.harvester.domain || 'N/A'
            };
            grouped.info.push(subdomainsInfo);
        }

        // Add hosts if found
        if (apiData.harvester.results?.hosts && apiData.harvester.results.hosts.length > 0) {
            const hostsInfo = {
                source: 'Harvester',
                title: 'Discovered Hosts',
                summary: apiData.harvester.results.hosts.join(' • '),
                severity: 'Info',
                references: [],
                url: apiData.harvester.domain || 'N/A'
            };
            grouped.info.push(hostsInfo);
        }

        // Add URLs if found
        if (apiData.harvester.results?.urls && apiData.harvester.results.urls.length > 0) {
            const urlsInfo = {
                source: 'Harvester',
                title: 'Discovered URLs',
                summary: apiData.harvester.results.urls.join(' • '),
                severity: 'Info',
                references: [],
                url: apiData.harvester.domain || 'N/A'
            };
            grouped.info.push(urlsInfo);
        }
    }
    // ========== END of Harvester processing ==========

    return grouped;
};

const ReportPage = () => {
    const { scanResult } = useScan();
    const navigate = useNavigate();
    const location = useLocation();

    const [scanFromUrl, setScanFromUrl] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const searchParams = new URLSearchParams(location.search);
        const scanId = searchParams.get("scanId");

        if (scanId && scanId !== "undefined" && scanId !== "null") {
            fetchScanFromAPI(scanId);
        } else {
            setLoading(false);
        }
    }, [location.search]);

    const fetchScanFromAPI = async (scanId) => {
        setLoading(true);
        setError(null);
        try {
            const response = await fetch(`http://localhost:5001/api/scan/${scanId}`);

            if (response.ok) {
                const data = await response.json();
                setScanFromUrl(data);
            } else {
                setError(`Failed to load scan data (${response.status})`);
            }
        } catch (error) {
            setError(`Network error: ${error.message}`);
        } finally {
            setLoading(false);
        }
    };

    // Use data from URL or from context
    const displayData = scanFromUrl || scanResult?.data || scanResult;
    const displayTarget = displayData?.target || 'Unknown Target';

    const allVulnerabilities = useMemo(() => {
        if (displayData) {
            return groupVulnerabilities(displayData);
        }
        return { critical: [], high: [], medium: [], low: [], info: [] };
    }, [displayData]);

    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    const initialFilter = useMemo(() => {
        return severityOrder.find(key => allVulnerabilities[key]?.length > 0) || 'info';
    }, [allVulnerabilities]);

    const [activeFilter, setActiveFilter] = useState(initialFilter);

    if (loading) {
        return (
            <div className="report-container">
                <div className="loading-state">
                    <h2>Loading Scan Data...</h2>
                    <p>Please wait while we fetch the scan results.</p>
                </div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="report-container">
                <div className="error-state">
                    <h2>Error Loading Scan Data</h2>
                    <p>{error}</p>
                    <button onClick={() => navigate('/')} className="back-button">
                        Go to Scanner
                    </button>
                </div>
            </div>
        );
    }

    if (!displayData) {
        return (
            <div className="report-container">
                <div className="no-data-state">
                    <h2>No Scan Data Available</h2>
                    <p>Please perform a scan first to see the results.</p>
                    <button onClick={() => navigate('/')} className="back-button">
                        Go to Scanner
                    </button>
                </div>
            </div>
        );
    }

    const filters = [
        { key: 'critical', label: 'Critical' },
        { key: 'high', label: 'High' },
        { key: 'medium', label: 'Medium' },
        { key: 'low', label: 'Low' },
        { key: 'info', label: 'Info' },
    ];

    const currentVulnerabilities = allVulnerabilities[activeFilter] || [];

    return (
        <div className="report-container">
            <main className="report-main-content">
                <header className="report-header">
                    <h1 className="target-title">Target: {displayTarget}</h1>
                </header>

                <div className="severity-filters-horizontal">
                    {filters.map(filter => (
                        <button
                            key={filter.key}
                            className={`filter-tab ${filter.key} ${activeFilter === filter.key ? 'active' : ''}`}
                            onClick={() => setActiveFilter(filter.key)}
                        >
                            <span className="filter-label">{filter.label}</span>
                            <span className="filter-count">({allVulnerabilities[filter.key]?.length || 0})</span>
                        </button>
                    ))}
                </div>

                <div className="vulnerability-list">
                    {currentVulnerabilities.length > 0 ? (
                        currentVulnerabilities.map((vuln, index) => (
                            <VulnerabilityCard
                                key={`${vuln.source}-${index}-${vuln.title}`}
                                vulnerability={vuln}
                            />
                        ))
                    ) : (
                        <div className={`no-findings no-findings-${activeFilter}`}>
                            No <strong>{activeFilter}</strong> vulnerabilities found.
                        </div>
                    )}
                </div>

                <div className="report-footer">
                    <button onClick={() => navigate('/')} className="back-button">
                        ← Back to Scanner
                    </button>
                </div>
            </main>
        </div>
    );
};

export default ReportPage;