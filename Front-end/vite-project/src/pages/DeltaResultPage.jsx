import React, { useState, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import "./DeltaResultPage.css";
import Header from "../components/Header/Header";

/**
 * The Page to show the result of a Comparison between two Scans the User made in the Past
 * @returns A JSX Element containig the comparison results
 */
export default function DeltaResultPage() {
  const [comparison, setComparison] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedTools, setExpandedTools] = useState({});
  const [showMoreItems, setShowMoreItems] = useState({});
  const location = useLocation();
  const navigate = useNavigate();

  const { oldScanId, newScanId } = location.state || {};

  useEffect(() => {
    if (!oldScanId || !newScanId) {
      navigate("/delta");
      return;
    }

    /**
     * Set of an API Call to await the comparing data of the of the entered Scans  
     */
    const fetchComparison = async () => {
      setLoading(true);
      try {

        const response = await fetch("http://localhost:5001/api/delta/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            old_scan_id: oldScanId,
            new_scan_id: newScanId,
          }),
        });

        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(`Server error: ${response.status} - ${errorText}`);
        }

        const data = await response.json();
        console.log("Comparison data received:", data);
        setComparison(data);
      } catch (err) {
        console.error("Error fetching comparison:", err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchComparison();
  }, [oldScanId, newScanId, navigate]);

  const handleNewComparison = () => {
    navigate("/delta");
  };

  const toggleToolExpansion = (toolId) => {
    setExpandedTools(prev => ({
      ...prev,
      [toolId]: !prev[toolId]
    }));
  };

  const toggleShowMore = (toolId, section, e) => {
    e.stopPropagation();
    const key = `${toolId}-${section}`;
    setShowMoreItems(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  // Format item for display - shows only real data
  const formatItem = (tool, item, detailed = false) => {
    if (!item || typeof item !== 'object') {
      return {
        title: "Scan Data",
        details: "Information collected",
        fullDetails: "Data point recorded"
      };
    }

    const entries = Object.entries(item);
    if (entries.length === 0) {
      return {
        title: "Scan Entry",
        details: "Data point recorded",
        fullDetails: "Entry logged in scan results"
      };
    }

    // For detailed view, show everything
    if (detailed) {
      const details = entries
        .filter(([key, value]) => value !== null && value !== undefined && value !== "")
        .map(([key, value]) => `${key}: ${value}`)
        .join('\n');

      return {
        title: getToolName(tool),
        details: details || "No details",
        fullDetails: details || "No detailed information available"
      };
    }

    // Regular view - show meaningful summary
    switch (tool) {
      case "harvester":
        if (item.type === 'email' && item.value) {
          return {
            title: "📧 Email",
            details: item.value,
            fullDetails: `Email: ${item.value}\n${item.explanation || 'Discovered via OSINT'}`
          };
        }
        if (item.type === 'host' && item.value) {
          return {
            title: "🌐 Host",
            details: item.value,
            fullDetails: `Host: ${item.value}\n${item.explanation || 'Discovered via OSINT'}`
          };
        }
        if (item.type === 'ip' && item.value) {
          return {
            title: "🔢 IP Address",
            details: item.value,
            fullDetails: `IP: ${item.value}\n${item.explanation || 'Discovered via OSINT'}`
          };
        }
        if (item.type === 'summary' && item.value) {
          const [type, count] = item.value.split(':');
          return {
            title: `📊 ${type.charAt(0).toUpperCase() + type.slice(1)}`,
            details: `${count} found`,
            fullDetails: `${item.explanation || 'OSINT summary'}`
          };
        }
        return {
          title: "🕵️ OSINT Data",
          details: item.explanation || "Reconnaissance data",
          fullDetails: JSON.stringify(item, null, 2)
        };

      case "whatweb":
        if (item.explanation && item.explanation !== "WhatWeb: -") {
          // Extract meaningful parts from explanation
          const explanation = item.explanation.replace("WhatWeb: ", "");
          const parts = explanation.split(" | ");

          let title = "🌐 Web Server";
          let details = "";

          if (parts[0] && parts[0] !== "Web technology scan") {
            title = parts[0];
            if (parts.length > 1) {
              details = parts.slice(1).join(" | ");
            }
          } else {
            details = "Web technology scan completed";
          }

          return {
            title: title,
            details: details || "Technology detected",
            fullDetails: item.explanation
          };
        }
        return {
          title: "🌐 Web Technology",
          details: "Scan completed",
          fullDetails: "WhatWeb scan executed - web technologies analyzed"
        };

      case "nmap":
        if (item.explanation) {
          return {
            title: item.service ? `🔍 ${item.service}` : "🔍 Port Scan",
            details: item.explanation.replace(/Port \d+\/\w+: /, ""),
            fullDetails: `Port: ${item.port}\nService: ${item.service || ''}\nProtocol: ${item.protocol}\n${item.explanation}`
          };
        }
        return {
          title: "🔍 Network Scan",
          details: `Port ${item.port} detected`,
          fullDetails: JSON.stringify(item, null, 2)
        };

      case "nikto":
        if (item.explanation) {
          const riskMatch = item.explanation.match(/High risk|Medium risk|Low risk|No security issues/);
          const risk = riskMatch ? riskMatch[0] : "Security scan";

          return {
            title: `⚠️ ${item.host || 'Target'}:${item.port || '80'}`,
            details: risk,
            fullDetails: item.explanation
          };
        }
        return {
          title: "⚠️ Vulnerability Scan",
          details: "Security assessment completed",
          fullDetails: JSON.stringify(item, null, 2)
        };

      case "zap":
        if (item.explanation) {
          const alertMatch = item.explanation.match(/High alerts|Medium alerts|Low alerts|Info alerts|No alerts/);
          const alerts = alertMatch ? alertMatch[0] : "Security scan";

          return {
            title: "🛡️ Security Scan",
            details: alerts,
            fullDetails: item.explanation
          };
        }
        return {
          title: "🛡️ OWASP ZAP",
          details: "Web app security tested",
          fullDetails: JSON.stringify(item, null, 2)
        };

      case "cve":
        if (item.cve) {
          return {
            title: `💀 ${item.cve}`,
            details: "Security vulnerability",
            fullDetails: item.explanation || `CVE: ${item.cve}`
          };
        }
        return {
          title: "💀 CVE Database",
          details: "Vulnerability check",
          fullDetails: JSON.stringify(item, null, 2)
        };

      default:
        // Show first meaningful field
        const firstEntry = entries.find(([key, value]) =>
          value !== null && value !== undefined && value !== "" &&
          !['explanation', 'type'].includes(key)
        );

        if (firstEntry) {
          const [key, value] = firstEntry;
          return {
            title: key.charAt(0).toUpperCase() + key.slice(1),
            details: String(value),
            fullDetails: entries.map(([k, v]) => `${k}: ${v}`).join('\n')
          };
        }

        // Fallback to explanation
        if (item.explanation) {
          return {
            title: getToolName(tool),
            details: item.explanation,
            fullDetails: item.explanation
          };
        }

        return {
          title: getToolName(tool),
          details: "Scan data collected",
          fullDetails: JSON.stringify(item, null, 2)
        };
    }
  };

  // Get tool icon
  const getToolIcon = (tool) => {
    const icons = {
      harvester: "🕵️",
      whatweb: "🌐",
      nmap: "🔍",
      nikto: "⚠️",
      zap: "🛡️",
      cve: "💀",
    };
    return icons[tool] || "📊";
  };

  // Get tool display name
  const getToolName = (tool) => {
    const names = {
      harvester: "Harvester",
      whatweb: "WhatWeb",
      nmap: "Nmap",
      nikto: "Nikto",
      zap: "OWASP ZAP",
      cve: "CVE Database",
    };
    return names[tool] || tool;
  };

  // Check if items contain real data
  const hasRealData = (items) => {
    if (!items || !Array.isArray(items)) return false;
    return items.length > 0;
  };

  // Count real items
  const countRealItems = (items) => {
    if (!items || !Array.isArray(items)) return 0;
    return items.length;
  };

  // Render findings list
  const renderFindings = (tool, items, type, showAll = false) => {
    if (!hasRealData(items)) {
      return <div className="no-findings">Scan executed - no specific findings</div>;
    }

    const displayItems = showAll ? items : items.slice(0, 3);
    const showMoreBtn = items.length > 3 && !showAll;

    return (
      <>
        <div className="findings-list">
          {displayItems.map((item, idx) => {
            const formatted = formatItem(tool, item);
            return (
              <div key={idx} className={`finding-item ${type}`}>
                <div className="finding-title">{formatted.title}</div>
                <div className="finding-details">{formatted.details}</div>
              </div>
            );
          })}
        </div>
        {showMoreBtn && (
          <div
            className="more-items"
            onClick={(e) => toggleShowMore(tool, `${type}-summary`, e)}
          >
            <span>Show {items.length - 3} more items</span>
            <span>▼</span>
          </div>
        )}
      </>
    );
  };

  // Render detailed findings
  const renderDetailedFindings = (tool, items, type, title) => {
    if (!hasRealData(items)) {
      return null;
    }

    return (
      <div className="detailed-section">
        <div className="detailed-section-title">{title} ({items.length} items)</div>
        <div className="detailed-list">
          {items.map((item, idx) => {
            const formatted = formatItem(tool, item, true);
            return (
              <div key={idx} className={`detailed-item ${type}`}>
                <div style={{ whiteSpace: 'pre-line', fontFamily: 'monospace', fontSize: '12px' }}>
                  {formatted.fullDetails}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  if (loading) {
    return (
      <div className="delta-page">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <div>Analyzing scan differences...</div>
          <p style={{color: '#a0a0d8', fontSize: '14px', marginTop: '12px'}}>
            Comparing Scan ID: {oldScanId} with Scan ID: {newScanId}
          </p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="delta-page">
        <div className="error-container">
          <h3>Error Loading Results</h3>
          <p>{error}</p>
          <p style={{color: '#a0a0d8', fontSize: '14px', marginTop: '12px'}}>
            Please check if both scans exist and have data.
          </p>
          <button onClick={handleNewComparison} className="back-button">
            ← Back to Comparison
          </button>
        </div>
      </div>
    );
  }

  if (!comparison || !comparison.delta) {
    return (
      <div className="delta-page">
        <div className="error-container">
          <h3>No Comparison Data</h3>
          <p>Unable to load comparison results.</p>
          <p style={{color: '#a0a0d8', fontSize: '14px', marginTop: '12px'}}>
            Make sure both scans have been completed.
          </p>
          <button onClick={handleNewComparison} className="back-button">
            ← Back to Comparison
          </button>
        </div>
      </div>
    );
  }

  const tools = ["harvester", "whatweb", "nmap", "nikto", "zap", "cve"];
  const targetUrl = comparison.scan_info?.old_target || comparison.old_target || 'Target URL';

  return (
    <div className="delta-page">
      <Header />

      {/* HEADER WITH PROPER SPACING */}
      <div className="delta-header">
        <h1 className="delta-title">ΔDelta Scan</h1>
        <p className="delta-subtitle">Security scan comparison results</p>
      </div>

      {/* Target URL */}
      <div className="target-display">
        <h2>Target URL</h2>
        <div className="target-url">{targetUrl}</div>
      </div>

      {/* Scan IDs */}
      <div className="scan-comparison-bar">
        <div className="scan-id-badge old">
          <div className="scan-id-label">Previous Scan</div>
          <div className="scan-id-number">ID: {oldScanId}</div>
        </div>

        <div className="compare-arrow">→</div>

        <div className="scan-id-badge new">
          <div className="scan-id-label">Current Scan</div>
          <div className="scan-id-number">ID: {newScanId}</div>
        </div>
      </div>

      {/* Tools Comparison */}
      <div className="tools-comparison-grid">
        {tools.map((tool) => {
          const toolData = comparison.delta?.[tool];

          // Handle missing tool data
          if (!toolData) {
            return (
              <div key={tool} className="tool-comparison-card">
                <div className="tool-header">
                  <div className="tool-icon">{getToolIcon(tool)}</div>
                  <h3 className="tool-name">{getToolName(tool)}</h3>
                  <div className="tool-stats">
                    <span className="stat-count" style={{background: 'rgba(108, 99, 255, 0.2)', color: '#6c63ff'}}>
                      No Data
                    </span>
                  </div>
                </div>
                <div className="comparison-columns">
                  <div className="comparison-section old">
                    <div className="section-header">
                      <h4 className="section-title old">Previous</h4>
                      <span className="section-count">0</span>
                    </div>
                    <div className="no-findings">Tool not executed</div>
                  </div>
                  <div className="comparison-section new">
                    <div className="section-header">
                      <h4 className="section-title new">Current</h4>
                      <span className="section-count">0</span>
                    </div>
                    <div className="no-findings">Tool not executed</div>
                  </div>
                </div>
              </div>
            );
          }

          const oldRealCount = countRealItems(toolData.old_scan);
          const newRealCount = countRealItems(toolData.new_scan);
          const addedRealCount = countRealItems(toolData.added);
          const removedRealCount = countRealItems(toolData.removed);

          const isExpanded = expandedTools[tool] || false;
          const showMoreOld = showMoreItems[`${tool}-old-summary`] || false;
          const showMoreNew = showMoreItems[`${tool}-new-summary`] || false;

          const hasOldData = oldRealCount > 0;
          const hasNewData = newRealCount > 0;

          return (
            <div key={tool} className="tool-comparison-card">
              {/* Tool Header */}
              <div
                className="tool-header"
                onClick={() => toggleToolExpansion(tool)}
              >
                <div className="tool-icon">{getToolIcon(tool)}</div>
                <h3 className="tool-name">{getToolName(tool)}</h3>
                <div className="tool-stats">
                  {addedRealCount > 0 && (
                    <span className="stat-count added">+{addedRealCount}</span>
                  )}
                  {removedRealCount > 0 && (
                    <span className="stat-count removed">-{removedRealCount}</span>
                  )}
                  {addedRealCount === 0 && removedRealCount === 0 && (hasOldData || hasNewData) && (
                    <span className="stat-count" style={{background: 'rgba(108, 99, 255, 0.2)', color: '#6c63ff'}}>
                      No Changes
                    </span>
                  )}
                </div>
                {(hasOldData || hasNewData) && (
                  <div className={`expand-icon ${isExpanded ? 'expanded' : ''}`}>
                    ▼
                  </div>
                )}
              </div>

              {/* Basic Comparison View */}
              <div className="comparison-columns">
                <div className="comparison-section old">
                  <div className="section-header">
                    <h4 className="section-title old">Previous</h4>
                    <span className="section-count">{oldRealCount}</span>
                  </div>
                  {renderFindings(tool, toolData.old_scan, "old", showMoreOld)}
                </div>

                <div className="comparison-section new">
                  <div className="section-header">
                    <h4 className="section-title new">Current</h4>
                    <span className="section-count">{newRealCount}</span>
                  </div>
                  {renderFindings(tool, toolData.new_scan, "new", showMoreNew)}
                </div>
              </div>

              {/* Expanded Detailed View */}
              {isExpanded && (
                <div className="expanded-view">
                  {hasOldData && renderDetailedFindings(tool, toolData.old_scan, "old", "Previous Scan Details")}
                  {hasNewData && renderDetailedFindings(tool, toolData.new_scan, "new", "Current Scan Details")}
                  {addedRealCount > 0 && renderDetailedFindings(tool, toolData.added, "new", "Newly Added Items")}
                  {removedRealCount > 0 && renderDetailedFindings(tool, toolData.removed, "old", "Removed Items")}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Back Button */}
      <div className="back-button-container">
        <button onClick={handleNewComparison} className="back-button">
          ← New Comparison
        </button>
      </div>
    </div>
  );
}