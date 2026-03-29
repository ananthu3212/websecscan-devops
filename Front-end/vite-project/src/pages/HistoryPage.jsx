import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/authProvider";
import "./HistoryPage.css";

/**
 * The page which loads the Last Scans of the User and Sorts them by Date 
 * The User can Filter the entries and currently running scans are also visible
 * @returns An JSX Element containing the History Page  
 */
export default function HistoryPage() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const { logIn } = useAuth();

  // Filter states
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [sortBy, setSortBy] = useState("date_desc");

  useEffect(() => {
    fetchScanHistory();
  }, []);

  /**
   * Set of an API Call to await the last Scans of the User 
   */
  const fetchScanHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch("http://localhost:5001/api/history", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          'Authorization': 'Bearer ' + logIn,
        },
        body: JSON.stringify({ limit: 100 })
      });

      if (!response.ok) {
        throw new Error(`Server error: ${response.status}`);
      }

      const data = await response.json();

      if (data.status === "ok" && data.items) {
        setScans(data.items);
      } else {
        setScans([]);
      }
    } catch (err) {
      console.error("Error fetching history:", err);
      setError(`Error loading scan history: ${err.message}`);
      setScans([]);
    } finally {
      setLoading(false);
    }
  };

  // Normalize status for consistent comparison
  const normalizeStatus = (status) => {
    if (!status) return "running";
    const s = status.toLowerCase();
    if (s.includes("success") || s.includes("completed") || s === "ok") return "completed";
    if (s.includes("fail")) return "failed";
    if (s.includes("run")) return "running";
    return s;
  };

  // Calculate statistics
  const stats = {
    total: scans.length,
    completed: scans.filter(s => normalizeStatus(s.status) === "completed").length,
    failed: scans.filter(s => normalizeStatus(s.status) === "failed").length,
    running: scans.filter(s => normalizeStatus(s.status) === "running").length
  };

  // Filter and sort scans (exclude failed scans)
  const filteredScans = scans
    .filter(scan => {
      // Skip failed scans
      if (normalizeStatus(scan.status) === "failed") return false;

      // Search filter
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        const matchesSearch =
          scan.target?.toLowerCase().includes(term) ||
          scan.id?.toString().includes(term) ||
          normalizeStatus(scan.status).includes(term);
        if (!matchesSearch) return false;
      }

      // Status filter
      if (statusFilter !== "all") {
        if (normalizeStatus(scan.status) !== statusFilter.toLowerCase()) {
          return false;
        }
      }

      return true;
    })
    .sort((a, b) => {
      if (sortBy === "date_asc") {
        return new Date(a.created_at || a.started_at) - new Date(b.created_at || b.started_at);
      } else if (sortBy === "status") {
        return normalizeStatus(a.status).localeCompare(normalizeStatus(b.status));
      }
      return new Date(b.created_at || b.started_at) - new Date(a.created_at || a.started_at);
    });

  const handleScanClick = (scanId) => {
    navigate(`/report?scanId=${scanId}`);
  };

  const formatDate = (dateString) => {
    if (!dateString) return "N/A";
    try {
      const date = new Date(dateString);
      return date.toLocaleDateString('en-GB', {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch {
      return "N/A";
    }
  };

  // Format status for display
  const formatStatus = (status) => {
    if (!status) return "Running";
    const normalized = normalizeStatus(status);
    if (normalized === "completed") return "Success";
    if (normalized === "failed") return "Failed";
    if (normalized === "running") return "Running";
    return status.charAt(0).toUpperCase() + status.slice(1).toLowerCase();
  };

  const handleResetFilters = () => {
    setSearchTerm("");
    setStatusFilter("all");
    setSortBy("date_desc");
  };

  const handleRunScan = () => {
    navigate("/");
  };

  if (loading) {
    return (
      <div className="history-page">
        <div className="hero-section">
          <h1 className="history-title">Scan <span className="accent">History</span></h1>
          <p className="history-subtitle">View and manage all your security scan results</p>
        </div>
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <div>Loading scan history...</div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="history-page">
        <div className="hero-section">
          <h1 className="history-title">Scan <span className="accent">History</span></h1>
          <p className="history-subtitle">View and manage all your security scan results</p>
        </div>
        <div className="error-container">
          <div className="error-title">Failed to Load History</div>
          <div className="error-description">{error}</div>
          <button onClick={fetchScanHistory} className="scan-btn" style={{ marginTop: "20px" }}>
            Try Again
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="history-page">
      {/* Hero Section */}
      <div className="hero-section">
        <h1 className="history-title">Scan <span className="accent">History</span></h1>
        <p className="history-subtitle">View and manage all your security scan results</p>
      </div>

      {/* Statistics Row - 3 CARDS ONLY */}
      <div className="stats-row">
        <div className="stat-card">
          <div className="stat-number">{stats.total}</div>
          <div className="stat-label">Total Scans</div>
        </div>
        <div className="stat-card">
          <div className="stat-number">{stats.completed}</div>
          <div className="stat-label">Completed</div>
        </div>
        <div className="stat-card">
          <div className="stat-number">{stats.running}</div>
          <div className="stat-label">Running</div>
        </div>
        {/* Removed Failed stat card */}
      </div>

      <div className="history-container">
        {/* Filter Section */}
        <div className="filter-section">
          <div className="filter-header">
            <div className="filter-title">Filter & Sort</div>
          </div>

          <div className="filter-grid">
            {/* Search - NORMAL WIDTH */}
            <div className="filter-group search-group">
              <label className="filter-label">Search</label>
              <div className="search-input-wrapper">
                <div className="search-icon">🔍</div>
                <input
                  type="text"
                  placeholder="Search scans..."
                  className="search-input"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
            </div>

            {/* Status and Sort in one row */}
            <div className="filter-row">
              {/* Status Filter */}
              <div className="filter-group">
                <label className="filter-label">Status</label>
                <div className="status-buttons">
                  <button
                    className={`status-btn ${statusFilter === "all" ? "active" : ""}`}
                    onClick={() => setStatusFilter("all")}
                  >
                    All
                  </button>
                  <button
                    className={`status-btn ${statusFilter === "completed" ? "active" : ""}`}
                    onClick={() => setStatusFilter("completed")}
                  >
                    Completed
                  </button>
                  <button
                    className={`status-btn ${statusFilter === "running" ? "active" : ""}`}
                    onClick={() => setStatusFilter("running")}
                  >
                    Running
                  </button>
                </div>
              </div>

              {/* Sort Filter */}
              <div className="filter-group">
                <label className="filter-label">Sort By</label>
                <select
                  className="sort-select"
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value)}
                >
                  <option value="date_desc">Newest First</option>
                  <option value="date_asc">Oldest First</option>
                  <option value="status">By Status</option>
                </select>
              </div>
            </div>
          </div>

          <div className="filter-actions">
            <button
              className="reset-btn"
              onClick={handleResetFilters}
            >
              Clear Filters
            </button>
          </div>
        </div>

        {/* Results Summary */}
        <div className="results-summary">
          <div>
            Showing <strong>{filteredScans.length}</strong> of <strong>{scans.length}</strong> scans
          </div>
          <div>
            {searchTerm && `Search: "${searchTerm}"`}
            {searchTerm && statusFilter !== "all" && " • "}
            {statusFilter !== "all" && `Status: ${statusFilter}`}
          </div>
        </div>

        {/* Table or Empty State */}
        {filteredScans.length > 0 ? (
          <div className="table-container">
            <table className="scan-table">
              <thead>
                <tr>
                  <th>NO.</th>
                  <th>SCAN ID</th>
                  <th>TARGET URL</th>
                  <th>DATE & TIME</th>
                  <th>STATUS</th>
                  <th>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((scan, index) => (
                  <tr key={scan.id || index}>
                    <td className="scan-index">{index + 1}</td>
                    <td className="scan-id">#{scan.id}</td>
                    <td className="scan-url" title={scan.target}>
                      {scan.target || "N/A"}
                    </td>
                    <td className="scan-date">
                      {formatDate(scan.created_at || scan.started_at)}
                    </td>
                    <td>
                      <span className={`status-badge ${normalizeStatus(scan.status)}`}>
                        {formatStatus(scan.status)}
                      </span>
                    </td>
                    <td>
                      <button
                        onClick={() => handleScanClick(scan.id)}
                        className="view-btn"
                      >
                        View Report
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-state-icon">📊</div>
            <div className="empty-state-title">
              {scans.length === 0 ? "No Scans Yet" : "No Results Found"}
            </div>
            <div className="empty-state-description">
              {scans.length === 0
                ? "You haven't run any security scans yet. Start by scanning a target URL."
                : "No scans match your current filters. Try adjusting your search or filter criteria."}
            </div>
            {scans.length === 0 ? (
              <button onClick={handleRunScan} className="scan-btn">
                Run First Scan
              </button>
            ) : (
              <button onClick={handleResetFilters} className="scan-btn">
                Clear All Filters
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}