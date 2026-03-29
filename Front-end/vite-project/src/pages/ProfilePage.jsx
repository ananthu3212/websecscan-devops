import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { getProfile } from "../api/authApiService.jsx";
import { useAuth } from "../context/authProvider.jsx";
import "./ProfilePage.css";

// Componet to visualize the Profile 
const ProfileInfoCard = ({ label, value, icon }) => (
  <div className="profile-info-card">
    <div className="profile-info-icon">{icon}</div>
    <div className="profile-info-content">
      <span className="profile-info-label">{label}</span>
      <span className="profile-info-value">{value}</span>
    </div>
  </div>
);

// Stat Card Component
const StatCard = ({ title, value, icon }) => (
  <div className="stat-card">
    <div className="stat-icon">{icon}</div>
    <div className="stat-content">
      <div className="stat-title">{title}</div>
      <div className="stat-value">{value}</div>
    </div>
  </div>
);

/**
 * The Page to Show the Information about the User and other Statistcs
 * @returns A JSX Element containing the User Profile
 */
export default function ProfilePage() {
  const { logIn } = useAuth();
  const navigate = useNavigate();

  const [profile, setProfile] = useState(null);
  const [scanStats, setScanStats] = useState({ total: 0, lastScan: null });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Fetch profile data
  useEffect(() => {
    const fetchProfileData = async () => {
      try {
        setLoading(true);
        if (!logIn) {
          throw new Error("Authentication required");
        }

        // Fetch user profile
        const userData = await getProfile(logIn);
        setProfile(userData);

        // Fetch user's scan history to get actual stats
        await fetchUserScanStats();

      } catch (err) {
        setError("Unable to load profile data. Please try again.");
      } finally {
        setLoading(false);
      }
    };

    fetchProfileData();
  }, [logIn]);

  // Fetch user's actual scan statistics
  const fetchUserScanStats = async () => {
    try {
      const response = await fetch("/api/history", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          'Authorization': 'Bearer ' + logIn,
        },
        body: JSON.stringify({ limit: 100 })
      });

      if (response.ok) {
        const data = await response.json();

        if (data.status === "ok" && data.items) {
          const scans = data.items;

          // Calculate statistics
          const total = scans.length;
          let lastScan = null;

          if (scans.length > 0) {
            // Find the most recent scan
            const sortedScans = [...scans].sort((a, b) => {
              const dateA = new Date(a.created_at || a.started_at || 0);
              const dateB = new Date(b.created_at || b.started_at || 0);
              return dateB - dateA;
            });

            lastScan = sortedScans[0].created_at || sortedScans[0].started_at;
          }

          setScanStats({
            total: total,
            lastScan: lastScan
          });
        } else {
          // No scans found for this user
          setScanStats({
            total: 0,
            lastScan: null
          });
        }
      } else {
        console.error("Failed to fetch scan history");
        setScanStats({
          total: 0,
          lastScan: null
        });
      }
    } catch (err) {
      console.error("Error fetching scan stats:", err);
      setScanStats({
        total: 0,
        lastScan: null
      });
    }
  };

  // Format date to a very readable format
  const formatDateTime = (dateString) => {
    if (!dateString) return "Not Available";

    try {
      let date;

      if (dateString instanceof Date) {
        date = dateString;
      } else if (!isNaN(dateString)) {
        date = new Date(parseInt(dateString));
      } else if (dateString.includes('T')) {
        date = new Date(dateString);
      } else {
        date = new Date(dateString);
      }

      if (isNaN(date.getTime())) {
        const parts = dateString.split(/[-/]/);
        if (parts.length === 3) {
          date = new Date(parts[0], parts[1] - 1, parts[2]);
        }
      }

      if (isNaN(date.getTime())) {
        return "Invalid date";
      }

      // Format: "December 21, 2025 at 10:33 PM"
      const formattedDate = date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      });

      const formattedTime = date.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        hour12: true
      });

      return `${formattedDate} at ${formattedTime}`;

    } catch (error) {
      console.error("Date formatting error:", error);
      return "Invalid date";
    }
  };

  // Format stats value for display
  const formatStatsValue = (type, value) => {
    if (type === 'total') {
      return value.toString(); // Return as string for display
    } else if (type === 'lastScan') {
      if (!value) return "No scans yet";
      return formatDateTime(value);
    }
    return value;
  };

  // Loading state
  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Loading your profile...</p>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="error-container">
        <div className="error-icon">⚠️</div>
        <h3>Error Loading Profile</h3>
        <div className="error-message">{error}</div>
        <button
          className="retry-button"
          onClick={() => window.location.reload()}
        >
          Retry
        </button>
      </div>
    );
  }

  // Get avatar initial
  const getAvatarInitial = () => {
    if (profile?.avatar) return String(profile.avatar);
    if (profile?.fullName) return String(profile.fullName.charAt(0));
    if (profile?.name) return String(profile.name.charAt(0));
    if (profile?.username) return String(profile.username.charAt(0));
    return "U";
  };

  // Get display name
  const getDisplayName = () => {
    if (profile?.fullName) return profile.fullName;
    if (profile?.name) return profile.name;
    if (profile?.username) return profile.username;
    return "User";
  };

  // Field configuration - KEEP ALL FIELDS except username
  const profileFieldConfig = {
    email: { label: "Email Address", icon: "✉️" },
    fullName: { label: "Full Name", icon: "📝" },
    name: { label: "Name", icon: "📝" },
    role: { label: "Account Type", icon: "👑" },
    status: { label: "Account Status", icon: "✅" },
    createdAt: { label: "Account Created", icon: "📅" },
    joinDate: { label: "Member Since", icon: "📅" },
    confirmed_at: { label: "Confirmed At", icon: "✅" },
    updatedAt: { label: "Last Updated", icon: "🔄" },
    lastLogin: { label: "Last Login", icon: "🔐" },
    subscription: { label: "Subscription", icon: "💎" },
    phone: { label: "Phone Number", icon: "📱" },
    location: { label: "Location", icon: "📍" }
  };

  // Get display fields from profile - EXCLUDE username
  const getDisplayFields = () => {
    const excluded = ['_id', 'id', 'password', 'token', '__v', 'avatar', 'username'];
    return Object.entries(profile || {})
      .filter(([key]) => !excluded.includes(key))
      .map(([key, value]) => {
        let displayValue = value || "Not set";

        // Special handling for dates - use the new readable format
        // Include confirmed_at in date fields
        if (key.toLowerCase().includes('date') ||
            key.toLowerCase().includes('created') ||
            key.toLowerCase().includes('updated') ||
            key.toLowerCase().includes('login') ||
            key === 'confirmed_at' ||
            key === 'joinDate') {
          displayValue = formatDateTime(value);
        }

        return {
          key,
          value: String(displayValue),
          label: profileFieldConfig[key]?.label || key.charAt(0).toUpperCase() + key.slice(1),
          icon: profileFieldConfig[key]?.icon || "📋"
        };
      });
  };

  const displayFields = getDisplayFields();

  return (
    <div className="profile-container">
      {/* Header Section */}
      <div className="profile-header-section">
        <div className="profile-avatar">
          {getAvatarInitial()}
        </div>
        <div className="profile-header-content">
          <h1>{getDisplayName()}</h1>
          <div className="profile-status">
            <span className={`status-badge ${profile?.status?.toLowerCase() || 'active'}`}>
              {String(profile?.status || "Active")}
            </span>
          </div>
        </div>
      </div>

      {/* Stats Section - Dynamic data from user's scan history */}
      <div className="stats-section">
        <div className="stats-grid">
          <StatCard
            title="Total Scans"
            value={formatStatsValue('total', scanStats.total)}
            icon="🔍"
          />
          <StatCard
            title="Last Scan"
            value={formatStatsValue('lastScan', scanStats.lastScan)}
            icon="📅"
          />
        </div>
      </div>

      {/* Account Information Section */}
      <div className="account-info-section">
        <h2>Account Information</h2>
        <div className="account-info-grid">
          {displayFields.map((field) => (
            <ProfileInfoCard
              key={field.key}
              label={field.label}
              value={field.value}
              icon={field.icon}
            />
          ))}
        </div>
      </div>

      {/* Quick Actions */}
      <div className="quick-actions">
        <button
          className="action-button primary"
          onClick={() => navigate("/")}
        >
          <span className="action-icon">🚀</span>
          <span className="action-text">Start New Scan</span>
        </button>
        <button
          className="action-button secondary"
          onClick={() => navigate("/history")}
        >
          <span className="action-icon">📋</span>
          <span className="action-text">View History</span>
        </button>
      </div>
    </div>
  );
}