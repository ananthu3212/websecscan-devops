import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./DeltaScanPage.css";

/**
 * The Pape to Initiate the Compairing of two Scans the User made in the Past
 * @returns An JSX Element containig a Simple Form
 */
export default function DeltaScanPage() {
  const [oldId, setOldId] = useState("");
  const [newId, setNewId] = useState("");
  const navigate = useNavigate();

  /**
   * Navigate the User to the result Page after the ID's where entered
   * @param {*} e containing the Form Data
   * @returns an alert if entry is faulty
   */
  const handleCompare = (e) => {
    e.preventDefault();

    if (!oldId || !newId) {
      alert("Please enter both Scan IDs");
      return;
    }

    // Navigate to results page with the scan IDs
    navigate("/delta-result", {
      state: {
        oldScanId: oldId,
        newScanId: newId
      }
    });
  };

  return (
    <div className="delta-page">


      <h1 className="delta-title">ΔDelta Scan</h1>

      <form onSubmit={handleCompare} className="delta-inputs">
        <label>Old Scan ID:</label>
        <input
          type="text"
          value={oldId}
          onChange={(e) => setOldId(e.target.value)}
          placeholder="Enter old scan ID"
        />

        <label>New Scan ID:</label>
        <input
          type="text"
          value={newId}
          onChange={(e) => setNewId(e.target.value)}
          placeholder="Enter new scan ID"
        />

        <button type="submit">
          Compare
        </button>
      </form>
    </div>
  );
}