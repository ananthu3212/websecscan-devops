import React from "react";
import { Routes, Route, useLocation, Navigate } from "react-router-dom";

import { ScanProvider } from "./context/ScanContext";
import AuthProvider, { useAuth } from "./context/authProvider";

import AppPage from "./pages/AppPage";
import ReportPage from "./pages/ReportPage";
import Aboutpage from "./pages/Aboutpage";
import HistoryPage from "./pages/HistoryPage";
import DeltaScanPage from "./pages/DeltaScanPage";
import DeltaResultPage from "./pages/DeltaResultPage";
import ProfilePage from "./pages/ProfilePage";

import Header from "./components/Header/Header";
import "./App.css";



/**
 * The Main Element containig the Routes and Contexts of the Application
 * @returns The Central JSX Element 
 */
function App() {
  return (
      <AuthProvider>
        <ScanProvider>

          <Header />
            <div className="main-content">
              <Routes>
                  <Route path="/" element={<AppPage />} />
                  <Route path="/report" element={<ReportPage />} />
                  <Route path="/about" element={<Aboutpage />} />
                  <Route path="/history" element={<RequireAuth> <HistoryPage /> </RequireAuth>} />
                  <Route path="/profile" element={<RequireAuth> <ProfilePage /></RequireAuth>} />

                  {/* Delta input page */}
                  <Route path="/delta" element={<RequireAuth> <DeltaScanPage /></RequireAuth>} />

                  {/* Delta result page */}
                  <Route path="/delta-result" element={<DeltaResultPage />} />

              </Routes>
            </div>
        </ScanProvider>
      </AuthProvider>
  );
}

/**
 * Check if the User is Authenticated to validate the Routing request
 * @param {*} param0 
 * @returns the right JSX Elemet based on the check
 */
function RequireAuth({ children }) {
  const {logIn} = useAuth();
  let location = useLocation();

  if (!logIn) {
    // Redirect them to the /login page, but save the current location they were
    // trying to go to when they were redirected. This allows us to send them
    // along to that page after they login, which is a nicer user experience
    // than dropping them off on the home page.
    return <Navigate to="/" state={{ from: location }} replace />;
  }

  return children;
}

export default App;
