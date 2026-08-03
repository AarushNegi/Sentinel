import { Routes, Route, Navigate } from 'react-router-dom'
import Register from './pages/Register'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import ModeSelect from './pages/ModeSelect'
import AttackSelect from './pages/AttackSelect'
import Guide from './pages/Guide'
import AlertQueue from './pages/AlertQueue'
import Landing from './pages/Landing'
import SOCSimulator from './pages/SOCSimulator'
import Outcome from './pages/Outcome'

const ProtectedRoute = ({ children }) => {
  const token = localStorage.getItem('token')
  return token ? children : <Navigate to="/login" />
}

function App() {
  return (
    <Routes>
      <Route path="/"          element={<Landing />} />
      <Route path="/register"  element={<Register />} />
      <Route path="/login"     element={<Login />} />
      <Route path="/mode-select" element={<ModeSelect />} />
      <Route path="/attack-select" element={<AttackSelect />} />
      <Route path="/guide" element={<Guide />} />
      <Route path="/alert-queue" element={<AlertQueue />} />
      <Route path="/simulation" element={<AlertQueue />} />
      <Route path="/soc-simulator" element={<SOCSimulator />} />
      <Route path="/outcome" element={<Outcome />} />
      <Route path="/dashboard" element={
        <ProtectedRoute>
          <Dashboard />
        </ProtectedRoute>
      } />
      {/* Catch all */}
      <Route path="*" element={<Navigate to="/" />} />
    </Routes>
  )
}

export default App