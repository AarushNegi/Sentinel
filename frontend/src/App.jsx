import { Routes, Route, Navigate } from 'react-router-dom'
import Register from './pages/Register'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import ModeSelect from './pages/ModeSelect'
import AttackSelect from './pages/AttackSelect'
import Guide from './pages/Guide'

// Protected route — redirects to login if no token
const ProtectedRoute = ({ children }) => {
  const token = localStorage.getItem('token')
  return token ? children : <Navigate to="/login" />
}

function App() {
  return (
    <Routes>
      <Route path="/"          element={<Register />} />
      <Route path="/register"  element={<Register />} />
      <Route path="/login"     element={<Login />} />
      <Route path="/mode-select" element={<ModeSelect />} />
      <Route path="/attack-select" element={<AttackSelect />} />
      <Route path="/guide" element={<Guide />} />
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