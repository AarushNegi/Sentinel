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
import Learn from './pages/Learn'
import ComingSoon from './pages/ComingSoon'
import Simulation from './pages/Simulation'
import RedPhishingSimulation from './pages/RedPhishingSimulation'
import BluePhishingSimulation from './pages/BluePhishingSimulation'
import RedRansomwareSimulation from './pages/RedRansomwareSimulation'
import BlueRansomwareSimulation from './pages/BlueRansomwareSimulation'
import BlueSupplyChainSimulation from './pages/BlueSupplyChainSimulation'
import RedSupplyChainSimulation from './pages/RedSupplyChainSimulation'

const ProtectedRoute = ({ children }) => {
  const token = localStorage.getItem('token')
  return token ? children : <Navigate to="/login" replace />
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
      <Route path="/simulation" element={<Simulation />} />
      <Route path="/red-phishing" element={<RedPhishingSimulation />} />
      <Route path="/blue-phishing" element={<BluePhishingSimulation />} />
      <Route path="/red-ransomware" element={<RedRansomwareSimulation />} />
      <Route path="/blue-ransomware" element={<BlueRansomwareSimulation />} />
      <Route path="/red-supply-chain" element={<RedSupplyChainSimulation />} />
      <Route path="/blue-supply-chain" element={<BlueSupplyChainSimulation />} />
      <Route path="/soc-simulator" element={<SOCSimulator />} />
      <Route path="/outcome" element={<Outcome />} />
      <Route path="/coming-soon/:slug" element={<ComingSoon />} />
      <Route path="/learn" element={<Learn />} />
      <Route path="/learn/:slug" element={<Learn />} />
      <Route path="/dashboard" element={
        <ProtectedRoute>
          <Dashboard />
        </ProtectedRoute>
      } />
      {/* Catch all */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default App