import axios from 'axios'

const API = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5000'
})

API.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Auth
export const registerUser = (data) => API.post('/api/auth/register', data)
export const loginUser    = (data) => API.post('/api/auth/login', data)
export const guestLogin   = ()     => API.post('/api/auth/guest')

// Dashboard
export const getDashboardStats = () => API.get('/api/dashboard/stats')

// Simulation
export const getSimulations     = ()     => API.get('/api/simulation')
export const startSimulationLegacy = (data) => API.post('/api/simulation/start-legacy', data)
export const stopSimulation     = (data) => API.post('/api/simulation/stop', data)
export const seedDemoSimulation = ()     => API.post('/api/simulation/seed-demo')

// Simulation Reports
export const saveSimulationReport = (data) => API.post('/api/simulation/report', data)
export const getMyReports         = ()     => API.get('/api/simulation/reports')
export const getReport            = (id)   => API.get(`/api/simulation/report/${id}`)

// Kill Chain
export const getKillChain = (simulationId) => API.get(`/api/killchain/${simulationId}`)

// Logs
export const getLogs = ()     => API.get('/api/logs')
export const addLog  = (data) => API.post('/api/logs/add', data)

// Scenarios & Simulation Engine
export const getScenario     = (mode, attack) => API.get(`/api/scenarios/${mode}/${attack}`)
export const startSimulation = (data)         => API.post('/api/simulation/start', data)
export const submitChoice    = (sessionId, optionId) => API.post(`/api/simulation/${sessionId}/choice`, { optionId })
export const completeSimulation = (sessionId) => API.post(`/api/simulation/${sessionId}/complete`)

export default API
