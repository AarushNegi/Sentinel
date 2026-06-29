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
export const getSimulations  = ()     => API.get('/api/simulation')
export const startSimulation = (data) => API.post('/api/simulation/start', data)
export const stopSimulation  = (data) => API.post('/api/simulation/stop', data)

// Logs
export const getLogs = ()     => API.get('/api/logs')
export const addLog  = (data) => API.post('/api/logs/add', data)

export default API