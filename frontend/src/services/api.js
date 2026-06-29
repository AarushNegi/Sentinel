import axios from 'axios'

const API = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5000'
})

// Attach JWT token to every request automatically
API.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Auth
export const registerUser = (data) => API.post('/auth/register', data)
export const loginUser    = (data) => API.post('/auth/login', data)
export const guestLogin   = ()     => API.post('/auth/guest')

// Dashboard
export const getDashboardStats = () => API.get('/dashboard/stats')

// Simulation
export const getSimulations   = ()     => API.get('/simulation')
export const startSimulation  = (data) => API.post('/simulation/start', data)
export const stopSimulation   = (data) => API.post('/simulation/stop', data)

// Logs
export const getLogs  = ()     => API.get('/logs')
export const addLog   = (data) => API.post('/logs/add', data)

export default API
