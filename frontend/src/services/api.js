import axios from 'axios';

const api = axios.create({ baseURL: '/api' });

export const runScan = (target, maxHunters = 8) =>
  api.post('/scan', { target, max_hunters });

export const getHealth = () => api.get('/health');

export const createScanSocket = () =>
  new WebSocket(`ws://${window.location.hostname}:8000/api/ws/scan`);