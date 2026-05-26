import axios from 'axios';

const api = axios.create({ baseURL: '/api' });

export const runScan = (target) => api.post('/scan', { target });
