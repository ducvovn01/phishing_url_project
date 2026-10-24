import * as client from './client.js'
import * as mock from './mock.js'

const api = import.meta.env.VITE_USE_MOCK === 'true' ? mock : client

export const { analyseUrl, getHealth } = api
