import { createApp } from './app.js';
import { loadSettings } from './settings.js';
const settings = loadSettings();
const { app, auth } = createApp(settings);
const server = app.listen(settings.authPort,settings.authHost, () => process.stdout.write('Monitor authorization service listening\n'));
for (const signal of ['SIGTERM','SIGINT'] as const) process.on(signal, () => { server.close(() => { void auth.close().then(() => process.exit(0)); }); });
